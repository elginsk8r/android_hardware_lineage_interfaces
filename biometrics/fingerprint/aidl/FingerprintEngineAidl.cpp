/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "FingerprintEngineAidl.h"

#include <aidl/android/hardware/biometrics/fingerprint/BnSessionCallback.h>
#include <android/binder_manager.h>

#include <cstdlib>
#include <thread>

namespace aidl::android::hardware::biometrics::fingerprint {

/*
 * Receives callbacks from the wrapped HAL. Each session gets its own instance bound to the
 * framework callback of that session, so late callbacks (e.g. onSessionClosed) from an old
 * session can never leak into a newer one.
 */
class FingerprintEngineAidl::SessionCallbackAidl : public BnSessionCallback {
  public:
    SessionCallbackAidl(std::weak_ptr<FingerprintEngineAidl> engine,
                  std::shared_ptr<ISessionCallback> cb)
        : mEngine(std::move(engine)), mCb(std::move(cb)) {}

    ndk::ScopedAStatus onChallengeGenerated(int64_t challenge) override {
        return mCb->onChallengeGenerated(challenge);
    }
    ndk::ScopedAStatus onChallengeRevoked(int64_t challenge) override {
        return mCb->onChallengeRevoked(challenge);
    }
    ndk::ScopedAStatus onAcquired(AcquiredInfo info, int32_t vendorCode) override {
        withHandler([&](UdfpsHandler& h) { h.onAcquired(static_cast<int32_t>(info), vendorCode); });
        return mCb->onAcquired(info, vendorCode);
    }
    ndk::ScopedAStatus onError(Error error, int32_t vendorCode) override {
        withHandler([](UdfpsHandler& h) { h.cancel(); });
        return mCb->onError(error, vendorCode);
    }
    ndk::ScopedAStatus onEnrollmentProgress(int32_t enrollmentId, int32_t remaining) override {
        return mCb->onEnrollmentProgress(enrollmentId, remaining);
    }
    ndk::ScopedAStatus onAuthenticationSucceeded(int32_t enrollmentId,
                                                 const HardwareAuthToken& hat) override {
        withHandler([](UdfpsHandler& h) { h.onAuthenticationSucceeded(); });
        return mCb->onAuthenticationSucceeded(enrollmentId, hat);
    }
    ndk::ScopedAStatus onAuthenticationFailed() override {
        withHandler([](UdfpsHandler& h) { h.onAuthenticationFailed(); });
        return mCb->onAuthenticationFailed();
    }
    ndk::ScopedAStatus onLockoutTimed(int64_t durationMillis) override {
        withHandler([](UdfpsHandler& h) { h.cancel(); });
        return mCb->onLockoutTimed(durationMillis);
    }
    ndk::ScopedAStatus onLockoutPermanent() override {
        withHandler([](UdfpsHandler& h) { h.cancel(); });
        return mCb->onLockoutPermanent();
    }
    ndk::ScopedAStatus onLockoutCleared() override { return mCb->onLockoutCleared(); }
    ndk::ScopedAStatus onInteractionDetected() override { return mCb->onInteractionDetected(); }
    ndk::ScopedAStatus onEnrollmentsEnumerated(const std::vector<int32_t>& ids) override {
        return mCb->onEnrollmentsEnumerated(ids);
    }
    ndk::ScopedAStatus onEnrollmentsRemoved(const std::vector<int32_t>& ids) override {
        return mCb->onEnrollmentsRemoved(ids);
    }
    ndk::ScopedAStatus onAuthenticatorIdRetrieved(int64_t authenticatorId) override {
        return mCb->onAuthenticatorIdRetrieved(authenticatorId);
    }
    ndk::ScopedAStatus onAuthenticatorIdInvalidated(int64_t newAuthenticatorId) override {
        return mCb->onAuthenticatorIdInvalidated(newAuthenticatorId);
    }
    ndk::ScopedAStatus onSessionClosed() override {
        withHandler([](UdfpsHandler& h) { h.cancel(); });
        return mCb->onSessionClosed();
    }

  private:
    template <typename F>
    void withHandler(F&& f) {
        if (auto engine = mEngine.lock(); engine && engine->mUdfpsHandler) {
            f(*engine->mUdfpsHandler);
        }
    }

    std::weak_ptr<FingerprintEngineAidl> mEngine;
    std::shared_ptr<ISessionCallback> mCb;
};

FingerprintEngineAidl::FingerprintEngineAidl(std::shared_ptr<FingerprintConfig> config)
    : FingerprintEngine(config) {
    // The HAL is patched to register as "wrapper" instead of "default".
    const std::string instance = std::string(IFingerprint::descriptor) + "/wrapper";
    mService = IFingerprint::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(instance.c_str())));
    if (mService == nullptr) {
        ALOGE("Failed to get fingerprint HAL %s", instance.c_str());
        return;
    }

    // Exit when the HAL dies so init restarts us against the new instance.
    mDeathRecipient = ndk::ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient_new([](void*) {
        ALOGE("Fingerprint HAL died, exiting");
        exit(EXIT_FAILURE);
    }));
    binder_status_t status =
            AIBinder_linkToDeath(mService->asBinder().get(), mDeathRecipient.get(), nullptr);
    if (status != STATUS_OK) {
        ALOGE("Failed to link to HAL death: %d", status);
    }

    // createSession() needs the sensor id, which may differ from the configured one.
    std::vector<SensorProps> props;
    if (mService->getSensorProps(&props).isOk() && !props.empty()) {
        mSensorId = props[0].commonProps.sensorId;
    } else {
        mSensorId = mConfig->get<std::int32_t>("sensor_id");
        ALOGW("Couldn't query sensor props, using configured sensor id %d", mSensorId);
    }

    if (mUdfpsHandler) {
        mUdfpsHandler->init(nullptr);
    }
}

FingerprintEngineAidl::~FingerprintEngineAidl() {
    if (mService != nullptr && mDeathRecipient.get() != nullptr) {
        AIBinder_unlinkToDeath(mService->asBinder().get(), mDeathRecipient.get(), nullptr);
    }
}

std::shared_ptr<FingerprintEngine> FingerprintEngineAidl::create(
        std::shared_ptr<FingerprintConfig> config) {
    auto engine = std::make_shared<FingerprintEngineAidl>(std::move(config));
    if (engine->mService == nullptr) {
        ALOGE("Failed to set up fingerprint aidl engine");
        return nullptr;
    }
    return engine;
}

std::shared_ptr<ISession> FingerprintEngineAidl::getServiceSession() {
    std::lock_guard<std::mutex> lock(mMutex);
    return mServiceSession;
}

void FingerprintEngineAidl::setCancellationSignal(std::shared_ptr<CancellationSignal> signal) {
    std::lock_guard<std::mutex> lock(mMutex);
    mCancellationSignal = std::move(signal);
}

void FingerprintEngineAidl::markPointerReleased() {
    std::lock_guard<std::mutex> lock(mMutex);
    mPointerActive = false;
    ++mPointerSeq;
}

// The HAL only needs the panel lit for a short capture window, so release the pointer
// ourselves if the framework hasn't done it by then. The timer is dropped if a real
// onPointerUp / cancel / session end arrives first, and never outlives the engine.
void FingerprintEngineAidl::armPointerTimeout(
        std::function<void(FingerprintEngineAidl&)> release) {
    uint64_t seq;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        seq = ++mPointerSeq;
        mPointerActive = true;
    }

    std::weak_ptr<FingerprintEngineAidl> weak = weak_from_this();
    std::thread([weak, seq, release = std::move(release)]() {
        std::this_thread::sleep_for(kPointerUpTimeout);
        auto self = weak.lock();
        if (!self) return;
        {
            std::lock_guard<std::mutex> lock(self->mMutex);
            if (!self->mPointerActive || self->mPointerSeq != seq) return;
        }
        release(*self);
    }).detach();
}

void FingerprintEngineAidl::startSession(std::shared_ptr<ISessionCallback> cb, int userId) {
    mCb = cb;
    mUserId = userId;

    auto callback = ndk::SharedRefBase::make<SessionCallbackAidl>(weak_from_this(), std::move(cb));

    std::shared_ptr<ISession> session;
    auto ret = mService->createSession(mSensorId, userId, callback, &session);
    if (!ret.isOk() || session == nullptr) {
        ALOGE("Failed to create stock fingerprint session: %s", ret.getDescription().c_str());
        return;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    mServiceSession = std::move(session);
    mCancellationSignal.reset();
}

void FingerprintEngineAidl::endSession() {
    if (mUdfpsHandler) {
        mUdfpsHandler->cancel();
    }

    std::shared_ptr<ISession> session;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        session = std::move(mServiceSession);
        mCancellationSignal.reset();
        mPointerActive = false;
        ++mPointerSeq;
    }

    // The HAL reports onSessionClosed() through SessionCallbackAidl. Only report it ourselves
    // if there was no session, or it couldn't be closed.
    if (session == nullptr) {
        mCb->onSessionClosed();
        return;
    }
    auto ret = session->close();
    if (!ret.isOk()) {
        ALOGE("Failed to close fingerprint session: %s", ret.getDescription().c_str());
        mCb->onSessionClosed();
    }
}

ndk::ScopedAStatus FingerprintEngineAidl::generateChallengeImpl() {
    return wrapSessionCall([](ISession& s) { return s.generateChallenge(); });
}

ndk::ScopedAStatus FingerprintEngineAidl::revokeChallengeImpl(int64_t challenge) {
    return wrapSessionCall([&](ISession& s) { return s.revokeChallenge(challenge); });
}

ndk::ScopedAStatus FingerprintEngineAidl::enrollImpl(const HardwareAuthToken& hat) {
    return wrapSessionCallCancelable([&](ISession& s, std::shared_ptr<CancellationSignal>* out) {
        return s.enroll(hat, out);
    });
}

ndk::ScopedAStatus FingerprintEngineAidl::authenticateImpl(int64_t operationId) {
    return wrapSessionCallCancelable([&](ISession& s, std::shared_ptr<CancellationSignal>* out) {
        return s.authenticate(operationId, out);
    });
}

ndk::ScopedAStatus FingerprintEngineAidl::detectInteractionImpl() {
    return wrapSessionCallCancelable([&](ISession& s, std::shared_ptr<CancellationSignal>* out) {
        return s.detectInteraction(out);
    });
}

ndk::ScopedAStatus FingerprintEngineAidl::enumerateEnrollmentsImpl() {
    return wrapSessionCall([](ISession& s) { return s.enumerateEnrollments(); });
}

ndk::ScopedAStatus FingerprintEngineAidl::removeEnrollmentsImpl(
        const std::vector<int32_t>& enrollmentIds) {
    return wrapSessionCall([&](ISession& s) { return s.removeEnrollments(enrollmentIds); });
}

ndk::ScopedAStatus FingerprintEngineAidl::getAuthenticatorIdImpl() {
    return wrapSessionCall([](ISession& s) { return s.getAuthenticatorId(); });
}

ndk::ScopedAStatus FingerprintEngineAidl::invalidateAuthenticatorIdImpl() {
    return wrapSessionCall([](ISession& s) { return s.invalidateAuthenticatorId(); });
}

ndk::ScopedAStatus FingerprintEngineAidl::resetLockoutImpl(const HardwareAuthToken& hat) {
    return wrapSessionCall([&](ISession& s) { return s.resetLockout(hat); });
}

ndk::ScopedAStatus FingerprintEngineAidl::onPointerDownImpl(int32_t pointerId, int32_t x,
                                                               int32_t y, float minor,
                                                               float major) {
    // Illumination must be up before the stock HAL starts capturing.
    if (mUdfpsHandler) {
        mUdfpsHandler->onFingerDown(x, y, minor, major);
    }
    auto ret = wrapSessionCall(
            [&](ISession& s) { return s.onPointerDown(pointerId, x, y, minor, major); });
    armPointerTimeout([pointerId](FingerprintEngineAidl& e) { e.onPointerUpImpl(pointerId); });
    return ret;
}

ndk::ScopedAStatus FingerprintEngineAidl::onPointerUpImpl(int32_t pointerId) {
    markPointerReleased();
    auto ret = wrapSessionCall([&](ISession& s) { return s.onPointerUp(pointerId); });
    if (mUdfpsHandler) {
        mUdfpsHandler->onFingerUp();
    }
    return ret;
}

ndk::ScopedAStatus FingerprintEngineAidl::onPointerDownWithContextImpl(
        const PointerContext& context) {
    if (mUdfpsHandler) {
        mUdfpsHandler->onFingerDown(context.x, context.y, context.minor, context.major);
    }
    auto ret = wrapSessionCall([&](ISession& s) { return s.onPointerDownWithContext(context); });
    armPointerTimeout(
            [context](FingerprintEngineAidl& e) { e.onPointerUpWithContextImpl(context); });
    return ret;
}

ndk::ScopedAStatus FingerprintEngineAidl::onPointerUpWithContextImpl(
        const PointerContext& context) {
    markPointerReleased();
    auto ret = wrapSessionCall([&](ISession& s) { return s.onPointerUpWithContext(context); });
    if (mUdfpsHandler) {
        mUdfpsHandler->onFingerUp();
    }
    return ret;
}

ndk::ScopedAStatus FingerprintEngineAidl::onPointerCancelWithContextImpl(
        const PointerContext& context) {
    markPointerReleased();
    auto ret = wrapSessionCall([&](ISession& s) { return s.onPointerCancelWithContext(context); });
    if (mUdfpsHandler) {
        mUdfpsHandler->cancel();
    }
    return ret;
}

ndk::ScopedAStatus FingerprintEngineAidl::onUiReadyImpl() {
    return wrapSessionCall([](ISession& s) { return s.onUiReady(); });
}

ndk::ScopedAStatus FingerprintEngineAidl::enrollWithContextImpl(
        const HardwareAuthToken& hat, const common::OperationContext& context) {
    return wrapSessionCallCancelable([&](ISession& s, std::shared_ptr<CancellationSignal>* out) {
        return s.enrollWithContext(hat, context, out);
    });
}

ndk::ScopedAStatus FingerprintEngineAidl::authenticateWithContextImpl(
        int64_t operationId, const common::OperationContext& context) {
    return wrapSessionCallCancelable([&](ISession& s, std::shared_ptr<CancellationSignal>* out) {
        return s.authenticateWithContext(operationId, context, out);
    });
}

ndk::ScopedAStatus FingerprintEngineAidl::detectInteractionWithContextImpl(
        const common::OperationContext& context) {
    return wrapSessionCallCancelable([&](ISession& s, std::shared_ptr<CancellationSignal>* out) {
        return s.detectInteractionWithContext(context, out);
    });
}

ndk::ScopedAStatus FingerprintEngineAidl::onContextChangedImpl(
        const common::OperationContext& context) {
    return wrapSessionCall([&](ISession& s) { return s.onContextChanged(context); });
}

ndk::ScopedAStatus FingerprintEngineAidl::setIgnoreDisplayTouchesImpl(bool shouldIgnore) {
    return wrapSessionCall([&](ISession& s) { return s.setIgnoreDisplayTouches(shouldIgnore); });
}

ndk::ScopedAStatus FingerprintEngineAidl::cancelImpl() {
    if (mUdfpsHandler) {
        mUdfpsHandler->cancel();
    }

    std::shared_ptr<CancellationSignal> signal;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        signal = std::move(mCancellationSignal);
    }
    // The stock HAL reports the cancellation itself through onError(CANCELED).
    return signal ? signal->cancel() : ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
