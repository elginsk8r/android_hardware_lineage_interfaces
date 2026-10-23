/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/android/hardware/biometrics/fingerprint/IFingerprint.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android/binder_auto_utils.h>
#include <android/log.h>
#include <log/log.h>

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>

#include "FingerprintEngine.h"

namespace aidl::android::hardware::biometrics::fingerprint {

/**
 * Engine that sits in front of a stock AIDL fingerprint HAL (registered as ".../wrapper") and
 * forwards every call to it, adding UdfpsHandler hooks around the points where the panel
 * (HBM / FOD illumination) has to be driven.
 */
class FingerprintEngineAidl : public FingerprintEngine,
                              public std::enable_shared_from_this<FingerprintEngineAidl> {
  public:
    explicit FingerprintEngineAidl(std::shared_ptr<FingerprintConfig> config);
    ~FingerprintEngineAidl() override;

    static std::shared_ptr<FingerprintEngine> create(std::shared_ptr<FingerprintConfig> config);

    void startSession(std::shared_ptr<ISessionCallback> cb, int userId) override;
    void endSession() override;
    ndk::ScopedAStatus generateChallengeImpl() override;
    ndk::ScopedAStatus revokeChallengeImpl(int64_t challenge) override;
    ndk::ScopedAStatus enrollImpl(const HardwareAuthToken& hat) override;
    ndk::ScopedAStatus authenticateImpl(int64_t operationId) override;
    ndk::ScopedAStatus detectInteractionImpl() override;
    ndk::ScopedAStatus enumerateEnrollmentsImpl() override;
    ndk::ScopedAStatus removeEnrollmentsImpl(const std::vector<int32_t>& enrollmentIds) override;
    ndk::ScopedAStatus getAuthenticatorIdImpl() override;
    ndk::ScopedAStatus invalidateAuthenticatorIdImpl() override;
    ndk::ScopedAStatus onPointerDownImpl(int32_t pointerId, int32_t x, int32_t y, float minor,
                                         float major) override;
    ndk::ScopedAStatus onPointerUpImpl(int32_t pointerId) override;
    ndk::ScopedAStatus cancelImpl() override;
    // Lockout is owned by the stock HAL, don't use the engine's LockoutTracker.
    ndk::ScopedAStatus resetLockoutImpl(const HardwareAuthToken& hat) override;

    ndk::ScopedAStatus onUiReadyImpl() override;
    ndk::ScopedAStatus enrollWithContextImpl(const HardwareAuthToken& hat,
                                             const common::OperationContext& context) override;
    ndk::ScopedAStatus authenticateWithContextImpl(
            int64_t operationId, const common::OperationContext& context) override;
    ndk::ScopedAStatus detectInteractionWithContextImpl(
            const common::OperationContext& context) override;
    ndk::ScopedAStatus onPointerDownWithContextImpl(const PointerContext& context) override;
    ndk::ScopedAStatus onPointerUpWithContextImpl(const PointerContext& context) override;
    ndk::ScopedAStatus onPointerCancelWithContextImpl(const PointerContext& context) override;
    ndk::ScopedAStatus onContextChangedImpl(const common::OperationContext& context) override;
    ndk::ScopedAStatus setIgnoreDisplayTouchesImpl(bool shouldIgnore) override;

  private:
    class SessionCallbackAidl;

    using CancellationSignal = common::ICancellationSignal;
    static constexpr std::chrono::milliseconds kPointerUpTimeout{200};

    std::shared_ptr<ISession> getServiceSession();
    void setCancellationSignal(std::shared_ptr<CancellationSignal> signal);
    void armPointerTimeout(std::function<void(FingerprintEngineAidl&)> release);
    void markPointerReleased();

    template <typename F>
    ndk::ScopedAStatus wrapSessionCall(F&& f) {
        auto session = getServiceSession();
        if (!session) {
            ALOGE("No stock fingerprint session");
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
        }
        return f(*session);
    }

    // Operations returning an ICancellationSignal (enroll/authenticate/detectInteraction).
    template <typename F>
    ndk::ScopedAStatus wrapSessionCallCancelable(F&& f) {
        std::shared_ptr<CancellationSignal> signal;
        auto ret = wrapSessionCall([&](ISession& s) { return f(s, &signal); });
        setCancellationSignal(ret.isOk() ? std::move(signal) : nullptr);
        return ret;
    }

    std::shared_ptr<IFingerprint> mService;
    ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
    int32_t mSensorId = 0;

    std::mutex mMutex;
    std::shared_ptr<ISession> mServiceSession;
    std::shared_ptr<CancellationSignal> mCancellationSignal;
    uint64_t mPointerSeq = 0;
    bool mPointerActive = false;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
