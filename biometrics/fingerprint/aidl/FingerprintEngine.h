/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/android/hardware/biometrics/common/ICancellationSignal.h>
#include <aidl/android/hardware/biometrics/common/OperationContext.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <aidl/android/hardware/biometrics/fingerprint/PointerContext.h>
#include <android/log.h>
#include <hardware/hardware.h>
#include <log/log.h>
#include <future>

#include "FingerprintConfig.h"
#include "LockoutTracker.h"
#include "UdfpsHandler.h"

using ::aidl::android::hardware::keymaster::HardwareAuthToken;

namespace aidl::android::hardware::biometrics::fingerprint {

class FingerprintEngine {
  public:
    FingerprintEngine(std::shared_ptr<FingerprintConfig> config);
    virtual ~FingerprintEngine();

    static std::shared_ptr<FingerprintEngine> create(std::shared_ptr<FingerprintConfig> config);

    virtual void startSession(std::shared_ptr<ISessionCallback> cb, int userId);
    virtual void endSession();
    virtual ndk::ScopedAStatus generateChallengeImpl() { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus revokeChallengeImpl(int64_t challenge) { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus enrollImpl(const HardwareAuthToken& hat) { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus authenticateImpl(int64_t operationId) { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus detectInteractionImpl();
    virtual ndk::ScopedAStatus enumerateEnrollmentsImpl() { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus removeEnrollmentsImpl(const std::vector<int32_t>& enrollmentIds) { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus getAuthenticatorIdImpl() { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus invalidateAuthenticatorIdImpl() { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus onPointerDownImpl(int32_t pointerId, int32_t x,
                                                 int32_t y, float minor, float major) { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus onPointerUpImpl(int32_t pointerId) { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus cancelImpl() { return ndk::ScopedAStatus::ok(); };

    // Context-aware / newer ISession entry points. The defaults fall back to the legacy
    // behaviour, so existing engines (hardware, hidl, ...) are unaffected. Engines that talk to
    // an AIDL HAL (e.g. the wrapper) override these to forward the context untouched.
    virtual ndk::ScopedAStatus onUiReadyImpl() { return ndk::ScopedAStatus::ok(); };
    virtual ndk::ScopedAStatus enrollWithContextImpl(const HardwareAuthToken& hat,
                                                     const common::OperationContext& /*context*/) {
        return enrollImpl(hat);
    };
    virtual ndk::ScopedAStatus authenticateWithContextImpl(
            int64_t operationId, const common::OperationContext& /*context*/) {
        return authenticateImpl(operationId);
    };
    virtual ndk::ScopedAStatus detectInteractionWithContextImpl(
            const common::OperationContext& /*context*/) {
        return detectInteractionImpl();
    };
    virtual ndk::ScopedAStatus onPointerDownWithContextImpl(const PointerContext& context) {
        return onPointerDownImpl(context.pointerId, context.x, context.y, context.minor,
                                 context.major);
    };
    virtual ndk::ScopedAStatus onPointerUpWithContextImpl(const PointerContext& context) {
        return onPointerUpImpl(context.pointerId);
    };
    virtual ndk::ScopedAStatus onPointerCancelWithContextImpl(const PointerContext& /*context*/) {
        return ndk::ScopedAStatus::ok();
    };
    virtual ndk::ScopedAStatus onContextChangedImpl(const common::OperationContext& /*context*/) {
        return ndk::ScopedAStatus::ok();
    };
    virtual ndk::ScopedAStatus setIgnoreDisplayTouchesImpl(bool /*shouldIgnore*/) {
        return ndk::ScopedAStatus::ok();
    };
    virtual ndk::ScopedAStatus resetLockoutImpl(const HardwareAuthToken& hat);

  protected:
    std::shared_ptr<FingerprintConfig> mConfig;
    UdfpsHandler* mUdfpsHandler = nullptr;

    int32_t mUserId;
    std::shared_ptr<ISessionCallback> mCb;
    LockoutTracker mLockoutTracker;

    bool checkSensorLockout();
    void clearLockout(bool clearAttemptCounter);

  private:
    void startLockoutTimer(int64_t timeout);
    void lockoutTimerExpired();

    // lockout timer
    bool mIsLockoutTimerStarted = false;
    bool mIsLockoutTimerAborted = false;

    UdfpsHandlerFactory* mUdfpsHandlerFactory = nullptr;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
