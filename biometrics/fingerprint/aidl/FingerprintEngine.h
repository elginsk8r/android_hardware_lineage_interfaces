/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android/log.h>
#include <hardware/hardware.h>
#include <log/log.h>
#include <future>

#include "FingerprintConfig.h"
#include "LockoutTracker.h"

using ::aidl::android::hardware::keymaster::HardwareAuthToken;

namespace aidl::android::hardware::biometrics::fingerprint {

class FingerprintEngine {
  public:
    FingerprintEngine(std::shared_ptr<FingerprintConfig> config);
    virtual ~FingerprintEngine();

    virtual void startSession(std::shared_ptr<ISessionCallback> cb, int userId);
    virtual void endSession();
    virtual ndk::ScopedAStatus generateChallengeImpl();
    virtual ndk::ScopedAStatus revokeChallengeImpl(int64_t challenge);
    virtual ndk::ScopedAStatus enrollImpl(const HardwareAuthToken& hat);
    virtual ndk::ScopedAStatus authenticateImpl(int64_t operationId);
    virtual ndk::ScopedAStatus detectInteractionImpl();
    virtual ndk::ScopedAStatus enumerateEnrollmentsImpl();
    virtual ndk::ScopedAStatus removeEnrollmentsImpl(const std::vector<int32_t>& enrollmentIds);
    virtual ndk::ScopedAStatus getAuthenticatorIdImpl();
    virtual ndk::ScopedAStatus invalidateAuthenticatorIdImpl();
    virtual ndk::ScopedAStatus onPointerDownImpl(int32_t pointerId, int32_t x,
                                                 int32_t y, float minor, float major);
    virtual ndk::ScopedAStatus onPointerUpImpl(int32_t pointerId);
    virtual ndk::ScopedAStatus cancelImpl();
    virtual ndk::ScopedAStatus resetLockoutImpl(const HardwareAuthToken& hat);

  protected:
    std::shared_ptr<FingerprintConfig> mConfig;

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
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
