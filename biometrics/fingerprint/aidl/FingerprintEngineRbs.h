/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android-base/macros.h>
#include <hardware/hw_auth_token.h>

#include <functional>
#include <memory>

#include "FingerprintEngine.h"

using ::aidl::android::hardware::keymaster::HardwareAuthToken;

namespace aidl::android::hardware::biometrics::fingerprint {

// Function table for libRbsFlow.so. Signatures verified against the library's
// exports; rbs_get_challenge / rbs_post_challenge do NOT exist in the library
// (the challenge is generated and tracked by the engine).
struct RbsFlow {
    typedef int32_t (*rbs_initialize)(void*, uint32_t);
    typedef int32_t (*rbs_uninitialize)(void);
    typedef int32_t (*rbs_cancel)(void);
    typedef int32_t (*rbs_active_user_group)(uint32_t, const char*);
    // (type, path, length); stock passes type 1 before fetching the master key
    typedef int32_t (*rbs_set_data_path)(uint32_t, const char*, uint32_t);
    // (gid, secureId): secureId is a full 64-bit value (hw_auth_token_t::user_id)
    typedef int32_t (*rbs_chk_secure_id)(uint32_t, uint64_t);
    // (gid, fid): checks the chosen finger ID is free; 0x0b == no space
    typedef int32_t (*rbs_pre_enroll)(uint32_t, uint32_t);
    typedef int32_t (*rbs_enroll)(void);
    typedef int32_t (*rbs_post_enroll)(void);
    typedef int32_t (*rbs_chk_auth_token)(const hw_auth_token_t*, uint32_t);
    // (gid, fid list or null, count <= 5, operationId)
    typedef int32_t (*rbs_authenticator)(uint32_t, void*, uint32_t, uint64_t);
    // (gid, fid); fid == 0 removes all
    typedef int32_t (*rbs_remove_fingerprint)(uint32_t, uint32_t);
    // (gid, out ids, in/out count); count must be <= 5
    typedef int32_t (*rbs_get_fingerprint_ids)(uint32_t, uint32_t*, uint32_t*);
    typedef int32_t (*rbs_get_authenticator_id)(uint64_t*);
    typedef int32_t (*rbs_set_on_callback_proc)(void*);
    typedef int32_t (*rbs_extra_api)(uint32_t, uint32_t*, uint32_t, uint32_t*, uint32_t*);
    typedef int32_t (*rbs_invalidate_auth_id)(void);
    typedef int32_t (*rbs_set_app_type)(uint32_t);
    typedef int32_t (*rbs_lockout_info_init)(void);
    typedef int32_t (*rbs_lockout_info_reset)(void);

    rbs_initialize initialize = nullptr;
    rbs_uninitialize uninitialize = nullptr;
    rbs_cancel cancel = nullptr;
    rbs_active_user_group activeUserGroup = nullptr;
    rbs_set_data_path setDataPath = nullptr;
    rbs_chk_secure_id chkSecureId = nullptr;
    rbs_pre_enroll preEnroll = nullptr;
    rbs_enroll enroll = nullptr;
    rbs_post_enroll postEnroll = nullptr;
    rbs_chk_auth_token chkAuthToken = nullptr;
    rbs_authenticator authenticator = nullptr;
    rbs_remove_fingerprint removeFingerprint = nullptr;
    rbs_get_fingerprint_ids getFingerprintIds = nullptr;
    rbs_get_authenticator_id getAuthenticatorId = nullptr;
    rbs_set_on_callback_proc setOnCallbackProc = nullptr;
    rbs_extra_api extraApi = nullptr;
    rbs_invalidate_auth_id invalidateAuthId = nullptr;
    rbs_set_app_type setAppType = nullptr;
    rbs_lockout_info_init lockoutInfoInit = nullptr;
    rbs_lockout_info_reset lockoutInfoReset = nullptr;
};

class FingerprintEngineRbs : public FingerprintEngine {
  public:
    explicit FingerprintEngineRbs(std::shared_ptr<FingerprintConfig> config);
    ~FingerprintEngineRbs() override;

    void startSession(std::shared_ptr<ISessionCallback> cb, int userId) override;
    void endSession() override;
    ndk::ScopedAStatus generateChallengeImpl() override;
    ndk::ScopedAStatus revokeChallengeImpl(int64_t challenge) override;
    ndk::ScopedAStatus enrollImpl(const HardwareAuthToken& hat) override;
    ndk::ScopedAStatus authenticateImpl(int64_t operationId) override;
    ndk::ScopedAStatus enumerateEnrollmentsImpl() override;
    ndk::ScopedAStatus removeEnrollmentsImpl(const std::vector<int32_t>& enrollmentIds) override;
    ndk::ScopedAStatus getAuthenticatorIdImpl() override;
    ndk::ScopedAStatus invalidateAuthenticatorIdImpl() override;
    ndk::ScopedAStatus onPointerDownImpl(int32_t pointerId, int32_t x, int32_t y, float minor,
                                         float major) override;
    ndk::ScopedAStatus onPointerUpImpl(int32_t pointerId) override;
    ndk::ScopedAStatus cancelImpl() override;
    ndk::ScopedAStatus resetLockoutImpl(const HardwareAuthToken& hat) override;

  private:
    // size: in = buffer size, out = key size returned by the TA
    static int32_t getSecureKey(void* masterkey, uint32_t* size);
    static void notify(uint32_t eventId, uint32_t value1, uint32_t value2, void* buffer,
                       uint32_t buffer_size);

    void setIniPath(int userId);
    void sendTouchEvent(uint32_t* in, uint32_t size);
    void onAcquired(AcquiredInfo info, int32_t vendorCode);

    std::unique_ptr<void, std::function<void(void*)>> mHandle;
    char* mCustomIniPath = nullptr;
    std::unique_ptr<RbsFlow> mRbsFlow;

    // Challenge is engine-scoped (not session-scoped) so it survives session recreation.
    uint64_t mChallenge = 0;
    bool mInitialized = false;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
