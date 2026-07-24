/*
 * Copyright (C) 2017 The Android Open Source Project
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "android.hardware.biometrics.fingerprint-service.rbs"

#include "FingerprintEngineRbs.h"
#include "Legacy2Aidl.h"

#include <android-base/logging.h>
#include <dlfcn.h>
#include <log/log.h>
#include <sys/stat.h>

#include <cstdio>
#include <cstring>
#include <format>

#define BIND_RBS_FUNCTIONS(name, member_name) \
    mRbsFlow->member_name = LoadFunction<RbsFlow::rbs_##name>(mHandle.get(), "rbs_" #name);
#define CHECK_RBS_FUNCTION(name) (mRbsFlow && mRbsFlow->name != nullptr)

#define LOAD_RBS_FUNCTIONS \
    BIND_RBS_FUNCTIONS(initialize, initialize) \
    BIND_RBS_FUNCTIONS(uninitialize, uninitialize) \
    BIND_RBS_FUNCTIONS(cancel, cancel) \
    BIND_RBS_FUNCTIONS(active_user_group, activeUserGroup) \
    BIND_RBS_FUNCTIONS(set_data_path, setDataPath) \
    BIND_RBS_FUNCTIONS(chk_secure_id, chkSecureId) \
    BIND_RBS_FUNCTIONS(pre_enroll, preEnroll) \
    BIND_RBS_FUNCTIONS(enroll, enroll) \
    BIND_RBS_FUNCTIONS(post_enroll, postEnroll) \
    BIND_RBS_FUNCTIONS(chk_auth_token, chkAuthToken) \
    BIND_RBS_FUNCTIONS(authenticator, authenticator) \
    BIND_RBS_FUNCTIONS(remove_fingerprint, removeFingerprint) \
    BIND_RBS_FUNCTIONS(get_fingerprint_ids, getFingerprintIds) \
    BIND_RBS_FUNCTIONS(get_authenticator_id, getAuthenticatorId) \
    BIND_RBS_FUNCTIONS(set_on_callback_proc, setOnCallbackProc) \
    BIND_RBS_FUNCTIONS(extra_api, extraApi) \
    BIND_RBS_FUNCTIONS(get_challenge, getChallenge) \
    BIND_RBS_FUNCTIONS(post_challenge, postChallenge) \
    BIND_RBS_FUNCTIONS(invalidate_auth_id, invalidateAuthId) \
    BIND_RBS_FUNCTIONS(set_app_type, setAppType) \
    BIND_RBS_FUNCTIONS(lockout_info_init, lockoutInfoInit) \
    BIND_RBS_FUNCTIONS(lockout_info_reset, lockoutInfoReset)

#define COMMAND_FINGER_UP	102
#define COMMAND_FINGER_DOWN	101

namespace {

constexpr uint64_t kEtsKeymasterCmdGetSecureKey = 0x200000205ull;

void* LoadRbsFlowLib() {
    auto handle = dlopen("libRbsFlow.so", RTLD_NOW);
    if (handle != nullptr) {
        ALOGD("Loaded: libRbsFlow.so");
    } else {
        ALOGE("Cannot load libRbsFlow.so (%s)", dlerror());
    }
    return handle;
}

template <typename Function>
Function LoadFunction(void* handle, const char* name) {
    void* fn = dlsym(handle, name);
    if (fn == nullptr) {
        ALOGE("LoadFunction -- failed to load function %s", name);
    }
    return reinterpret_cast<Function>(fn);
}

}  // anonymous namespace

namespace aidl::android::hardware::biometrics::fingerprint {

static FingerprintEngineRbs* sInstance = nullptr;

FingerprintEngineRbs::FingerprintEngineRbs(std::shared_ptr<FingerprintConfig> config)
    : FingerprintEngine(config),
      mHandle(LoadRbsFlowLib(),
              [](void* p) {
                  if (p != nullptr) {
                      if (dlclose(p) != 0) {
                          ALOGE("Failed to close RBS flow lib.");
                      }
                  }
              }),
      mCustomIniPath(nullptr),
      mRbsFlow(std::make_unique<RbsFlow>()) {
    sInstance = this;

    if (mHandle == nullptr) {
        ALOGE("Failed to load RBS fingerprint lib (%s)", dlerror());
        return;
    }

    LOAD_RBS_FUNCTIONS

    mCustomIniPath = LoadFunction<char*>(mHandle.get(), "g_custom_ini_path");

    uint8_t masterkey[0x100];
    if (getSecureKey(masterkey, sizeof(masterkey)) != 0) {
        ALOGE("Failed to fetch secure key for RBS sensor");
    } else if (!mRbsFlow || mRbsFlow->initialize == nullptr ||
               mRbsFlow->initialize(masterkey, sizeof(masterkey)) != 0) {
        ALOGE("Failed to initialize RBS sensor");
    }

    // Handle updated libRbsFlow.so (new APIs if present)
    if (mRbsFlow) {
        if (mRbsFlow->setAppType != nullptr) {
            mRbsFlow->setAppType(0);  // default app type for fingerprint HAL
        }
        if (mRbsFlow->lockoutInfoInit != nullptr) {
            mRbsFlow->lockoutInfoInit();
        }
    }
}

FingerprintEngineRbs::~FingerprintEngineRbs() {
    sInstance = nullptr;
    if (mRbsFlow) {
        if (mRbsFlow->uninitialize != nullptr) {
            mRbsFlow->uninitialize();
        }
        if (mRbsFlow->lockoutInfoReset != nullptr) {
            mRbsFlow->lockoutInfoReset();
        }
    }
}

void FingerprintEngineRbs::startSession(std::shared_ptr<ISessionCallback> cb, int userId) {
    mCb = std::move(cb);
    mUserId = userId;

    std::string path = std::format("/data/vendor_de/{}/fpdata/", userId);
    if (mCustomIniPath != nullptr) {
        mkdir(path.c_str(), 0700);
        snprintf(mCustomIniPath, path.size() + 1, "%s", path.c_str());
    }

    if (!mRbsFlow || mRbsFlow->setOnCallbackProc == nullptr ||
        mRbsFlow->setOnCallbackProc(reinterpret_cast<void*>(FingerprintEngineRbs::notify)) != 0) {
        ALOGE("Can't register fingerprint module callback");
        return;
    }

    if (CHECK_RBS_FUNCTION(activeUserGroup)) {
        mRbsFlow->activeUserGroup(userId, path.c_str());
    }
}

void FingerprintEngineRbs::endSession() {
    if (CHECK_RBS_FUNCTION(lockoutInfoReset)) {
        mRbsFlow->lockoutInfoReset();  // Best-effort cleanup on updated libs
    }
    mCb->onSessionClosed();
}

ndk::ScopedAStatus FingerprintEngineRbs::generateChallengeImpl() {
    uint64_t challenge = 0;
    if (CHECK_RBS_FUNCTION(getChallenge) && mRbsFlow->getChallenge(&challenge) == 0) {
        ALOGI("generateChallenge: %lu", challenge);
        mCb->onChallengeGenerated(challenge);
        return ndk::ScopedAStatus::ok();
    }
    return ndk::ScopedAStatus::fromServiceSpecificError(-EIO);
}

ndk::ScopedAStatus FingerprintEngineRbs::revokeChallengeImpl(int64_t /* challenge */) {
    uint64_t challenge = 0;
    if (CHECK_RBS_FUNCTION(postChallenge)) {
        mRbsFlow->postChallenge(&challenge);
    }
    mCb->onChallengeRevoked(challenge);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::enrollImpl(const HardwareAuthToken& hat) {
    hw_auth_token_t authToken;
    translate(hat, authToken);

    if (CHECK_RBS_FUNCTION(chkAuthToken)) {
        mRbsFlow->chkAuthToken(&authToken, sizeof(authToken));
    }

    if (!mRbsFlow || mRbsFlow->enroll == nullptr || mRbsFlow->enroll() != 0) {
        ALOGE("enroll failed");
        mCb->onError(Error::UNABLE_TO_PROCESS, 0);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::authenticateImpl(int64_t operationId) {
    checkSensorLockout();
    if (!mRbsFlow || mRbsFlow->authenticator == nullptr ||
        mRbsFlow->authenticator(mUserId, nullptr, 0, operationId) != 0) {
        ALOGE("authenticate failed");
        mCb->onError(Error::UNABLE_TO_PROCESS, 0);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::enumerateEnrollmentsImpl() {
    uint32_t fids[16];
    uint32_t numFids = 16;
    if (CHECK_RBS_FUNCTION(getFingerprintIds) &&
        mRbsFlow->getFingerprintIds(mUserId, fids, &numFids) == 0) {
        std::vector<int32_t> enrollments;
        for (uint32_t i = 0; i < numFids; ++i) {
            enrollments.push_back(fids[i]);
        }
        mCb->onEnrollmentsEnumerated(enrollments);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::removeEnrollmentsImpl(
        const std::vector<int32_t>& enrollmentIds) {
    if (mRbsFlow) {
        for (int32_t fid : enrollmentIds) {
            if (mRbsFlow->removeFingerprint != nullptr) {
                int error = mRbsFlow->removeFingerprint(mUserId, fid);
                if (error != 0) {
                    ALOGE("remove failed: %d", error);
                }
            }
        }
    }
    mCb->onEnrollmentsRemoved(enrollmentIds);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::getAuthenticatorIdImpl() {
    uint64_t authId = 0;
    if (CHECK_RBS_FUNCTION(getAuthenticatorId)) {
        mRbsFlow->getAuthenticatorId(&authId);
    }
    ALOGI("getAuthenticatorId: %lu", authId);
    mCb->onAuthenticatorIdRetrieved(authId);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::invalidateAuthenticatorIdImpl() {
    uint64_t authId = 0;
    if (CHECK_RBS_FUNCTION(invalidateAuthId)) {
        mRbsFlow->invalidateAuthId();
    } else if (CHECK_RBS_FUNCTION(getAuthenticatorId)) {
        mRbsFlow->getAuthenticatorId(&authId);
    }
    ALOGI("invalidateAuthenticatorId: %lu", authId);
    mCb->onAuthenticatorIdInvalidated(authId);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::onPointerDownImpl(int32_t /* pointerId */, int32_t x,
                                                           int32_t y, float minor, float major) {
    std::string sensorTypeProp = mConfig->get<std::string>("type");
    if (sensorTypeProp != "udfps" && sensorTypeProp != "udfps_optical") {
        return ndk::ScopedAStatus::ok();
    }
    if (CHECK_RBS_FUNCTION(extraApi)) {
        mRbsFlow->extraApi(COMMAND_FINGER_DOWN, 0, 0, 0, 0);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::onPointerUpImpl(int32_t /* pointerId */) {
    std::string sensorTypeProp = mConfig->get<std::string>("type");
    if (sensorTypeProp != "udfps" && sensorTypeProp != "udfps_optical") {
        return ndk::ScopedAStatus::ok();
    }
    if (CHECK_RBS_FUNCTION(extraApi)) {
        mRbsFlow->extraApi(COMMAND_FINGER_UP, 0, 0, 0, 0);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::cancelImpl() {
    if (CHECK_RBS_FUNCTION(cancel) && mRbsFlow->cancel() == 0) {
        mCb->onError(Error::CANCELED, 0);
        return ndk::ScopedAStatus::ok();
    }
    return ndk::ScopedAStatus::fromServiceSpecificError(-ECANCELED);
}

void FingerprintEngineRbs::notify(uint32_t eventId, uint32_t value1, uint32_t value2,
                                  void* /* buffer */, uint32_t /* buffer_size */) {
    if (sInstance == nullptr || sInstance->mCb == nullptr) {
        ALOGE("Can't dispatch notification: Engine context or Callback is missing");
        return;
    }

    switch (eventId) {
        case 1:  // Error
            sInstance->mCb->onError(static_cast<Error>(value1), value2);
            break;
        case 2:  // Acquired
            sInstance->mCb->onAcquired(static_cast<AcquiredInfo>(value1), value2);
            break;
        case 3:  // Enroll
            sInstance->mCb->onEnrollmentProgress(value1, value2);
            break;
        case 4:  // Authenticated
            if (value1 != 0) {
                sInstance->mCb->onAuthenticationSucceeded(value1, HardwareAuthToken{});
                sInstance->clearLockout(true);
            } else {
                sInstance->mCb->onAuthenticationFailed();
                sInstance->checkSensorLockout();
            }
            break;
        default:
            ALOGD("Unhandled vendor callback eventId: %u", eventId);
            break;
    }
}

int32_t FingerprintEngineRbs::getSecureKey(void* masterkey, uint32_t size) {
    struct QSEECom_handle { unsigned char* ion_sbuffer; };
    struct ets_masterkey_response {
        uint32_t rc;
        uint32_t pad;
        uint32_t size;
        uint32_t masterkey[256];
    };

    int rc = 0;
    int (*qsc_start_app)(QSEECom_handle**, const char*, uint32_t);
    int (*qsc_shutdown_app)(QSEECom_handle**);
    int (*ets_keymaster_send_cmd)(QSEECom_handle*, void*, uint32_t, void*, uint32_t*);
    QSEECom_handle* keymasterHandle = nullptr;
    uint64_t sendCmd = kEtsKeymasterCmdGetSecureKey;
    ets_masterkey_response rcvBuf;
    uint32_t rcvBufSize = sizeof(rcvBuf);

    void* teeClientHandle = dlopen("libets_teeclient_v3.so", RTLD_NOW);
    if (teeClientHandle == nullptr) {
        teeClientHandle = dlopen("libets_teeclient_v2.so", RTLD_NOW);
        if (teeClientHandle == nullptr) {
            ALOGE("Cannot load TEE client");
            return -1;
        }
    }

    qsc_start_app = LoadFunction<decltype(qsc_start_app)>(teeClientHandle, "qsc_start_app");
    qsc_shutdown_app = LoadFunction<decltype(qsc_shutdown_app)>(teeClientHandle, "qsc_shutdown_app");
    ets_keymaster_send_cmd = LoadFunction<decltype(ets_keymaster_send_cmd)>(
            teeClientHandle, "ets_keymaster_issue_send_modified_cmd_req");

    rc = qsc_start_app(&keymasterHandle, "keymaster64", 0x2400);
    if (rc != 0) {
        ALOGE("Cannot load keymaster application, error %d", rc);
        dlclose(teeClientHandle);
        return rc;
    }

    rc = ets_keymaster_send_cmd(keymasterHandle, &sendCmd, 8, &rcvBuf, &rcvBufSize);
    if (rc != 0) {
        ALOGE("Cannot send keymaster cmd, error %d", rc);
    } else if (rcvBuf.rc != 0) {
        ALOGE("Get master key failed, error %u", rcvBuf.rc);
        rc = rcvBuf.rc;
    } else if (size < rcvBuf.size) {
        ALOGE("Output buffer too short, expected size %u, got size %u", rcvBuf.size, size);
        rc = -ENOMEM;
    } else {
        memcpy(masterkey, rcvBuf.masterkey, size);
    }

    qsc_shutdown_app(&keymasterHandle);
    dlclose(teeClientHandle);

    return rc;
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
