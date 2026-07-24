/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "android.hardware.biometrics.fingerprint-service.rbs"

#include "FingerprintEngineRbs.h"
#include "Legacy2Aidl.h"

#include <android-base/logging.h>
#include <dlfcn.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <cstdio>
#include <cstring>
#include <format>

#define BIND_RBS_FUNCTIONS(name, member_name) \
    mRbsFlow->member_name = LoadFunction<RbsFlow::rbs_##name>(mHandle.get(), "rbs_" #name);
#define CHECK_RBS_FUNCTION(name) (mRbsFlow && mRbsFlow->name != nullptr)
// For use from static contexts (e.g. notify) where there is no `this`.
#define CHECK_RBS_FUNCTION_ON(inst, name) ((inst)->mRbsFlow && (inst)->mRbsFlow->name != nullptr)

// rbs_get_challenge / rbs_post_challenge absent: libRbsFlow.so does not export them.
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
    BIND_RBS_FUNCTIONS(invalidate_auth_id, invalidateAuthId) \
    BIND_RBS_FUNCTIONS(set_app_type, setAppType) \
    BIND_RBS_FUNCTIONS(lockout_info_init, lockoutInfoInit) \
    BIND_RBS_FUNCTIONS(lockout_info_reset, lockoutInfoReset)

namespace {

constexpr uint64_t kEtsKeymasterCmdGetSecureKey = 0x200000205ull;

// rbs_get_fingerprint_ids / rbs_authenticator reject counts above this.
constexpr uint32_t kMaxFingerprints = 5;
// sizeof(g_custom_ini_path) in libRbsFlow.so.
constexpr size_t kIniPathSize = 4096;

// Return codes from libRbsFlow.so.
constexpr int32_t kRbsHwUnavailable = 4;        // rbs_enroll
constexpr int32_t kRbsNoSpace = 0x0b;           // rbs_pre_enroll
constexpr int32_t kRbsSecureIdMismatch = 0x21;  // rbs_chk_secure_id
constexpr int32_t kRbsAuthTokenInvalid = 0x22;  // rbs_chk_auth_token

// rbs_extra_api touch command; payload[0] selects finger down/up (from stock HAL).
constexpr uint32_t kExtraCmdTouch = 7;
constexpr uint32_t kTouchFingerDown = 101;
constexpr uint32_t kTouchFingerUp = 102;
constexpr uint32_t kExtraOutSize = 32;

// Event IDs from rbs_set_on_callback_proc (mapped from stock event handler).
constexpr uint32_t kEvtEnrollFailA = 0x3e9;
constexpr uint32_t kEvtEnrollLegacyOk = 0x3ea;  // percentage; lib re-emits as 0x40d
constexpr uint32_t kEvtEnrollFailB = 0x3eb;
constexpr uint32_t kEvtTooSlowA = 0x3ec;
constexpr uint32_t kEvtTooSlowB = 0x3ed;
constexpr uint32_t kEvtImmobileA = 0x3ee;
constexpr uint32_t kEvtImmobileB = 0x3ef;
constexpr uint32_t kEvtVendor1000 = 0x3f0;
constexpr uint32_t kEvtAuthSuccess = 0x3f2;  // v1=gid, v2=fid, buffer=hw_auth_token_t
constexpr uint32_t kEvtAuthFailA = 0x3f3;
constexpr uint32_t kEvtInsufficient = 0x3f5;
constexpr uint32_t kEvtPartialA = 0x3f7;
constexpr uint32_t kEvtPartialB = 0x3f8;
constexpr uint32_t kEvtTooFast = 0x3f9;
constexpr uint32_t kEvtVendor1002 = 0x3fd;
constexpr uint32_t kEvtGood = 0x3ff;
constexpr uint32_t kEvtEnrollRemaining = 0x40d;  // v1=fid, v2=remaining steps
constexpr uint32_t kEvtTimeout = 0x40e;
constexpr uint32_t kEvtAuthFailB = 0x424;
constexpr uint32_t kEvtLockoutTimed = 0xbb9;
constexpr uint32_t kEvtLockoutPermanent = 0xbba;

static_assert(sizeof(hw_auth_token_t) == 69, "hw_auth_token_t must be packed (69 bytes)");

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

    // g_custom_ini_path is a data symbol; dlsym returns the buffer itself.
    mCustomIniPath = LoadFunction<char*>(mHandle.get(), "g_custom_ini_path");

    // Path must be set before rbs_initialize (library creates its ini config then).
    setIniPath(0);

    // Stock sets the data path and callback before fetching the master key; the
    // keymaster TA rejects the request until the RBS TA has been brought up.
    constexpr char kDataPath[] = "/data/system/users/0/fpdata";
    if (CHECK_RBS_FUNCTION(setDataPath)) {
        mRbsFlow->setDataPath(1, kDataPath, strlen(kDataPath));
    }
    if (CHECK_RBS_FUNCTION(setOnCallbackProc)) {
        mRbsFlow->setOnCallbackProc(reinterpret_cast<void*>(FingerprintEngineRbs::notify));
    }

    uint8_t masterkey[0x100] = {};
    uint32_t masterkeySize = sizeof(masterkey);
    if (getSecureKey(masterkey, &masterkeySize) != 0) {
        ALOGE("Failed to fetch secure key for RBS sensor");
    } else if (CHECK_RBS_FUNCTION(initialize) &&
               mRbsFlow->initialize(masterkey, masterkeySize) == 0) {
        mInitialized = true;
    } else {
        ALOGE("Failed to initialize RBS sensor");
    }
    memset(masterkey, 0, sizeof(masterkey));

    if (mUdfpsHandler) {
        mUdfpsHandler->init(nullptr);
    }
}

std::shared_ptr<FingerprintEngine> FingerprintEngineRbs::create(
        std::shared_ptr<FingerprintConfig> config) {
    auto engine = std::make_shared<FingerprintEngineRbs>(std::move(config));
    if (!engine->mInitialized) {
        ALOGE("Failed to set up fingerprint RBS engine");
        return nullptr;
    }
    return engine;
}

FingerprintEngineRbs::~FingerprintEngineRbs() {
    sInstance = nullptr;
    if (mInitialized && CHECK_RBS_FUNCTION(uninitialize)) {
        mRbsFlow->uninitialize();
    }
}

void FingerprintEngineRbs::setIniPath(int userId) {
    if (mCustomIniPath == nullptr) {
        return;
    }
    auto path = std::format("/data/vendor_de/{}/fpdata/", userId);
    mkdir(path.c_str(), 0700);
    snprintf(mCustomIniPath, kIniPathSize, "%s", path.c_str());
}

void FingerprintEngineRbs::startSession(std::shared_ptr<ISessionCallback> cb, int userId) {
    mCb = std::move(cb);
    mUserId = userId;

    setIniPath(userId);

    if (!CHECK_RBS_FUNCTION(setOnCallbackProc) ||
        mRbsFlow->setOnCallbackProc(reinterpret_cast<void*>(FingerprintEngineRbs::notify)) != 0) {
        ALOGE("Can't register fingerprint module callback");
        return;
    }

    if (CHECK_RBS_FUNCTION(activeUserGroup)) {
        // Stock passes path without trailing slash.
        std::string path = std::format("/data/vendor_de/{}/fpdata", userId);
        int32_t rc = mRbsFlow->activeUserGroup(userId, path.c_str());
        if (rc != 0) {
            ALOGE("activeUserGroup failed: %d", rc);
        }
    }
}

void FingerprintEngineRbs::endSession() {
    mCb->onSessionClosed();

    int ret = mRbsFlow->setOnCallbackProc(nullptr);
    if (ret == 0) {
        ALOGE("Can't register fingerprint module callback");
    }
}

ndk::ScopedAStatus FingerprintEngineRbs::generateChallengeImpl() {
    uint64_t challenge;
    do {
        arc4random_buf(&challenge, sizeof(challenge));
    } while (challenge == 0);

    mChallenge = challenge;
    mCb->onChallengeGenerated(static_cast<int64_t>(challenge));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::revokeChallengeImpl(int64_t challenge) {
    mChallenge = 0;
    mCb->onChallengeRevoked(challenge);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::enrollImpl(const HardwareAuthToken& hat) {
    auto fail = [this](Error error) {
        mCb->onError(error, 0);
        return ndk::ScopedAStatus::ok();
    };

    if (!mInitialized || !CHECK_RBS_FUNCTION(chkAuthToken) || !CHECK_RBS_FUNCTION(chkSecureId) ||
        !CHECK_RBS_FUNCTION(preEnroll) || !CHECK_RBS_FUNCTION(enroll)) {
        ALOGE("enroll: RBS not ready");
        return fail(Error::HW_UNAVAILABLE);
    }

    // Challenge is engine-scoped; reject tokens from a different instance.
    if (mChallenge == 0 || hat.challenge != static_cast<int64_t>(mChallenge)) {
        ALOGE("enroll: challenge mismatch");
        return fail(Error::UNABLE_TO_PROCESS);
    }

    const uint32_t gid = static_cast<uint32_t>(mUserId);

    hw_auth_token_t authToken;
    translate(hat, authToken);

    int32_t rc = mRbsFlow->chkAuthToken(&authToken, sizeof(authToken));
    if (rc != 0) {
        ALOGE("enroll: auth token check failed: %d", rc);
        return fail(rc == kRbsAuthTokenInvalid ? Error::TIMEOUT : Error::UNABLE_TO_PROCESS);
    }

    // Secure ID mismatch => credential changed; wipe templates and retry.
    const uint64_t secureId = static_cast<uint64_t>(hat.userId);
    rc = mRbsFlow->chkSecureId(gid, secureId);
    if (rc == kRbsSecureIdMismatch) {
        ALOGW("enroll: secure id mismatch, removing all fingerprints");
        if (CHECK_RBS_FUNCTION(removeFingerprint)) {
            int32_t rrc = mRbsFlow->removeFingerprint(gid, 0);  // 0 == all
            if (rrc != 0) {
                ALOGE("enroll: remove all failed: %d", rrc);
            }
        }
        rc = mRbsFlow->chkSecureId(gid, secureId);
    }
    if (rc != 0) {
        ALOGE("enroll: secure id check failed: %d", rc);
        return fail(Error::UNABLE_TO_PROCESS);
    }

    // Random fid; retry on collision, stop on no-space.
    rc = -1;
    for (int attempt = 0; attempt < 16; ++attempt) {
        uint32_t fid;
        arc4random_buf(&fid, sizeof(fid));
        if (fid == 0) {
            continue;  // 0 means "all" for removeFingerprint
        }
        rc = mRbsFlow->preEnroll(gid, fid);
        if (rc == kRbsNoSpace) {
            ALOGE("enroll: no space for new fingerprint");
            return fail(Error::NO_SPACE);
        } else if (rc != 0) {
            ALOGE("enroll: pre_enroll failed: %d", rc);
            return fail(Error::UNABLE_TO_PROCESS);
        }
    }

    // HBM / display handled by mUdfpsHandler.

    rc = mRbsFlow->enroll();
    if (rc != 0) {
        ALOGE("enroll failed: %d", rc);
        return fail(rc == kRbsHwUnavailable ? Error::HW_UNAVAILABLE : Error::UNABLE_TO_PROCESS);
    }
    return ndk::ScopedAStatus::fromExceptionCode(EX_SERVICE_SPECIFIC);
}

ndk::ScopedAStatus FingerprintEngineRbs::authenticateImpl(int64_t operationId) {
    if (checkSensorLockout()) {
        return ndk::ScopedAStatus::ok();
    }
    if (!mInitialized || !CHECK_RBS_FUNCTION(authenticator) ||
        mRbsFlow->authenticator(mUserId, nullptr, 0, operationId) != 0) {
        ALOGE("authenticate failed");
        mCb->onError(Error::UNABLE_TO_PROCESS, 0);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::enumerateEnrollmentsImpl() {
    uint32_t fids[kMaxFingerprints] = {};
    uint32_t numFids = kMaxFingerprints;  // in/out; library rejects > 5
    std::vector<int32_t> enrollments;

    if (CHECK_RBS_FUNCTION(getFingerprintIds) &&
        mRbsFlow->getFingerprintIds(mUserId, fids, &numFids) == 0 && numFids <= kMaxFingerprints) {
        enrollments.assign(fids, fids + numFids);
    } else {
        ALOGE("enumerate failed");
    }

    // Always complete so the framework does not hang.
    mCb->onEnrollmentsEnumerated(enrollments);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::removeEnrollmentsImpl(
        const std::vector<int32_t>& enrollmentIds) {
    bool failed = !CHECK_RBS_FUNCTION(removeFingerprint);
    for (int32_t fid : enrollmentIds) {
        if (failed) {
            break;
        }
        int32_t rc = mRbsFlow->removeFingerprint(mUserId, fid);
        if (rc != 0) {
            ALOGE("remove failed: %d", rc);
            failed = true;
        }
    }

    if (failed) {
        mCb->onError(Error::UNABLE_TO_REMOVE, 0);
    } else {
        mCb->onEnrollmentsRemoved(enrollmentIds);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::getAuthenticatorIdImpl() {
    uint64_t authId = 0;
    if (CHECK_RBS_FUNCTION(getAuthenticatorId)) {
        mRbsFlow->getAuthenticatorId(&authId);
    }
    mCb->onAuthenticatorIdRetrieved(static_cast<int64_t>(authId));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::invalidateAuthenticatorIdImpl() {
    // invalidate returns no ID; read the new one afterward.
    uint64_t authId = 0;
    if (CHECK_RBS_FUNCTION(invalidateAuthId)) {
        mRbsFlow->invalidateAuthId();
    }
    if (CHECK_RBS_FUNCTION(getAuthenticatorId)) {
        mRbsFlow->getAuthenticatorId(&authId);
    }
    mCb->onAuthenticatorIdInvalidated(static_cast<int64_t>(authId));
    return ndk::ScopedAStatus::ok();
}

void FingerprintEngineRbs::sendTouchEvent(uint32_t* in, uint32_t size) {
    if (!CHECK_RBS_FUNCTION(extraApi)) {
        return;
    }

    uint32_t out[kExtraOutSize / sizeof(uint32_t)] = {};
    uint32_t outSize = kExtraOutSize;
    int32_t rc = mRbsFlow->extraApi(kExtraCmdTouch, in, size, out, &outSize);
    if (rc != 0) {
        ALOGE("touch event %u failed: %d", in[0], rc);
    }
}

ndk::ScopedAStatus FingerprintEngineRbs::onPointerDownImpl(int32_t /* pointerId */, int32_t x,
                                                           int32_t y, float minor, float major) {
    // Illumination must be up before the library starts capturing.
    if (mUdfpsHandler) {
        mUdfpsHandler->onFingerDown(x, y, minor, major);
    }

    // Stock fills payload[1] from IMotoFingerPrint::sendFodEvent; 0 when unused.
    uint32_t in[2] = {kTouchFingerDown, 0};
    sendTouchEvent(in, sizeof(in));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::onPointerUpImpl(int32_t /* pointerId */) {
    uint32_t in[1] = {kTouchFingerUp};
    sendTouchEvent(in, sizeof(in));

    if (mUdfpsHandler) {
        mUdfpsHandler->onFingerUp();
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngineRbs::cancelImpl() {
    if (mUdfpsHandler) {
        mUdfpsHandler->cancel();
    }

    // Library may also emit 0x3e9/0x3eb (-> CANCELED) after cancel.
    if (CHECK_RBS_FUNCTION(cancel) && mRbsFlow->cancel() == 0) {
        mCb->onError(Error::CANCELED, 0);
        return ndk::ScopedAStatus::ok();
    }
    return ndk::ScopedAStatus::fromServiceSpecificError(-ECANCELED);
}

ndk::ScopedAStatus FingerprintEngineRbs::resetLockoutImpl(const HardwareAuthToken& hat) {
    // Clear library lockout only after a valid token (matches stock).
    hw_auth_token_t authToken;
    translate(hat, authToken);
    if (CHECK_RBS_FUNCTION(chkAuthToken) &&
        mRbsFlow->chkAuthToken(&authToken, sizeof(authToken)) == 0) {
        if (CHECK_RBS_FUNCTION(lockoutInfoReset)) {
            mRbsFlow->lockoutInfoReset();
        }
    } else {
        ALOGE("resetLockout: auth token check failed");
    }
    return FingerprintEngine::resetLockoutImpl(hat);
}

void FingerprintEngineRbs::onAcquired(AcquiredInfo info, int32_t vendorCode) {
    if (mUdfpsHandler) {
        mUdfpsHandler->onAcquired(static_cast<int32_t>(info), vendorCode);
    }
    mCb->onAcquired(info, vendorCode);
}

void FingerprintEngineRbs::notify(uint32_t eventId, uint32_t value1, uint32_t value2,
                                  void* buffer, uint32_t bufferSize) {
    if (sInstance == nullptr || sInstance->mCb == nullptr) {
        ALOGE("Can't dispatch notification: Engine context or Callback is missing");
        return;
    }

    switch (eventId) {
        case kEvtEnrollFailA:
        case kEvtEnrollFailB:
            sInstance->mCb->onError(Error::CANCELED, 0);
            break;
        case kEvtTimeout:
            sInstance->mCb->onError(Error::TIMEOUT, 0);
            break;
        case kEvtGood:
            sInstance->onAcquired(AcquiredInfo::GOOD, 0);
            break;
        case kEvtPartialA:
        case kEvtPartialB:
            sInstance->onAcquired(AcquiredInfo::PARTIAL, 0);
            break;
        case kEvtInsufficient:
            sInstance->onAcquired(AcquiredInfo::INSUFFICIENT, 0);
            break;
        case kEvtTooSlowA:
        case kEvtTooSlowB:
            sInstance->onAcquired(AcquiredInfo::TOO_SLOW, 0);
            break;
        case kEvtTooFast:
            sInstance->onAcquired(AcquiredInfo::TOO_FAST, 0);
            break;
        case kEvtImmobileA:
        case kEvtImmobileB:
            sInstance->onAcquired(AcquiredInfo::IMMOBILE, 0);
            break;
        case kEvtVendor1000:
            sInstance->onAcquired(AcquiredInfo::VENDOR, 0);
            break;
        case kEvtVendor1002:
            sInstance->onAcquired(AcquiredInfo::VENDOR, 2);
            break;
        case kEvtEnrollLegacyOk:
            // Percentage; library re-emits as kEvtEnrollRemaining.
            break;
        case kEvtEnrollRemaining:
            sInstance->mCb->onEnrollmentProgress(static_cast<int32_t>(value1), static_cast<int32_t>(value2));
            break;
        case kEvtAuthSuccess: {
            // value1=gid, value2=fid (inferred from stock).
            ALOGD("auth success: value1=%u value2=%u size=%u", value1, value2, bufferSize);
            HardwareAuthToken hat{};
            if (buffer != nullptr && bufferSize == sizeof(hw_auth_token_t)) {
                hw_auth_token_t raw;
                memcpy(&raw, buffer, sizeof(raw));
                translate(raw, hat);
            } else {
                ALOGE("auth success without valid HAT (size=%u)", bufferSize);
            }
            if (sInstance->mUdfpsHandler) {
                sInstance->mUdfpsHandler->onAuthenticationSucceeded();
            }
            sInstance->mCb->onAuthenticationSucceeded(static_cast<int32_t>(value2), hat);
            sInstance->clearLockout(true);
            if (CHECK_RBS_FUNCTION_ON(sInstance, lockoutInfoReset)) {
                sInstance->mRbsFlow->lockoutInfoReset();
            }
            break;
        }
        case kEvtAuthFailA:
        case kEvtAuthFailB:
            if (sInstance->mUdfpsHandler) {
                sInstance->mUdfpsHandler->onAuthenticationFailed();
            }
            sInstance->mCb->onAuthenticationFailed();
            sInstance->checkSensorLockout();
            break;
        // Library lockout events; LockoutTracker is authoritative.
        case kEvtLockoutTimed:
        case kEvtLockoutPermanent:
            ALOGW("library lockout event 0x%x", eventId);
            break;
        default:
            ALOGD("Unhandled vendor callback eventId: 0x%x (%u, %u)", eventId, value1, value2);
            break;
    }
}

int32_t FingerprintEngineRbs::getSecureKey(void* masterkey, uint32_t* size) {
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
    ets_masterkey_response rcvBuf = {};
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

    if (qsc_start_app == nullptr || qsc_shutdown_app == nullptr ||
        ets_keymaster_send_cmd == nullptr) {
        ALOGE("TEE client is missing required symbols");
        dlclose(teeClientHandle);
        return -1;
    }

    rc = qsc_start_app(&keymasterHandle, "keymaster64", 0x2000);
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
    } else if (rcvBuf.size > sizeof(rcvBuf.masterkey)) {
        ALOGE("Bogus master key size %u", rcvBuf.size);
        rc = -EINVAL;
    } else if (*size < rcvBuf.size) {
        ALOGE("Output buffer too short, expected size %u, got size %u", rcvBuf.size, *size);
        rc = -ENOMEM;
    } else {
        // Caller pre-zeroes the buffer; copy only what the TA returned.
        memcpy(masterkey, rcvBuf.masterkey, rcvBuf.size);
        *size = rcvBuf.size;
    }

    memset(&rcvBuf, 0, sizeof(rcvBuf));
    qsc_shutdown_app(&keymasterHandle);
    dlclose(teeClientHandle);

    return rc;
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
