#include "TPMHandler.h"
#include "tss2/tss2_tpm2_types.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <sstream>
#include <stdexcept>

#include <chrono>
#include <iostream>


using namespace t3e;
using namespace t3e::tpm;

TSS2_ABI_VERSION tpm::EsysContext::currentABI = TSS2_ABI_VERSION_CURRENT;

template<typename T,
         typename TFreeFunc = decltype(
             [](T* x)
             {
                 std::free(x);
             })>
class OutPtr
{
    T* handle {nullptr};

public:
    OutPtr() {}
    operator T**()
    {
        if (handle != nullptr)
        {
            TFreeFunc()(handle);
            handle = nullptr;
        }
        return &handle;
    }

    bool valid() const
    {
        return handle != nullptr;
    }

    T& operator*() const
    {
        return *handle;
    }

    T* operator->() const
    {
        return handle;
    }

    ~OutPtr()
    {
        if (handle != nullptr)
        {
            TFreeFunc()(handle);
            handle = nullptr;
        }
    }
};

EsysContext::EsysContext()
{
    auto rc = Esys_Initialize(&ectx, nullptr, &currentABI);
    switch (rc)
    {
    case TSS2_RC_SUCCESS:
        break;
    case TSS2_ESYS_RC_MEMORY:
        throw std::bad_alloc();
        break;
    case TSS2_ESYS_RC_ABI_MISMATCH:
        throw std::runtime_error("ABI Mismatch");
        break;
    case TSS2_ESYS_RC_IO_ERROR:
        throw std::runtime_error("I/O Error, typically Access Denied.");
        break;
    case TSS2_ESYS_RC_BAD_TCTI_STRUCTURE:
    case TSS2_ESYS_RC_INCOMPATIBLE_TCTI:
    case TSS2_ESYS_RC_BAD_REFERENCE:
    default:
        std::terminate(); // Should be unreachable
        break;
    }
}

EsysContext& EsysContext::operator=(EsysContext&& that)
{
    if (ectx != nullptr)
        Esys_Finalize(&ectx);

    ectx      = that.ectx;
    that.ectx = nullptr;

    return *this;
}

TSS2_SYS_CONTEXT* EsysContext::getSysContext() const
{
    TSS2_SYS_CONTEXT* ret = nullptr;
    Esys_GetSysContext(this->ectx, &ret);
    return ret;
}

bool EsysContext::setTimeout(int32_t timeout)
{
    return Esys_SetTimeout(this->ectx, timeout) == TSS2_RC_SUCCESS;
}

EsysContext::~EsysContext()
{
    if (ectx != nullptr)
        Esys_Finalize(&ectx);
}

void EsysSession::setPasswordPolicySecret(ESYS_TR shandle)
{
    TPM2_RC rc = Esys_PolicySecret(this->ctx, ESYS_TR_RH_ENDORSEMENT, sessionHandle, shandle, ESYS_TR_NONE,
                                   ESYS_TR_NONE, NULL, NULL, NULL, 0, NULL, NULL);
    if (rc != TPM2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "Setting PolicySecret failed: " << std::hex << rc << "\n";
        throw std::runtime_error(std::move(ss).str());
    }
}

void EsysSession::setAuthValue(std::string_view pass)
{
    TPM2B_AUTH authValue {
        .size = static_cast<uint16_t>(pass.length()),
    };
    std::copy(pass.begin(), pass.end(), authValue.buffer);

    TSS2_RC rval = Esys_TR_SetAuth(this->ctx, sessionHandle, &authValue);
    if (rval != TPM2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "Setting AuthValue failed: " << std::hex << rval << "\n";
        throw std::runtime_error(std::move(ss).str());
    }
}

EsysSession::EsysSession(EsysContext const& ctx, TPM2_SE sessionType): ctx(ctx)
{
    TPMT_SYM_DEF symmetric {.algorithm = TPM2_ALG_NULL};

    auto rc = Esys_StartAuthSession(this->ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    NULL, sessionType, &symmetric, TPM2_ALG_SHA256, &this->sessionHandle);
    if (rc != TSS2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "Auth session failed: " << std::hex << rc << "\n";
        throw std::runtime_error(std::move(ss).str());
    }
}

EsysSession::~EsysSession()
{
    Esys_FlushContext(this->ctx, this->sessionHandle);
}

auto EsysContext::createPrimary(ESYS_TR primaryHandle, TPM2B_SENSITIVE_CREATE const& sensitive,
                                TPM2B_PUBLIC const& publicArea, TPM2B_DATA const& outsideInfo,
                                TPML_PCR_SELECTION const& creationPCR) const -> std::tuple<ESYS_TR, TPMObjectData>
{
    OutPtr<TPM2B_PUBLIC> publicOut;
    OutPtr<TPM2B_CREATION_DATA> creationData;
    OutPtr<TPM2B_DIGEST> creationHash;
    OutPtr<TPMT_TK_CREATION> creationTicket;
    ESYS_TR outHandle = ESYS_TR_NONE;

    EsysSession tpmSession {*this, TPM2_SE_HMAC};

    auto rc = Esys_CreatePrimary(this->ectx, primaryHandle, tpmSession, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
                                 &publicArea, &outsideInfo, &creationPCR, &outHandle, publicOut, creationData,
                                 creationHash, creationTicket);

    if (rc != TSS2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "CreatePrimary failed: " << std::hex << rc << "\n";
        throw std::runtime_error(std::move(ss).str());
    }

    return {
        outHandle, TPMObjectData {*publicOut, *creationHash, *creationData, *creationTicket}
    };
}

auto EsysContext::createObject(EsysSession const& sessionHandle, ESYS_TR primaryKeyHandle,
                               TPM2B_SENSITIVE_CREATE const& sensitive, TPM2B_PUBLIC const& publicArea,
                               TPM2B_DATA const& outsideInfo, TPML_PCR_SELECTION const& creationPCR) const
    -> TPMPrivateObjectData
{
    OutPtr<TPM2B_PRIVATE> privateOut;
    OutPtr<TPM2B_PUBLIC> publicOut;
    OutPtr<TPM2B_CREATION_DATA> creationData;
    OutPtr<TPM2B_DIGEST> creationHash;
    OutPtr<TPMT_TK_CREATION> creationTicket;

    auto rc =
        Esys_Create(this->ectx, primaryKeyHandle, sessionHandle, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &publicArea,
                    &outsideInfo, &creationPCR, privateOut, publicOut, creationData, creationHash, creationTicket);

    if (rc != TSS2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "Create failed: " << std::hex << rc << "\n";
        throw std::runtime_error(std::move(ss).str());
    }

    return {*publicOut, *creationHash, *creationData, *creationTicket, *privateOut};
}

ESYS_TR EsysContext::loadObject(EsysSession const& sessionHandle, ESYS_TR parentHandle,
                                TPMPrivateObjectData const& object) const
{
    ESYS_TR outHandle;
    auto rc = Esys_Load(this->ectx, parentHandle, sessionHandle, ESYS_TR_NONE, ESYS_TR_NONE, &object.privateArea,
                        &object.objectData.publicArea, &outHandle);

    if (rc != TSS2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "Load failed: " << std::hex << rc << "\n";
        throw std::runtime_error(std::move(ss).str());
    }

    return outHandle;
}

auto EsysContext::activateCredential(ESYS_TR primaryHandle, ESYS_TR keyObject, std::span<uint8_t const> credentialBin,
                                     std::span<uint8_t const> secretBin) const -> std::vector<uint8_t>
{
    // Perform size sanity check
    TPM2B_ID_OBJECT credentialBlob {.size = static_cast<uint16_t>(credentialBin.size())};
    std::copy(credentialBin.begin(), credentialBin.end(), credentialBlob.credential);

    // Perform size sanity check
    TPM2B_ENCRYPTED_SECRET secret {
        .size = static_cast<uint16_t>(secretBin.size()),
    };
    std::copy(secretBin.begin(), secretBin.end(), secret.secret);

    OutPtr<TPM2B_DIGEST> certInfo;

    EsysSession policySession {*this, TPM2_SE_POLICY};
    policySession.setPasswordPolicySecret();

    EsysSession privateObjectSession {*this, TPM2_SE_HMAC};

    std::string_view pass = "akpass";
    TPM2B_AUTH authValue {
        .size = static_cast<uint16_t>(pass.length()),
    };
    std::copy(pass.begin(), pass.end(), authValue.buffer);
    Esys_TR_SetAuth(this->ectx, keyObject, &authValue);

    auto rc = Esys_ActivateCredential(this->ectx, keyObject, primaryHandle, privateObjectSession, policySession,
                                      ESYS_TR_NONE, &credentialBlob, &secret, certInfo);

    if (rc != TSS2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "ActivateCredential failed: " << std::hex << rc << std::endl;
        return {};
        // throw std::runtime_error(std::move(ss).str());
    }

    std::vector<uint8_t> ret;
    ret.resize(certInfo->size);

    std::memcpy(ret.data(), certInfo->buffer, certInfo->size);
    return ret;
}


auto EsysContext::getTime(EsysSession const& sessionHandle, EsysSession const& authSessionHandle, ESYS_TR signerHandle, TPMI_ALG_SIG_SCHEME algScheme, std::span<uint8_t const> qualifyingData) const -> TPMGetTimeData
{
    // clang-format off
    TPMT_SIG_SCHEME sigScheme {
        .scheme = algScheme,
        .details = {
            .any = {
                .hashAlg = TPM2_ALG_SHA256,
            },
        },
    };
    // clang-format on

    TPMT_SYM_DEF symmetric {.algorithm = TPM2_ALG_NULL};

    if(qualifyingData.size() > sizeof(TPM2B_DATA{}.buffer))
        throw std::runtime_error("qualifyingData too big");

    TPM2B_DATA qualifyingDataBuf {
        .size = static_cast<uint16_t>(qualifyingData.size())
    };

    std::copy_n(qualifyingData.begin(), qualifyingDataBuf.size, qualifyingDataBuf.buffer);

    OutPtr<TPM2B_ATTEST> timeInfo;
    OutPtr<TPMT_SIGNATURE> signature;

    auto start = std::chrono::system_clock::now(); 
    auto rc        = Esys_GetTime(this->ectx, ESYS_TR_RH_ENDORSEMENT, signerHandle, sessionHandle, authSessionHandle,
                                  ESYS_TR_NONE, &qualifyingDataBuf, &sigScheme, timeInfo, signature);
    auto elapsed = std::chrono::system_clock::now() - start;

    //std::cout << "GetTime elapsed: " << elapsed.count() << " ns" << std::endl; 

    if (rc != TSS2_RC_SUCCESS)
    {
        std::stringstream ss;
        ss << "GetTime failed: " << std::hex << rc << "\n";
        throw std::runtime_error(std::move(ss).str());
    }

    return { *timeInfo, *signature };
}