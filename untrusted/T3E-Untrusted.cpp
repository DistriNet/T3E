#include "T3E-Untrusted.h"
#include "TPMHandler.h"
#include <chrono>
#include <cstdint>
#include <date/date.h>
#include <iostream>
#include <locale>
#include <optional>
#include <sgx_urts.h>

using namespace t3e;

bool showTimeLog = false;

struct TrustedTimeHandler::Impl
{
    // TPM Data
    tpm::EsysContext context;
    ESYS_TR primaryHandle {ESYS_TR_NONE};
    TPMObjectData primaryObjectData;

    ESYS_TR keyObjectHandle {ESYS_TR_NONE};
    std::optional<tpm::EsysSession> getTimeSession;

    std::optional<tpm::EsysSession> getTimeAuthSession;

    // Enclave Data
    sgx::EnclaveHandler& enclave;
    SigScheme scheme;

    constexpr auto getEKInitializer(SigScheme scheme)
    {
        switch (scheme)
        {
        case RSASSA:
        case RSAPSS:
            return tpm::initializer::DEFAULT_EK_PUBLIC;
        case ECDSA:
            return tpm::initializer::DEFAULT_EK_PUBLIC_ECC;
        }
    }

    Impl(sgx::EnclaveHandler& enclave, SigScheme scheme): scheme(scheme), enclave(enclave)
    {
        // Get TPM
        auto [primaryHandle, primaryObject] = context.createPrimary(
            ESYS_TR_RH_ENDORSEMENT, tpm::initializer::DEFAULT_SENSITIVE_CREATE, getEKInitializer(scheme),
            tpm::initializer::EMPTY_OUTSIDE_INFO, tpm::initializer::EMPTY_PCR_SELECTION);

        this->primaryHandle     = primaryHandle;
        this->primaryObjectData = primaryObject;
    }

    constexpr auto getAKInitializer(SigScheme scheme)
    {
        switch (scheme)
        {
        case RSASSA:
            return tpm::initializer::DEFAULT_AK;
        case RSAPSS:
            return tpm::initializer::DEFAULT_AK_RSAPSS;
        case ECDSA:
            return tpm::initializer::DEFAULT_AK_ECC;
        }
    }

    auto createAttestationKey()
    {
        tpm::EsysSession policySession {context, TPM2_SE_POLICY};
        policySession.setPasswordPolicySecret();

        auto object = context.createObject(policySession, primaryHandle, tpm::initializer::DEFAULT_SENSITIVE_CREATE_AK,
                                           getAKInitializer(scheme), tpm::initializer::EMPTY_OUTSIDE_INFO,
                                           tpm::initializer::EMPTY_PCR_SELECTION);

        return object;
    }

    void loadObject(TPMPrivateObjectData const& obj)
    {
        tpm::EsysSession policySession {context, TPM2_SE_POLICY};
        policySession.setPasswordPolicySecret();

        keyObjectHandle = context.loadObject(policySession, primaryHandle, obj);
    }

    auto activateCredential(std::span<uint8_t const> credential, std::span<uint8_t const> encryptedSeed)
    {
        return context.activateCredential(primaryHandle, keyObjectHandle, credential, encryptedSeed);
    }

    auto getTime(std::span<uint8_t const> qualifyingData)
    {
        if (getTimeSession == std::nullopt)
            getTimeSession.emplace(context, TPM2_SE_HMAC);

        if (getTimeAuthSession == std::nullopt)
            getTimeAuthSession.emplace(context, TPM2_SE_HMAC);

        return context.getTime(*getTimeSession, *getTimeAuthSession, keyObjectHandle, scheme, qualifyingData);
    }

    ~Impl()
    {
        Esys_FlushContext(context, keyObjectHandle);
    }
};

void TrustedTimeHandler::startTPMAttestation()
{
    auto attestationKey = impl->createAttestationKey();
}

void TrustedTimeHandler::proofTPMAttestation() {}
void TrustedTimeHandler::getTPMTime() {}

TrustedTimeHandler::TrustedTimeHandler(sgx::EnclaveHandler& enclave, SigScheme scheme):
    impl(std::make_unique<Impl>(enclave, scheme))
{
}

void TrustedTimeHandler::start()
{
    timeThread    = std::jthread {&TrustedTimeHandler::timeThreadFunc, this};
    counterThread = std::jthread {&TrustedTimeHandler::counterThreadFunc, this};
}

void TrustedTimeHandler::counterThreadFunc()
{
    // Enter Enclave
    impl->enclave.ecall<t3e_TrustedTime_counterThread>();
}

void TrustedTimeHandler::timeThreadFunc()
{
    // Start attestation sequence

    // Create attestation key
    auto attestationKey = impl->createAttestationKey();

    // Enter Enclave
    /*
    t3e_TrustedTime_start(impl->enclaveId, reinterpret_cast<intptr_t>(this), &impl->primaryObjectData,
                            &attestationKey);
    */
    // We pass the `this` pointer so it can be passed back to the OCALL and perform callback, because the OCALL is a
    // static free function, not instance function.
    impl->enclave.ecall<t3e_TrustedTime_start>(reinterpret_cast<intptr_t>(this), &impl->primaryObjectData,
                                               &attestationKey);
}

std::tuple<bool, uint64_t, uint64_t> TrustedTimeHandler::getTrustedTime()
{
    // Enter Enclave
    uint64_t time {};
    uint64_t counter {};
    uint8_t trustedTimeAvailable = impl->enclave.ecall<t3e_TrustedTime_getTrustedTime>(&time, &counter);
    return std::tuple {trustedTimeAvailable == 1, time, counter};
}

void TrustedTimeHandler::stop()
{
    // Send signal to the enclave to stop looping
    impl->enclave.ecall<t3e_TrustedTime_stop>();
}

void TrustedTimeHandler::activateCredential(TPMPrivateObjectData const& attestationKey,
                                            std::span<uint8_t const> credential, std::span<uint8_t const> encryptedSeed,
                                            std::span<uint8_t> outToken)
{
    // Load object to local context
    impl->loadObject(attestationKey);

    // Activate credential
    auto res = impl->activateCredential(credential, encryptedSeed);

    if (outToken.size() != res.size())
        throw std::runtime_error("Invalid result token size");

    std::copy(res.begin(), res.end(), outToken.begin());
}

TPMGetTimeData TrustedTimeHandler::getTime(std::span<uint8_t const> qualifyingData)
{
    return impl->getTime(qualifyingData);
}

void TrustedTimeHandler::setTimeLog(bool timeLog)
{
    showTimeLog = timeLog;
}

TrustedTimeHandler::~TrustedTimeHandler() {}

extern "C"
{
    void t3e_TrustedTime_activateCredential(intptr_t tthandle, const TPMPrivateObjectData* attestationKey,
                                            const uint8_t* credential, size_t cntCredential, const uint8_t* encSeed,
                                            size_t cntEncSeed, uint8_t* tokenOut, size_t cntTokenOut)
    {
        auto* ttobj = reinterpret_cast<TrustedTimeHandler*>(tthandle);

        ttobj->activateCredential(*attestationKey, {credential, cntCredential}, {encSeed, cntEncSeed},
                                  {tokenOut, cntTokenOut});
    }

    TPMGetTimeData t3e_TrustedTime_getTime(intptr_t tthandle, const uint8_t* qualifyingData, size_t qualifyingDataLen)
    {
        auto* ttobj = reinterpret_cast<TrustedTimeHandler*>(tthandle);
        return ttobj->getTime({qualifyingData, qualifyingDataLen});
    }

    void t3e_TrustedTime_debugPrintTime(uint64_t currentClock, uint64_t currentEpoch)
    {
        static uint64_t prevClock {};
        auto calculatedClock = std::chrono::system_clock::time_point(std::chrono::milliseconds(currentEpoch));
        std::cout << "Tick => TPM: " << currentClock << " - Since Epoch: " << calculatedClock
                  << " - Elapsed: " << (currentClock - prevClock) << std::endl;
        prevClock = currentClock;
    }

    void t3e_TrustedTime_debugTimeLog(TrustedTimeLog* log, size_t logCount)
    {
        if (!showTimeLog)
            return;

        std::cout << "TPM Time => Thread Counter \n";
        for (int i = 0; i < logCount; i++)
        {
            auto& curr = log[i];
            std::cout << curr.tpmTime << "\t" << curr.counterTime << "\n";
        }
        std::cout.flush();
    }

    uint64_t t3e_TrustedTime_getSystemTime()
    {
        auto currentTime = std::chrono::system_clock::now();
        auto ms          = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime.time_since_epoch()) % 1000;
        return std::chrono::system_clock::to_time_t(currentTime) * 1000 + ms.count();
    }

    void t3e_Test_DebugPrint(const char* str)
    {
        std::cout << "DEBUG: " << str << std::endl;
    }
}