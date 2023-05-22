#pragma once
#ifndef T3E_UNTRUSTED_H
#define T3E_UNTRUSTED_H

#include <sgx_urts.h>

#include <TPMStruct.h>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <iostream>

namespace t3e
{
    namespace sgx
    {
        template<typename TFunc>
        struct EnclaveFuncTrait;

        template<typename TFirst, typename... TArgs>
        struct EnclaveFuncTrait<sgx_status_t (*)(sgx_enclave_id_t, TFirst, TArgs...)>
        {
            using FirstParam              = TFirst;
            static constexpr size_t arity = sizeof...(TArgs) + 1;
        };

        template<>
        struct EnclaveFuncTrait<sgx_status_t (*)(sgx_enclave_id_t)>
        {
            using FirstParam              = void;
            static constexpr size_t arity = 0;
        };

        /**
         * @brief This is some fancy wrapper to Intel SGX SDK enclave library. It aids some mechanics to perform ECALL
         * and RAII over SGX enclave handle.
         */
        class EnclaveHandler
        {
        private:
            sgx_enclave_id_t enclaveId {};

        public:
            EnclaveHandler(std::string_view enclaveName)
            {
                uint32_t ret {};
                ret = sgx_create_enclave(enclaveName.data(), 1, nullptr, nullptr, &enclaveId, nullptr);
                if (ret != SGX_SUCCESS)
                    throw std::runtime_error("Failed initializing enclave");
            }

            EnclaveHandler(EnclaveHandler&& that): enclaveId(that.enclaveId)
            {
                that.enclaveId = 0;
            }
            EnclaveHandler& operator=(EnclaveHandler&& that)
            {
                this->enclaveId = that.enclaveId;
                that.enclaveId  = 0;
            }

            EnclaveHandler(EnclaveHandler const&)            = delete;
            EnclaveHandler& operator=(EnclaveHandler const&) = delete;

            ~EnclaveHandler()
            {
                if (enclaveId)
                    sgx_destroy_enclave(enclaveId);
            }

            /**
             * @brief Some fancy template to wrap the ECALL signature
             *
             * @tparam func ECALL function as declared in the generated header from EDL file
             * @tparam TArgs Automatically deduced from the args
             * @param args Parameters of the ECALL function
             * @return auto return value, in case of the first parameter in the EDL is an out parameter
             */
            template<auto func, typename... TArgs>
            auto ecall(TArgs&&... args)
            {
                using FuncTrait = EnclaveFuncTrait<decltype(func)>;

                if constexpr (FuncTrait::arity == sizeof...(TArgs))
                {
                    // This case, the function pointer argument has the same with supplied
                    // therefore, this ecall function returns void and just pass all args
                    sgx_status_t status = std::invoke(func, enclaveId, std::forward<TArgs>(args)...);

                    if (status != SGX_SUCCESS)
                        throw std::runtime_error("Unexpected enclave error");

                    return;
                }
                else if constexpr (FuncTrait::arity == sizeof...(TArgs) + 1)
                {
                    // This case, the caller supplies less one argument than the actual ecall signature
                    // therefore, we check if it returns a pointer or not. If it is, then it must be
                    // a return value
                    static_assert(std::is_pointer_v<typename FuncTrait::FirstParam>);

                    std::remove_pointer_t<typename FuncTrait::FirstParam> ret {};
                    sgx_status_t status = std::invoke(func, enclaveId, &ret, std::forward<TArgs>(args)...);

                    if (status != SGX_SUCCESS)
                        throw std::runtime_error("Unexpected enclave error");

                    return ret;
                }
                else
                {
                    static_assert(FuncTrait::arity > sizeof...(TArgs), "Wrong parameter");
                }
            }
        };
    } // namespace sgx

    /**
     * @brief The infrastructure that governs all the untrusted part of the T3E
     * 
     */
    class TrustedTimeHandler
    {
    private:
        /**
         * @brief Opaque pointer of the handler
         */
        struct Impl;
        std::unique_ptr<Impl> impl;

        /**
         * @brief Initialize the TPM attestation process
         */
        void startTPMAttestation();

        /**
         * @brief Complete the TPM attestation process
         */
        void proofTPMAttestation();

        /**
         * @brief Invoke the TPM2_GetTime function
         */
        void getTPMTime();

        /**
         * @brief The timer thread function that continuously request for the TPM time information
         */
        void timeThreadFunc();

        /**
         * @brief Additional counter thread if we are using counter to perform some measurement on experiment
         */
        void counterThreadFunc();
        std::jthread timeThread;
        std::jthread counterThread;

    public:
        enum SigScheme
        {
            RSASSA = TPM2_ALG_RSASSA,
            RSAPSS = TPM2_ALG_RSAPSS,
            ECDSA  = TPM2_ALG_ECDSA
        };
        /**
         * @brief Construct a new trusted time object, and supply the respective enclave
         * 
         * @param enclave The enclave, it must have the T3E API exposed
         * @param scheme Signature scheme to be used
         */
        TrustedTimeHandler(sgx::EnclaveHandler& enclave, SigScheme scheme);

        /**
         * @brief Start the time thread
         */
        void start();

        /**
         * @brief Stop the time thread
         */
        void stop();

        /**
         * @brief Get the current trusted time value from the untrusted domain. This will be called on a separate thread.
         * @return std::tuple<bool, uint64_t, uint64_t> 
         */
        std::tuple<bool, uint64_t, uint64_t> getTrustedTime();

        /**
         * @brief Proxy method to dispatch the OCALL from the trusted domain, to the activateCredential function
         * 
         * @param attestationKey TPM attestation key that was initially produced from TPM2_Create API
         * @param credential Encrypted data that is produced from the trusted domain, encrypted using the public key provided by the TPM.
         * @param encryptedSeed The encrypted seed that is used alongside the credential.
         * @param outToken Space to store the decrypted credential, which then the trusted domain can verify
         */
        void activateCredential(TPMPrivateObjectData const& attestationKey, std::span<uint8_t const> credential,
                                std::span<uint8_t const> encryptedSeed, std::span<uint8_t> outToken);

        /**
         * @brief Proxy method to dispatch the OCALL from the trusted domain, to the getTime function
         * 
         * @param qualifyingData Nonce
         * @return TPMGetTimeData Signed TPM time to be passed back to the trusted domain
         */
        TPMGetTimeData getTime(std::span<uint8_t const> qualifyingData);

        /**
         * @brief Some debugging feature
         * 
         * @param true to enable time logging 
         */
        static void setTimeLog(bool timeLog);

        ~TrustedTimeHandler();
    };
} // namespace t3e

#endif