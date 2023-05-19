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

        class EnclaveHandler
        {
        private:
            sgx_enclave_id_t enclaveId;

        public:
            EnclaveHandler(std::string_view enclaveName)
            {
                uint32_t ret {};
                ret = sgx_create_enclave(enclaveName.data(), 1, nullptr, nullptr, &enclaveId, nullptr);
                if (ret != SGX_SUCCESS)
                    throw std::runtime_error("Failed initializing enclave");
            }

            ~EnclaveHandler()
            {
                sgx_destroy_enclave(enclaveId);
            }

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
    
    class TrustedTimeHandler
    {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

        void startTPMAttestation();
        void proofTPMAttestation();
        void getTPMTime();

        void timeThreadFunc();
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
        TrustedTimeHandler(sgx::EnclaveHandler& enclave, SigScheme scheme);
        void start();
        void stop();
        std::tuple<bool, uint64_t, uint64_t> getTrustedTime();

        void activateCredential(TPMPrivateObjectData const& attestationKey, std::span<uint8_t const> credential,
                                std::span<uint8_t const> encryptedSeed, std::span<uint8_t> outToken);
        TPMGetTimeData getTime(std::span<uint8_t const> qualifyingData);

        static void setTimeLog(bool timeLog);

        ~TrustedTimeHandler();
    };
} // namespace t3e

#endif