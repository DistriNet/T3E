#pragma once
#ifndef TRUSTEDTIME_TPM_H
#define TRUSTEDTIME_TPM_H

#include <TPMStruct.h>
#include <span>
#include <string>
#include <tss2/tss2_esys.h>
#include <tuple>
#include <vector>

/**
 * @brief This header and its respective source is to encapsulate the C API of TPM2-TSS library so that it will
 * integrate nicely with the C++ pattern, including RAII.
 */

typedef struct ESYS_CONTEXT ESYS_CONTEXT;

namespace t3e::tpm
{
    class EsysContext;

    /**
     * @brief Type that represents a TPM session, and hold the lifetime of the session handle. This class is
     * non-copyable to enforce the RAII pattern. Think about the std::unique_ptr implementation for TPM session. Move
     * assignment is also not possible since a reference is used.
     */
    class EsysSession
    {
    private:
        ESYS_TR sessionHandle {ESYS_TR_NONE};
        EsysContext const& ctx;

    public:
        EsysSession(EsysContext const& ctx, TPM2_SE sessionType);

        EsysSession(EsysSession const&)            = delete;
        EsysSession& operator=(EsysSession const&) = delete;

        EsysSession(EsysSession&& that): sessionHandle(that.sessionHandle), ctx(that.ctx)
        {
            that.sessionHandle = ESYS_TR_NONE;
        };

        EsysSession& operator=(EsysSession&&) = delete;

        operator ESYS_TR() const
        {
            return this->sessionHandle;
        }

        void setPasswordPolicySecret(ESYS_TR shandle = ESYS_TR_PASSWORD);
        void setAuthValue(std::string_view pass);
        ~EsysSession();
    };

    /**
     * @brief Type that represent a TPM connection context. It is the main entry point for the communication between our
     * program and the TPM device via TPM2-TSS API. It is movable via move constructor and move assignment, however
     * doing so may invalidate the EsysSession that hold the reference to the previous object. Ideally, the referencing
     * mechanics should employ a weak-reference model, or observer pattern, whicever it is possible.
     */
    class EsysContext
    {
    private:
        ESYS_CONTEXT* ectx {nullptr};
        static TSS2_ABI_VERSION currentABI;

    public:
        EsysContext();
        EsysContext(EsysContext const&)            = delete;
        EsysContext& operator=(EsysContext const&) = delete;

        EsysContext(EsysContext&& that): ectx(that.ectx)
        {
            that.ectx = nullptr;
        }
        EsysContext& operator=(EsysContext&& that);

        /**
         * @brief Conversion operator to easily put this object into any TPM2-TSS API.
         *
         * @return ESYS_CONTEXT* The raw ESYS_CONTEXT pointer that is stored in this object. DO NOT INVALIDATE THIS
         * POINTER BY RELEASING IT.
         */
        operator ESYS_CONTEXT*() const
        {
            return this->ectx;
        }

        /**
         * @brief Set the timeout time for the TPM connection.
         *
         * @param timeout Timeout value in millisecond, or -1 to have no timeout.
         * @return true if success, false otherwise
         */
        bool setTimeout(int32_t timeout);

        /**
         * @brief Create a TPM Primary object, which can be Endorsement Key, Owner Key, or Platform Key
         *
         * @param primaryHandle ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM, ESYS_TR_RH_PLATFORM_NV,
         * or TPM2_RH_NULL.
         * @param sensitive The TPM2B_SENSITIVE_CREATE object that configures the primary object. See:
         * tpm::initializer::DEFAULT_SENSITIVE_CREATE.
         * @param publicArea The TPM2B_PUBLIC object that configures the primary object. See:
         * tpm::initializer::DEFAULT_EK_PUBLIC or tpm::initializer::DEFAULT_EK_PUBLIC_ECC.
         * @param outsideInfo Information to attach to the primary object to provide linkage between the primary object
         * and the owning program. See: tpm::initializer::EMPTY_OUTSIDE_INFO.
         * @param creationPCR PCR that will be used in creation data. See: tpm::initializer::EMPTY_PCR_SELECTION)
         * @return std::tuple<ESYS_TR, TPMObjectData> tuple of a TPM handle and the object data, which contains the
         * public part and the creation data.
         */
        auto createPrimary(ESYS_TR primaryHandle, TPM2B_SENSITIVE_CREATE const& sensitive,
                           TPM2B_PUBLIC const& publicArea, TPM2B_DATA const& outsideInfo,
                           TPML_PCR_SELECTION const& creationPCR) const -> std::tuple<ESYS_TR, TPMObjectData>;

        /**
         * @brief Create a TPM object under a hierarchy of a TPM primary object. It represents a TPM key that is stored
         * inside the TPM.
         *
         * @param sessionHandle A TPM session
         * @param primaryHandle Handle to a TPM primary object, that is retrieved from createPrimary function.
         * @param sensitive The TPM2B_SENSITIVE_CREATE object that configures the primary object. See:
         * tpm::initializer::DEFAULT_SENSITIVE_CREATE_AK.
         * @param publicArea The TPM2B_PUBLIC object that configures the object. See: tpm::initializer::DEFAULT_AK,
         * tpm::initializer::DEFAULT_AK_RSAPSS, and tpm::initializer::DEFAULT_AK_ECC.
         * @param outsideInfo Information to attach to the primary object to provide linkage between the primary object
         * and the owning program. See: tpm::initializer::EMPTY_OUTSIDE_INFO.
         * @param creationPCR PCR that will be used in creation data. See: tpm::initializer::EMPTY_PCR_SELECTION)
         * @return std::tuple<ESYS_TR, TPMObjectData>
         * @return TPMPrivateObjectData Combination of TPMObjectData with the encrypted private part that is a wrapped
         * key of the private key.
         */
        auto createObject(EsysSession const& sessionHandle, ESYS_TR primaryHandle,
                          TPM2B_SENSITIVE_CREATE const& sensitive, TPM2B_PUBLIC const& publicArea,
                          TPM2B_DATA const& outsideInfo, TPML_PCR_SELECTION const& creationPCR) const
            -> TPMPrivateObjectData;

        /**
         * @brief Load a TPM object into the TPM
         *
         * @param sessionHandle A TPM session
         * @param parentHandle Handle to a TPM primary object, that id retrieved from createPrimary function.
         * @param object A TPM object that is previously created by createObject function
         * @return ESYS_TR
         */
        ESYS_TR loadObject(EsysSession const& sessionHandle, ESYS_TR parentHandle,
                           TPMPrivateObjectData const& object) const;

        /**
         * @brief Activate a TPM object and attest itself to be able to decrypt the credentialed object. If the TPM is
         * successfully decipher the credential, it means the TPM possess the correct key.
         *
         * @param parentHandle Primary key hierarchy
         * @param keyObject Handle to a loaded key object
         * @param credentialBin Credential data to be deciphered
         * @param secretBin Encrypted seed, encrypted with the public part of the TPM object
         * @return std::vector<uint8_t> Of the deciphered credential data, which can be compared by the caller
         */
        auto activateCredential(ESYS_TR parentHandle, ESYS_TR keyObject, std::span<uint8_t const> credentialBin,
                                std::span<uint8_t const> secretBin) const -> std::vector<uint8_t>;

        /**
         * @brief Get the signed time information from the TPM device.
         *
         * @param sessionHandle A TPM session
         * @param authSessionHandle An Auth session
         * @param signerHandle Handle to a TPM object that will be used to sign the time information
         * @param algScheme Signature scheme
         * @param qualifyingData Qualifying data to be attached to the signature, a.k.a. nonce
         * @return TPMGetTimeData Structure containing all data retrieved from TPM_GetTime function.
         */
        auto getTime(EsysSession const& sessionHandle, EsysSession const& authSessionHandle, ESYS_TR signerHandle,
                     TPMI_ALG_SIG_SCHEME algScheme, std::span<uint8_t const> qualifyingData) const -> TPMGetTimeData;

        ~EsysContext();
    };

    /**
     * @brief Namespace that encapsulates all default initializers to the TPM2-TSS API. It is possible for the user of
     * this wrapper library to modify some of the default value. However, it must conform with the TPM2 API
     * specification. Incorrect parameter will make the API refuse to work.
     *
     * Also, it may varies from TPM device to another. However this default value is tested in several TPM devices, from
     * normal TPM (Infineon), to Intel fTPM. But testing is always recommended to ensure it is working properly.
     */
    namespace initializer
    {
        // clang-format off
        constexpr TPM2B_PUBLIC DEFAULT_PUBLIC = {
            .publicArea = {
                .type             = TPM2_ALG_RSA,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                                    TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
                .parameters = {
                    .rsaDetail = {
                        .symmetric = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits   = {.aes = 128},
                        .mode      = {.aes = TPM2_ALG_CFB},
                        },
                        .scheme   = {.scheme = TPM2_ALG_NULL},
                        .keyBits  = 2048,
                        .exponent = 0},
                    }, 
                .unique = {
                    .rsa = {.size = 0}
                }
            }
        };

        constexpr TPM2B_PUBLIC DEFAULT_PUBLIC_ECC = {
            .publicArea = {
                .type             = TPM2_ALG_ECC,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                                    TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
                .parameters = {
                    .eccDetail = {
                        .curveID = TPM2_ECC_NIST_P256,
                    },
                },
            
                .unique = {
                    .ecc = { 
                        .x = { .size = 32, }, 
                        .y = { .size = 32, }, 
                    },
                }
                
            }
        };

        constexpr TPM2B_DIGEST DEFAULT_POLICY_A_SHA256 = {
            .size   = 32,
            .buffer = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA}
        };

        constexpr TPM2B_PUBLIC DEFAULT_EK_PUBLIC = {
            .publicArea = {
                .type             = TPM2_ALG_RSA,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY | TPMA_OBJECT_RESTRICTED |
                                    TPMA_OBJECT_DECRYPT, 
                .authPolicy = DEFAULT_POLICY_A_SHA256,
                .parameters = {
                    .rsaDetail = {
                        .symmetric = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits   = {.aes = 128},
                        .mode      = {.aes = TPM2_ALG_CFB},
                        },
                        .scheme   = {.scheme = TPM2_ALG_NULL},
                        .keyBits  = 2048,
                        .exponent = 0
                    },
                }, 
                .unique = {
                    .rsa = {
                        .size   = 256,
                        .buffer = {0, }
                    }
                }
            }
        };

        constexpr TPM2B_PUBLIC DEFAULT_EK_PUBLIC_ECC = {
            .publicArea = {
                .type             = TPM2_ALG_ECC,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY | TPMA_OBJECT_RESTRICTED |
                                    TPMA_OBJECT_DECRYPT, 
                .authPolicy = DEFAULT_POLICY_A_SHA256,
                .parameters = {
                    .eccDetail = {
                        .symmetric = {
                            .algorithm = TPM2_ALG_AES,
                            .keyBits   = {.aes = 128},
                            .mode      = {.aes = TPM2_ALG_CFB},
                        },
                        .scheme   = {
                            .scheme = TPM2_ALG_NULL, 
                            
                        },
                        .curveID = TPM2_ECC_NIST_P256,
                        .kdf = { .scheme = TPM2_ALG_NULL }
                    },
                }, 
                .unique = {
                    .ecc = {
                        .x = {
                            .size = 32,
                            .buffer = {0, } 
                        },
                        .y = {
                            .size = 32,
                            .buffer = {0, }
                        },
                    }
                }
            }
        };

        constexpr TPM2B_PUBLIC DEFAULT_SIGN = {
            .publicArea = {
                .type             = TPM2_ALG_RSA,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
                                    TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
                .parameters = {
                    .rsaDetail = {
                        .symmetric = {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits   = {.aes = TPM2_ALG_ERROR},
                        .mode      = {.aes = TPM2_ALG_ERROR},
                        },
                        .scheme   = {.scheme = TPM2_ALG_NULL},
                        .keyBits  = 2048,
                        .exponent = 0
                    },
                }, 
                .unique = {.rsa = {.size = 0}}}
        };

        constexpr TPM2B_PUBLIC DEFAULT_AK = {
            .publicArea = {
                .type             = TPM2_ALG_RSA,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_USERWITHAUTH |
                                    TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN, 
                .parameters = {
                    .rsaDetail = {
                        .symmetric = {
                            .algorithm = TPM2_ALG_NULL,
                            .keyBits   = {.aes = TPM2_ALG_ERROR},
                            .mode      = {.aes = TPM2_ALG_ERROR},
                        },
                        .scheme   = {
                            .scheme = TPM2_ALG_RSASSA, 
                            .details = {
                                .rsassa = { 
                                    .hashAlg = TPM2_ALG_SHA256
                                }
                            }
                        },
                        .keyBits  = 2048,
                        .exponent = 0},
                    }, 
                .unique = {.rsa = {.size = 0}}
            }
        };

        constexpr TPM2B_PUBLIC DEFAULT_AK_RSAPSS = {
            .publicArea = {
                .type             = TPM2_ALG_RSA,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_USERWITHAUTH |
                                    TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN, 
                .parameters = {
                    .rsaDetail = {
                        .symmetric = {
                            .algorithm = TPM2_ALG_NULL,
                            .keyBits   = {.aes = TPM2_ALG_ERROR},
                            .mode      = {.aes = TPM2_ALG_ERROR},
                        },
                        .scheme   = {
                            .scheme = TPM2_ALG_RSAPSS, 
                            .details = {
                                .rsapss = { 
                                    .hashAlg = TPM2_ALG_SHA256
                                }
                            }
                        },
                        .keyBits  = 2048,
                        .exponent = 0},
                    }, 
                .unique = {.rsa = {.size = 0}}
            }
        };

        constexpr TPM2B_PUBLIC DEFAULT_AK_ECC = {
            .publicArea = {
                .type             = TPM2_ALG_ECC,
                .nameAlg          = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_USERWITHAUTH |
                                    TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                    TPMA_OBJECT_SENSITIVEDATAORIGIN, 
                .parameters = {
                    .eccDetail = {
                        .symmetric = {
                            .algorithm = TPM2_ALG_NULL,
                            .keyBits   = {.aes = TPM2_ALG_ERROR},
                            .mode      = {.aes = TPM2_ALG_ERROR},
                        },
                        .scheme   = {
                            .scheme = TPM2_ALG_ECDSA, 
                            .details = {
                                .ecdsa = {
                                    .hashAlg = TPM2_ALG_SHA256
                                },
                            }
                        },
                        .curveID = TPM2_ECC_NIST_P256,
                        .kdf = { .scheme = TPM2_ALG_NULL }
                    }
                }, 
                .unique = {
                    .ecc = {
                        .x = {
                            .size = 0,
                            .buffer = {0, } 
                        },
                        .y = {
                            .size = 0,
                            .buffer = {0, }
                        },
                    }
                }
            }
        };

        constexpr TPM2B_SENSITIVE_CREATE DEFAULT_SENSITIVE_CREATE_AK = {
            .sensitive = {
                .userAuth = {.size = 6, .buffer = "akpass"}, 
                .data = {.size = 0,}
            }
        };

        constexpr TPM2B_SENSITIVE_CREATE DEFAULT_SENSITIVE_CREATE = {
            .sensitive = {
                .userAuth = {.size = 0,}, 
                .data = {.size = 0,}
            }
        };

        constexpr TPM2B_DATA EMPTY_OUTSIDE_INFO = {
            .size = 0,
        };

        constexpr TPML_PCR_SELECTION EMPTY_PCR_SELECTION = {
            .count = 0,
        };
        // clang-format on
    } // namespace initializer

} // namespace t3e::tpm

#endif