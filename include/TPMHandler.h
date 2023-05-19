#pragma once
#ifndef TRUSTEDTIME_TPM_H
#define TRUSTEDTIME_TPM_H

#include <TPMStruct.h>
#include <span>
#include <string>
#include <tss2/tss2_esys.h>
#include <tuple>
#include <vector>

typedef struct ESYS_CONTEXT ESYS_CONTEXT;

namespace t3e::tpm
{
    class EsysContext;

    class EsysSession
    {
    private:
        ESYS_TR sessionHandle {ESYS_TR_NONE};
        EsysContext const& ctx;

    public:
        EsysSession(EsysContext const& ctx, TPM2_SE sessionType);

        operator ESYS_TR() const
        {
            return this->sessionHandle;
        }

        void setPasswordPolicySecret(ESYS_TR shandle = ESYS_TR_PASSWORD);
        void setAuthValue(std::string_view pass);
        ~EsysSession();
    };

    class EsysContext
    {
    private:
        ESYS_CONTEXT* ectx {nullptr};
        static TSS2_ABI_VERSION currentABI;

    public:
        EsysContext();
        EsysContext(EsysContext const&) = delete;
        EsysContext& operator=(EsysContext const&) = delete;

        EsysContext(EsysContext&& that): ectx(that.ectx)
        {
            that.ectx = nullptr;
        }

        EsysContext& operator=(EsysContext&& that);

        operator ESYS_CONTEXT*() const
        {
            return this->ectx;
        }

        TSS2_SYS_CONTEXT* getSysContext() const;

        bool setTimeout(int32_t timeout);

        auto createPrimary(ESYS_TR primaryHandle, TPM2B_SENSITIVE_CREATE const& sensitive,
                           TPM2B_PUBLIC const& publicArea, TPM2B_DATA const& outsideInfo,
                           TPML_PCR_SELECTION const& creationPCR) const -> std::tuple<ESYS_TR, TPMObjectData>;

        auto createObject(EsysSession const& sessionHandle, ESYS_TR primaryHandle,
                          TPM2B_SENSITIVE_CREATE const& sensitive, TPM2B_PUBLIC const& publicArea,
                          TPM2B_DATA const& outsideInfo, TPML_PCR_SELECTION const& creationPCR) const
            -> TPMPrivateObjectData;

        ESYS_TR loadObject(EsysSession const& sessionHandle, ESYS_TR parentHandle,
                           TPMPrivateObjectData const& object) const;

        auto activateCredential(ESYS_TR parentHandle, ESYS_TR keyObject, std::span<uint8_t const> credentialBin,
                                std::span<uint8_t const> secretBin) const -> std::vector<uint8_t>;

        auto getTime(EsysSession const& sessionHandle, EsysSession const& authSessionHandle, ESYS_TR signerHandle, TPMI_ALG_SIG_SCHEME algScheme, std::span<uint8_t const> qualifyingData) const -> TPMGetTimeData;

        ~EsysContext();
    };

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