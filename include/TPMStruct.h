#ifndef TPMSTRUCT_H
#define TPMSTRUCT_H

#include <tss2/tss2_tpm2_types.h>

/**
 * @brief Data structure that is both used in C++ and C part of the program. This type definition will appear on SGX EDL
 * declaration, which hence be compiled as a C code. Therefore, it is important that the data structure is declared in
 * C.
 *
 * It is to simplify the marshalling between untrusted and trusted part of the code, which ensure both side is binary
 * compatible and does not require its special serialization logic. The TPM2-TSS MU (Marshal-Unmarshal) library is made
 * available inside the enclave, allowing the enclave to operate the TPM2 data structure easily.
 */

typedef uint32_t ESYS_TR;

typedef struct TPMObjectData
{
    TPM2B_PUBLIC publicArea;
    TPM2B_DIGEST hash;
    TPM2B_CREATION_DATA data;
    TPMT_TK_CREATION ticket;
} TPMObjectData;

typedef struct TPMPrivateObjectData
{
    TPMObjectData objectData;
    TPM2B_PRIVATE privateArea;
} TPMPrivateObjectData;

typedef struct TPMGetTimeData
{
    TPM2B_ATTEST attestedTime;
    TPMT_SIGNATURE signature;
} TPMGetTimeData;

typedef struct TrustedTimeLog
{
    uint64_t tpmTime;
    uint64_t counterTime;
} TrustedTimeLog;

#endif