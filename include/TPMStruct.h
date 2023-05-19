#ifndef TPMSTRUCT_H
#define TPMSTRUCT_H

#include <tss2/tss2_tpm2_types.h>

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