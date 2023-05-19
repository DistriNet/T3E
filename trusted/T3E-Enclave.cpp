#include <__sgx> // This is for Clang compiler
#include <sgx_trts.h>

#include "T3E-Enclave_t.h"
#include "T3E.h"

#include "OpenSSLHelper.h"

#include <array>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <tss2/tss2_mu.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define ERROR_WRAPPER(x)                    \
    {                                       \
        int err = (x);                      \
        if (err != 1)                       \
            throw std::runtime_error((#x)); \
    }

auto createEVPPublicKey(std::span<uint8_t const> publicKey, uint32_t exponent)
{
    // Create RSA public key
    auto n = BN_bin2bn(publicKey.data(), publicKey.size(), nullptr);

    if (exponent == 0)
        exponent = 0x10001;

    auto e = t3e::openssl::MakeOpenSSLObject<BIGNUM>();
    BN_set_word(e.get(), exponent);

    auto rsa = t3e::openssl::MakeOpenSSLObject<RSA>();
    ERROR_WRAPPER(RSA_set0_key(rsa.get(), n, e.release(), nullptr));

    auto sslPkey = t3e::openssl::MakeOpenSSLObject<EVP_PKEY>();
    ERROR_WRAPPER(EVP_PKEY_assign_RSA(sslPkey.get(), rsa.release()));

    return std::move(sslPkey);
}

auto generateRandomData(size_t size)
{
    std::vector<uint8_t> ret;
    ret.resize(32);
    ERROR_WRAPPER(RAND_bytes(ret.data(), ret.size()));
    return ret;
}

/*
 * Some functions related to the TPM attestation and key derivation functions are adapted from the TPM2-Tools
 * source code (tpm2_kdfe.c) with substantial changes to use a little bit more typesafe and RAII C++ pattern. Also,
 * eliminating the modularities that is present on the TPM2-Tools original source code, and focus more on the specific
 * functionality that we need.
 *
 * Also eliminates many error handling case and just throw std::runtime_error directly which eventually will abort the
 * enclave, since many errors are OpenSSL error that is not supposed to happen in the first place. We can assume if such
 * error occurs, the enclave is corrupted and we don't need to recover.
 *
 * Original source/function:
 *      - tpm2_kdfe
 *      - get_ECDH_shared_secret
 *      - get_public_key_from_ec_key
 *      - ecdh_derive_seed_and_encrypted_seed
 *
 * Partially copyrighted by the Trusted Computing Group (TCG) and its authors, licensed under BSD 3-clause license
 */

/**
 * @brief Get the TPM structure representation for ECC points from EVP_PKEY OpenSSL object. Adapted from
 * tpm2_kdfe.c:get_public_key_from_ec_key
 *
 * @param pkey EVP_PKEY OpenSSL object
 * @return TPMS_ECC_POINT TPMS Struct ECC point from the EVP_PKEY object
 */
TPMS_ECC_POINT getPublicKeyFromECKey(EVP_PKEY* pkey)
{
    TPMS_ECC_POINT point;
    unsigned int nbx, nby;
    bool result            = false;

    EC_KEY* key            = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_POINT* pubkey = EC_KEY_get0_public_key(key);

    auto x                 = t3e::openssl::WrapOpenSSLObject(BN_new());
    auto y                 = t3e::openssl::WrapOpenSSLObject(BN_new());

    if ((x == NULL) || (y == NULL) || (pubkey == NULL))
        throw std::runtime_error("getPublicKeyFromECKey failed");

    EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key), pubkey, x.get(), y.get(), NULL);

    nbx = BN_num_bytes(x.get());
    nby = BN_num_bytes(y.get());

    if ((nbx > sizeof(point.x.buffer)) || (nby > sizeof(point.y.buffer)))
        throw std::runtime_error("getPublicKeyFromECKey failed");

    point.x.size = nbx;
    point.y.size = nby;
    BN_bn2bin(x.get(), point.x.buffer);
    BN_bn2bin(y.get(), point.y.buffer);

    return point;
}

/**
 * @brief Derive shared secret from our EC private key and their EC public key. Adapted from
 * tpm2_kdfe.c:get_ECDH_shared_secret
 *
 * @param pkey EVP_PKEY of our private key
 * @param p_pub EVP_PKEY of their public key (the TPM public key of the Endorsment Key)
 * @return std::vector<uint8_t> vector of bytes of the shared secret
 */
auto getECDHSharedSecret(EVP_PKEY* pkey, EVP_PKEY* p_pub)
{
    int result = -1;

    auto ctx   = t3e::openssl::MakeOpenSSLObject<EVP_PKEY_CTX>(pkey, nullptr);
    if (!ctx)
        throw std::runtime_error("");

    ERROR_WRAPPER(EVP_PKEY_derive_init(ctx.get()));
    ERROR_WRAPPER(EVP_PKEY_derive_set_peer(ctx.get(), p_pub));

    std::vector<uint8_t> sharedSecret;
    sharedSecret.resize(128);
    auto secretLen = sharedSecret.size();
    ERROR_WRAPPER(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &secretLen));
    sharedSecret.resize(secretLen);
    return sharedSecret;
}

/**
 * @brief Convert EC points into OpenSSL EVP_PKEY representation. Basically to convert TPM struct data into OpenSSL.
 *
 * @param xPoint the x point of the EC
 * @param yPoint the y point of the EC
 * @return std::unique_ptr<EVP_PKEY> EVP_PKEY of the EC keys wrapped in a smart pointer
 */
auto convertPubkeyECC(std::span<uint8_t const> xPoint, std::span<uint8_t const> yPoint)
{
    auto x     = t3e::openssl::WrapOpenSSLObject(BN_bin2bn(xPoint.data(), xPoint.size(), NULL));
    auto y     = t3e::openssl::WrapOpenSSLObject(BN_bin2bn(yPoint.data(), yPoint.size(), NULL));
    auto group = t3e::openssl::WrapOpenSSLObject(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (!x || !y || !group)
        throw std::runtime_error("");

    auto point = t3e::openssl::MakeOpenSSLObject<EC_POINT>(group.get());
    if (!point)
        throw std::runtime_error("");

    ERROR_WRAPPER(EC_POINT_set_affine_coordinates(group.get(), point.get(), x.get(), y.get(), NULL));

    /*
     * Create an empty EC key by the NID
     */
    auto ec_key = t3e::openssl::WrapOpenSSLObject(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!ec_key)
        throw std::runtime_error("convertPubkeyECC error");

    ERROR_WRAPPER(EC_KEY_set_public_key(ec_key.get(), point.get()));
    auto pkey = t3e::openssl::MakeOpenSSLObject<EVP_PKEY>();
    ERROR_WRAPPER(EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key.release()));

    return pkey;
}

/**
 * @brief TPM2 Key Derivation Function for ECDH (KDFe), following the specification. Adapted from tpm2_kdfe.c:tpm2_kdfe.
 *
 * @param Z Shared secret
 * @param label Some string label
 * @param partyU
 * @param partyV
 * @param size_in_bits
 * @return auto
 */
auto TPM2_KDFe(std::span<uint8_t const> Z, std::span<uint8_t const> label, std::span<uint8_t const> partyU,
               std::span<uint8_t const> partyV, uint16_t size_in_bits)
{
    int32_t bytes = ((size_in_bits + 7) / 8);
    int32_t done;
    uint32_t counter, counter_be;
    uint16_t hash_size = 32;
    TSS2_RC rval       = TPM2_RC_SUCCESS;

    std::vector<uint8_t> hashInput;
    hashInput.resize(4);
    std::copy(Z.begin(), Z.end(), std::back_inserter(hashInput));
    std::copy(label.begin(), label.end(), std::back_inserter(hashInput));
    std::copy(partyU.begin(), partyU.end(), std::back_inserter(hashInput));
    std::copy(partyV.begin(), partyV.end(), std::back_inserter(hashInput));

    /*
     * Hash[i] := H(hash_input), where otherInfo := Use | PartyUInfo|PartyVInfo
     * hash_input := counter | Z | OtherInfo
     */

    std::vector<uint8_t> resultKey;
    resultKey.resize(1024);

    for (done = 0, counter = 1; done < bytes; done += hash_size, counter++)
    {
        counter_be = __builtin_bswap32(counter);
        memcpy(hashInput.data(), &counter_be, 4);

        int rc = EVP_Digest(hashInput.data(), hashInput.size(), resultKey.data() + done, NULL, EVP_sha256(), NULL);
        if (!rc)
        {
            throw std::runtime_error("Invalid hashing");
        }
    }
    // truncate the result to the desired size
    resultKey.resize(bytes);

    return resultKey;
}

/**
 * @brief Create secret sharing material using ECDH algorithm for the attestation procedure. Adapted from:
 * tpm2_kdfe.c:ecdh_derive_seed_and_encrypted_seed
 *
 * @param xPoint TPM EC x point
 * @param yPoint TPM EC y point
 * @return std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> of the seed and encrypted seed for attestation
 * procedure
 */
auto secretSharingAlgECDH(std::span<uint8_t const> xPoint, std::span<uint8_t const> yPoint)
{
    // Get EVP for ECC
    auto ctx = t3e::openssl::WrapOpenSSLObject(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    // NID_X9_62_prime256v1

    // Generate a random new EC point
    ERROR_WRAPPER(EVP_PKEY_keygen_init(ctx.get()));
    ERROR_WRAPPER(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1));

    EVP_PKEY* pkeyPtr = NULL;
    ERROR_WRAPPER(EVP_PKEY_keygen(ctx.get(), &pkeyPtr));
    auto pkey          = t3e::openssl::WrapOpenSSLObject<EVP_PKEY>(pkeyPtr);

    TPMS_ECC_POINT qeu = getPublicKeyFromECKey(pkey.get());

    // marshal the public key to encrypted seed
    // Effectively the public key itself is the "encrypted seed" to be sent to the TPM
    std::vector<uint8_t> encryptedSeed;
    encryptedSeed.resize(sizeof(TPMS_ECC_POINT));
    size_t outlen = 0;
    TSS2_RC rval;
    ERROR_WRAPPER(!Tss2_MU_TPMS_ECC_POINT_Marshal(&qeu, encryptedSeed.data(), encryptedSeed.size(), &outlen));

    encryptedSeed.resize(outlen);

    auto pubkey       = convertPubkeyECC(xPoint, yPoint);
    auto eccSecret    = getECDHSharedSecret(pkey.get(), pubkey.get());

    char const* label = "IDENTITY\0";
    size_t len        = 9;

    auto seed = TPM2_KDFe(eccSecret, {reinterpret_cast<uint8_t const*>(label), len}, {qeu.x.buffer, qeu.x.size}, xPoint,
                          32 * 8);

    return std::make_pair(std::move(seed), std::move(encryptedSeed));
}

/**
 * @brief Create secret sharing material using RSA algorithm for the attestation procedure, following the TPM
 * specification
 *
 * @param publicKeyBin RSA public key of the TPM Endorsement Key
 * @param exponent RSA exponent of the TPM Endrosement Key
 * @return std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> of the seed and encrypted seed for attestation
 * procedure
 */
auto secretSharingAlgRSA(std::span<uint8_t const> publicKeyBin, uint32_t exponent)
{
    auto publicKey            = createEVPPublicKey(publicKeyBin, exponent);

    // Get random size for RSA secret sharing
    std::vector<uint8_t> seed = generateRandomData(32);

    // Generate seed value
    auto ctx = t3e::openssl::WrapOpenSSLObject<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(publicKey.get(), nullptr));

    ERROR_WRAPPER(EVP_PKEY_encrypt_init(ctx.get()));
    ERROR_WRAPPER(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING));
    ERROR_WRAPPER(EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()));

    char const* label = "IDENTITY\0";
    auto len          = strlen(label);
    auto newlabel     = static_cast<char*>(malloc(len));
    strncpy(newlabel, label, len);

    ERROR_WRAPPER(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.get(), newlabel, 9));

    std::vector<uint8_t> encryptedSeed;
    encryptedSeed.resize(1024);
    size_t outlen = encryptedSeed.size();
    ERROR_WRAPPER(EVP_PKEY_encrypt(ctx.get(), encryptedSeed.data(), &outlen, seed.data(), seed.size()));

    // shrink
    encryptedSeed.resize(outlen);
    return std::make_pair(std::move(seed), std::move(encryptedSeed));
}

/**
 * @brief Generates a key using TPM2 KDFa function. Roughly adapted from tpm2_kdfa.c:tpm2_kdfa, but more simplified.
 * Note that this is using OpenSSL 1.1.1 and may need to be changed if using OpenSSL 3.x as the HMAC_CTX class is
 * deprecated.
 *
 * @param proctectionSeed The seed generated from the secret sharing algorithm
 * @param bits Number of bits
 * @param labelStr A string label
 * @param keyName TPM key "name"
 * @return std::vector<uint8_t> of the derived key which then will be used for AES encryption
 */
auto TPM2KeyDerivationFunction(std::span<uint8_t const> proctectionSeed, uint16_t bits, std::string const& labelStr,
                               std::span<uint8_t const> keyName)
{
    auto hmacCtx = t3e::openssl::MakeOpenSSLObject<HMAC_CTX>();

    ERROR_WRAPPER(HMAC_Init_ex(hmacCtx.get(), proctectionSeed.data(), proctectionSeed.size(), EVP_sha256(), NULL));

    // The structure is in Big-Endian
    // Structure order:
    // 1. Size i = 1
    uint32_t i_be = __builtin_bswap32(1);
    HMAC_Update(hmacCtx.get(), reinterpret_cast<uint8_t*>(&i_be), sizeof(i_be));

    // 2. Label - It needs to be null-terminated.
    HMAC_Update(hmacCtx.get(), reinterpret_cast<uint8_t const*>(labelStr.c_str()), labelStr.size() + 1);

    // 3 context_u
    auto keyNameSize = keyName.size();
    HMAC_Update(hmacCtx.get(), keyName.data(), keyNameSize);

    // 4. context_v is null

    // 5. bits size
    uint32_t bits_be = __builtin_bswap32(bits);
    HMAC_Update(hmacCtx.get(), reinterpret_cast<uint8_t*>(&bits_be), sizeof(bits_be));

    std::vector<uint8_t> hmacResult;
    hmacResult.resize(128);
    uint32_t size = hmacResult.size();
    HMAC_Final(hmacCtx.get(), hmacResult.data(), &size);
    hmacResult.resize(bits / 8);

    return hmacResult;
}

auto aesEncrypt(std::span<uint8_t const> key, std::span<uint8_t const> data)
{
    auto cipher = EVP_aes_128_cfb();
    std::vector<uint8_t> iv;
    iv.resize(EVP_CIPHER_iv_length(cipher), 0);

    auto ctx = t3e::openssl::MakeOpenSSLObject<EVP_CIPHER_CTX>();

    ERROR_WRAPPER(EVP_EncryptInit_ex(ctx.get(), cipher, NULL, key.data(), iv.data()));
    ERROR_WRAPPER(EVP_CIPHER_CTX_set_padding(ctx.get(), 0));

    std::vector<uint8_t> cipherText;
    cipherText.resize(data.size(), 0);

    int len = cipherText.size();

    ERROR_WRAPPER(EVP_EncryptUpdate(ctx.get(), cipherText.data(), &len, data.data(), data.size_bytes()));
    ERROR_WRAPPER(EVP_EncryptFinal_ex(ctx.get(), NULL, &len));

    return cipherText;
}

auto hmacCredential(std::span<uint8_t const> key, std::span<uint8_t const> data, std::span<uint8_t const> keyName)
{
    std::vector<uint8_t> merged;
    merged.reserve(data.size() + keyName.size());
    std::copy(data.begin(), data.end(), std::back_inserter(merged));
    std::copy(keyName.begin(), keyName.end(), std::back_inserter(merged));

    std::vector<uint8_t> hmac;
    hmac.resize(32);
    uint32_t size = 0;
    HMAC(EVP_sha256(), key.data(), key.size(), merged.data(), merged.size(), hmac.data(), &size);

    return hmac;
}

/**
 * @brief Create a Credential object to be sent to the TPM to attest its authenticity. If the TPM is genuine and
 * authentic (i.e., possess the Endorsement Key private key of the public key its claimed), it should be able to decrypt
 * this object and present the randomly generated token to us.
 *
 * @tparam createSecretSharingFunc The secret sharing algorithm function, either RSA or ECDH
 * @tparam TParams Variadic template type parameters to be forwarded to the secret sharing algorithm function
 * @param name The key "name"
 * @param sharingFuncArgs Arguments to be forwarded to the secret sharing algorithm function
 *
 * @return std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>> Tuple of the random token for
 * validation, encrypted seed and credential to be passed to the TPM.
 */
template<auto createSecretSharingFunc, typename... TParams>
auto createCredential(std::span<const uint8_t> name, TParams... sharingFuncArgs)
    -> std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
{
    // Generate seed
    auto [seed, encryptedSeed]   = createSecretSharingFunc(sharingFuncArgs...);

    // Derive key from the seed
    auto protectionHmacKey       = TPM2KeyDerivationFunction(seed, 256, "INTEGRITY", {});
    auto protectionEncryptionKey = TPM2KeyDerivationFunction(seed, 128, "STORAGE", name);

    // Marshal credential
    auto token                   = generateRandomData(32);
    uint16_t credentialSize      = __builtin_bswap16(token.size());

    std::vector<uint8_t> marshaledCredential;
    marshaledCredential.reserve(token.size() + sizeof(credentialSize));

    std::copy(reinterpret_cast<uint8_t*>(&credentialSize),
              reinterpret_cast<uint8_t*>(&credentialSize) + sizeof(credentialSize),
              std::back_inserter(marshaledCredential));

    std::copy(token.begin(), token.end(), std::back_inserter(marshaledCredential));

    // Encrypt credential
    auto encryptedCredential = aesEncrypt(protectionEncryptionKey, marshaledCredential);

    // Calculate outer HMAC
    auto hmac                = hmacCredential(protectionHmacKey, encryptedCredential, name);

    // Marshal into object
    std::vector<uint8_t> compiledCredential;

    auto hmacSize_be = __builtin_bswap16(hmac.size());

    compiledCredential.reserve(sizeof(hmacSize_be) + hmac.size() + encryptedCredential.size());
    std::copy(reinterpret_cast<uint8_t*>(&hmacSize_be), reinterpret_cast<uint8_t*>(&hmacSize_be) + sizeof(hmacSize_be),
              std::back_inserter(compiledCredential));
    std::copy(hmac.begin(), hmac.end(), std::back_inserter(compiledCredential));
    std::copy(encryptedCredential.begin(), encryptedCredential.end(), std::back_inserter(compiledCredential));

    return std::make_tuple(std::vector<uint8_t> {token.begin(), token.end()}, std::move(encryptedSeed),
                           std::move(compiledCredential));
}

/**
 * @brief Get the TPM2 "name" of the TPMT_PUBLIC object, basically it is a SHA256 value of the public data.
 *
 * @param publicArea TPMT_PUBLIC object to get its "name"
 * @return std::vector<uint8_t> The binary "name"
 */
std::vector<uint8_t> getObjectName(TPMT_PUBLIC const& publicArea)
{
    std::vector<uint8_t> buffer;
    buffer.resize(sizeof(TPMT_PUBLIC));
    size_t offset = 0;
    Tss2_MU_TPMT_PUBLIC_Marshal(&publicArea, buffer.data(), buffer.size(), &offset);
    buffer.resize(offset);

    SHA256_CTX context;
    std::vector<uint8_t> ret;
    uint16_t alg = __builtin_bswap16(TPM2_ALG_SHA256);
    std::copy(reinterpret_cast<uint8_t*>(&alg), reinterpret_cast<uint8_t*>(&alg) + sizeof(uint16_t),
              std::back_inserter(ret));
    ret.resize(SHA256_DIGEST_LENGTH + sizeof(uint16_t));

    if (!(SHA256_Init(&context) && SHA256_Update(&context, buffer.data(), buffer.size()) &&
          SHA256_Final(ret.data() + sizeof(uint16_t), &context)))
        ret.resize(0);

    return ret;
}

/**
 * @brief Verify the signature of the GetTime payload using the public key of the TPM
 *
 * @param publicKey TPM public key used to sign the GetTime response
 * @param timeInfo The GetTime response object from the TPM
 * @param nonceData Nonce that is used in the process for freshness validation
 * @return true if it validates
 * @return false otherwise
 */
bool verifySignature(TPMObjectData const& publicKey, TPMGetTimeData const& timeInfo,
                     std::array<uint8_t, 32> const& nonceData)
{
    using namespace t3e::openssl;

    decltype(MakeOpenSSLObject<EVP_PKEY>()) evpPublicKey;
    std::unique_ptr<uint8_t, decltype([](uint8_t *ptr) { OPENSSL_free(ptr); })>
      sigBuffer;
    size_t sigLen = 0;

    if (publicKey.publicArea.publicArea.type == TPM2_ALG_RSA)
    {
        // Set public key elements
        auto n = MakeOpenSSLObject<BIGNUM>();
        BN_bin2bn(publicKey.publicArea.publicArea.unique.rsa.buffer, publicKey.publicArea.publicArea.unique.rsa.size,
                  n.get());
        auto e = MakeOpenSSLObject<BIGNUM>();
        BN_set_word(e.get(), 65537);

        auto rsaPublicKey = MakeOpenSSLObject<RSA>();
        RSA_set0_key(rsaPublicKey.get(), n.release(), e.release(), nullptr);

        evpPublicKey = MakeOpenSSLObject<EVP_PKEY>();
        EVP_PKEY_assign_RSA(evpPublicKey.get(), rsaPublicKey.release());
    }
    else if (publicKey.publicArea.publicArea.type == TPM2_ALG_ECC)
    {
        evpPublicKey = convertPubkeyECC(
            {publicKey.publicArea.publicArea.unique.ecc.x.buffer, publicKey.publicArea.publicArea.unique.ecc.x.size},
            {publicKey.publicArea.publicArea.unique.ecc.y.buffer, publicKey.publicArea.publicArea.unique.ecc.y.size});

        auto ecdsaSig = MakeOpenSSLObject<ECDSA_SIG>();
        ECDSA_SIG_set0(ecdsaSig.get(),
                       BN_bin2bn(timeInfo.signature.signature.ecdsa.signatureR.buffer,
                                 timeInfo.signature.signature.ecdsa.signatureR.size, NULL),
                       BN_bin2bn(timeInfo.signature.signature.ecdsa.signatureS.buffer,
                                 timeInfo.signature.signature.ecdsa.signatureS.size, NULL));

        uint8_t* signature = nullptr;
        sigLen             = i2d_ECDSA_SIG(ecdsaSig.get(), &signature);
        sigBuffer.reset(signature);
    }

    auto mdctx            = MakeOpenSSLObject<EVP_MD_CTX>();
    EVP_PKEY_CTX* pkeyCtx = nullptr;

    if (!EVP_DigestVerifyInit(mdctx.get(), &pkeyCtx, EVP_sha256(), NULL, evpPublicKey.get()))
        abort();

    if (publicKey.publicArea.publicArea.parameters.rsaDetail.scheme.scheme == TPM2_ALG_RSAPSS)
    {
        EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_AUTO);
    }

    EVP_DigestUpdate(mdctx.get(), timeInfo.attestedTime.attestationData, timeInfo.attestedTime.size);

    int res = -1;
    if (publicKey.publicArea.publicArea.type == TPM2_ALG_RSA)
        res = EVP_DigestVerifyFinal(mdctx.get(), timeInfo.signature.signature.rsassa.sig.buffer,
                                    timeInfo.signature.signature.rsassa.sig.size);
    else if (publicKey.publicArea.publicArea.type == TPM2_ALG_ECC)
        res = EVP_DigestVerifyFinal(mdctx.get(), sigBuffer.get(), sigLen);

    // Verification success
    if (res == 1)
    {
        TPMS_ATTEST timeData;
        size_t offset = 0;

        TSS2_RC rval  = Tss2_MU_TPMS_ATTEST_Unmarshal(timeInfo.attestedTime.attestationData, timeInfo.attestedTime.size,
                                                      &offset, &timeData);

        if (rval != TPM2_RC_SUCCESS)
            std::abort();

        // Check nonce
        if (std::equal(nonceData.begin(), nonceData.end(), timeData.extraData.buffer))
            return true;
    }

    return false;
}

// Global state
bool stopping                   = false;
uint64_t currentTPMTime         = 0;
uint64_t currentEpochTime       = 0;

uint64_t localCounter           = 0;
uint64_t counterTimeOnTPMUpdate = 0;

/**
 * @brief Helper function to simply extract the GetTime response data
 *
 * @param data TPMGetTimeData object (which is our internal combined objects)
 * @return TPMS_TIME_INFO the Time Info object that contains the time information
 */
TPMS_TIME_INFO extractAttestedTime(TPMGetTimeData const& data)
{
    size_t offset = 0;
    TPMS_ATTEST timeData;
    TSS2_RC rval =
        Tss2_MU_TPMS_ATTEST_Unmarshal(data.attestedTime.attestationData, data.attestedTime.size, &offset, &timeData);

    if (rval != TPM2_RC_SUCCESS)
        std::abort();

    return timeData.attested.time.time;
}

/**
 * @brief Create a credential from the TPM Attestation Key and Endorsement Key public key
 *
 * @param publicAreaAK Public part of the Attestation Key of the TPM that is derived from Endorsement Key
 * @param publicAreaEK Public part of the Endorsement Key of the TPM
 * @return std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>> Tuple of the random token for
 * validation, encrypted seed and credential to be passed to the TPM.
 */
auto createCredential(TPMT_PUBLIC const& publicAreaAK, TPMT_PUBLIC const& publicAreaEK)
{
    auto name = getObjectName(publicAreaAK);

    if (publicAreaEK.type == TPM2_ALG_RSA)
    {
        auto pubkeyBuf   = publicAreaEK.unique.rsa.buffer;
        size_t pubkeyLen = publicAreaEK.unique.rsa.size;

        // Build credential
        return createCredential<secretSharingAlgRSA>(name, std::span<uint8_t const> {pubkeyBuf, pubkeyLen},
                                                     publicAreaEK.parameters.rsaDetail.exponent);
    }
    else if (publicAreaEK.type == TPM2_ALG_ECC)
    {
        return createCredential<secretSharingAlgECDH>(
            name, std::span<uint8_t const> {publicAreaEK.unique.ecc.x.buffer, publicAreaEK.unique.ecc.x.size},
            std::span<uint8_t const> {publicAreaEK.unique.ecc.y.buffer, publicAreaEK.unique.ecc.y.size});
    }
    else
        abort();
}

// Intel SGX does not properly support thread_local since the C++ ABI is incomplete, but it supports __thread modifier.
__thread struct
{
    uint64_t threadCurrentTime;
    uint64_t useCount;
} threadContext;

/**
 * @brief The getTrustedTime API for T3E, that can be called from other threads. In this current implementation, the
 * call to this API will just indefinitely block if it cannot procure a trusted time or the use count is already beyond
 * its limit.
 *
 * @return std::tuple<bool, uint64_t, uint64_t> true indicating a time that can be trusted, uint64_t of the current
 * trusted time, uint64_t of the current counter (if the counter is enabled, otherwise 0)
 */
std::tuple<bool, uint64_t, uint64_t> t3e::getTrustedTime()
{
    while (threadContext.useCount > 14 || currentEpochTime == 0)
    {
        if (currentEpochTime != 0 && threadContext.threadCurrentTime != currentEpochTime)
        {
            threadContext.useCount = 0;
            break;
        }
    }

    if (threadContext.threadCurrentTime != currentEpochTime)
    {
        threadContext.threadCurrentTime = currentEpochTime;
        threadContext.useCount          = 0;
    }

    threadContext.useCount++;

    // std::string res = "Use: ";
    // res.append(std::to_string(threadContext.useCount));
    // t3e_Test_DebugPrint(res.c_str());

    return {true, threadContext.threadCurrentTime, counterTimeOnTPMUpdate};
}

extern "C"
{
    /**
     * @brief Main T3E trusted time thread. It runs indefinitely until it exits
     * 
     * @param tthandle The TPM handle in the untrusted domain to communicate with the TPM device
     * @param endorsementKey Endorsement key of the TPM
     * @param attestationKey Attestation key of the TPM
     */
    void t3e_TrustedTime_start(intptr_t tthandle, TPMObjectData const* endorsementKey,
                               TPMPrivateObjectData const* attestationKey)
    {
        // Create the credential
        auto [token, seed, credential] =
            createCredential(attestationKey->objectData.publicArea.publicArea, endorsementKey->publicArea.publicArea);

        std::vector<uint8_t> tokenProof(token.size(), static_cast<uint8_t>(0));

        // OCALL to perform the attestation to the TPM, and activates the credential
        auto res = t3e_TrustedTime_activateCredential(tthandle, attestationKey, credential.data(), credential.size(),
                                                      seed.data(), seed.size(), tokenProof.data(), tokenProof.size());

        // Check credential
        if (std::equal(token.begin(), token.end(), tokenProof.begin(), tokenProof.end()))
        {
            // Start TPM Time
            TPMGetTimeData attestedTime {
                0,
            };

            std::array<uint8_t, 32> nonceData;
            sgx_read_rand(nonceData.data(), nonceData.size());

            // OCALL to perform the TPM2_GetTime operation to the TPM
            res = t3e_TrustedTime_getTime(&attestedTime, tthandle, nonceData.data(), nonceData.size());

            // Time log for testing
            std::vector<TrustedTimeLog> trustedTimeLog;
            trustedTimeLog.reserve(1000);

            if (verifySignature(attestationKey->objectData, attestedTime, nonceData))
            {
                auto timeData          = extractAttestedTime(attestedTime);
                currentTPMTime         = timeData.clockInfo.clock;
                counterTimeOnTPMUpdate = localCounter;
                t3e_TrustedTime_getSystemTime(&currentEpochTime);

                while (!stopping)
                {
                    std::array<uint8_t, 32> nonceData;
                    sgx_read_rand(nonceData.data(), nonceData.size());
                    res = t3e_TrustedTime_getTime(&attestedTime, tthandle, nonceData.data(), nonceData.size());
                    if (verifySignature(attestationKey->objectData, attestedTime, nonceData))
                    {
                        timeData       = extractAttestedTime(attestedTime);
                        auto diff      = timeData.clockInfo.clock - currentTPMTime;
                        currentTPMTime = timeData.clockInfo.clock;
                        currentEpochTime += diff;
                        counterTimeOnTPMUpdate = localCounter;

                        trustedTimeLog.emplace_back(TrustedTimeLog {currentTPMTime, counterTimeOnTPMUpdate});
                        // t3e_TrustedTime_debugPrintTime(currentTPMTime, currentEpochTime);
                    }
                    else
                    {
                        break;
                    }
                }

                // Write trusted time log externally
                // t3e_TrustedTime_debugTimeLog(trustedTimeLog.data(), trustedTimeLog.size());
            }
        }
    }

    /**
     * @brief ECALL handle if we want to inspect the trusted time in the enclave from untrusted domain
     *
     * @param timeOut The trusted time value
     * @param counterTime Counter time (if available)
     * @return uint8_t 1 success, 0 otherwise
     */
    uint8_t t3e_TrustedTime_getTrustedTime(uint64_t* timeOut, uint64_t* counterTime)
    {
        auto [available, time, counter] = t3e::getTrustedTime();
        if (!available)
            return 0;
        else
        {
            *timeOut     = time;
            *counterTime = counter;
            return 1;
        }
    }

    /**
     * @brief Signal the trusted time thread to stop and exit
     *
     */
    void t3e_TrustedTime_stop()
    {
        stopping = true;
    }

    /**
     * @brief Extra thread if it is enable, to perform software counter. Currently only for debugging purposes. (Think
     * about S-FaaS implementation that is almost similar to use software counter, but without Intel TSX)
     *
     */
    void t3e_TrustedTime_counterThread()
    {
        while (!stopping)
            localCounter++;
    }
}