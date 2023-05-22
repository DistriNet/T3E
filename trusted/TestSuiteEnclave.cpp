#include <__sgx> // This is for Clang compiler
#include <sgx_trts.h>

#include "T3E.h"
#include "TestSuiteEnclave_t.h"

#include <OpenSSLHelper.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

#include <string>
#include <vector>

static uint64_t counter {0};
extern uint64_t localCounter;
bool trustedTimeEnabled              = false;
static constexpr size_t NONCE_LENGTH = 64;

/*
 * Some function related to the Timestamping Authority (TSA) is adopted from the OpenSSL implementation
 * (openssl/apps/ts.c). Most of the modification is to remove the modularity, and usage of BIO object and directly
 * using raw buffer. Some other complex functionality of the TSA is also omitted.
 *
 * Also, it is not using a proper C++ RAII as in the T3E-Enclave.cpp with its OpenSSL helper function as it is for
 * testing and demonstration purpose.
 *
 * Partially copyrighted by The OpenSSL Project Authors, licensed under Apache License 2.0
 */

void* app_malloc(size_t sz)
{
    void* vp;

    /*
     * This isn't ideal but it is what the app's app_malloc() does on failure.
     * Instead of exiting with a failure, abort() is called which makes sure
     * that there will be a good stack trace for debugging purposes.
     */
    if ((vp = OPENSSL_malloc(sz)) == nullptr)
    {
        abort();
    }
    return vp;
}

static int create_digest(uint8_t const* buffer, size_t length, const EVP_MD* md, unsigned char** md_value)
{
    int md_value_len;
    int rv             = 0;
    EVP_MD_CTX* md_ctx = NULL;

    md_value_len       = EVP_MD_size(md);
    if (md_value_len < 0)
        return 0;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        return 0;
    *md_value = reinterpret_cast<unsigned char*>(app_malloc(md_value_len));
    if (!EVP_DigestInit(md_ctx, md))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, buffer, length))
        goto err;

    if (!EVP_DigestFinal(md_ctx, *md_value, NULL))
        goto err;
    md_value_len = EVP_MD_size(md);

    rv           = md_value_len;
err:
    EVP_MD_CTX_free(md_ctx);
    return rv;
}

static ASN1_INTEGER* create_nonce(int bits)
{
    unsigned char buf[20];
    ASN1_INTEGER* nonce = NULL;
    int len             = (bits - 1) / 8 + 1;
    int i;

    if (len > (int) sizeof(buf))
        goto err;

#ifdef SGX
    if (sgx_read_rand(buf, len) != SGX_SUCCESS)
        goto err;
#else
    if (RAND_bytes(buf, len) <= 0)
        goto err;
#endif

    /* Find the first non-zero byte and creating ASN1_INTEGER object. */
    for (i = 0; i < len && !buf[i]; ++i)
        continue;
    if ((nonce = ASN1_INTEGER_new()) == NULL)
        goto err;
    OPENSSL_free(nonce->data);
    nonce->length = len - i;
    nonce->data   = reinterpret_cast<unsigned char*>(app_malloc(nonce->length + 1));

    memcpy(nonce->data, buf + i, nonce->length);
    return nonce;

err:
    // BIO_printf(bio_err, "could not create nonce\n");
    ASN1_INTEGER_free(nonce);
    return NULL;
}

static TS_REQ* create_query(uint8_t const* buffer, size_t length, const EVP_MD* md, const char* policy, int no_nonce,
                            int cert)
{
    int ret        = 0;
    TS_REQ* ts_req = NULL;
    int len;
    TS_MSG_IMPRINT* msg_imprint = NULL;
    X509_ALGOR* algo            = NULL;
    unsigned char* data         = NULL;
    ASN1_OBJECT* policy_obj     = NULL;
    ASN1_INTEGER* nonce_asn1    = NULL;

    if (md == NULL && (md = EVP_get_digestbyname("sha256")) == NULL)
        goto err;
    if ((ts_req = TS_REQ_new()) == NULL)
        goto err;
    if (!TS_REQ_set_version(ts_req, 1))
        goto err;
    if ((msg_imprint = TS_MSG_IMPRINT_new()) == NULL)
        goto err;
    if ((algo = X509_ALGOR_new()) == NULL)
        goto err;
    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(md))) == NULL)
        goto err;
    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
        goto err;
    algo->parameter->type = V_ASN1_NULL;
    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, algo))
        goto err;
    if ((len = create_digest(buffer, length, md, &data)) == 0)
        goto err;
    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, data, len))
        goto err;
    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint))
        goto err;
    /*
    if (policy && (policy_obj = txt2obj(policy)) == NULL)
        goto err;
    if (policy_obj && !TS_REQ_set_policy_id(ts_req, policy_obj))
        goto err;
    */

    /* Setting nonce if requested. */
    if (!no_nonce && (nonce_asn1 = create_nonce(NONCE_LENGTH)) == NULL)
        goto err;
    if (nonce_asn1 && !TS_REQ_set_nonce(ts_req, nonce_asn1))
        goto err;
    if (!TS_REQ_set_cert_req(ts_req, cert))
        goto err;

    ret = 1;
err:
    if (!ret)
    {
        TS_REQ_free(ts_req);
        ts_req = NULL;
        /*
        BIO_printf(bio_err, "could not create query\n");
        ERR_print_errors(bio_err);
        */
    }
    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    OPENSSL_free(data);
    ASN1_OBJECT_free(policy_obj);
    ASN1_INTEGER_free(nonce_asn1);
    return ts_req;
}

static ASN1_INTEGER* serial_cb(TS_RESP_CTX* ctx, void* data)
{
    int ret              = 0;
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!ASN1_INTEGER_set(serial, 1))
        goto err;

    ret = 1;
err:
    if (!ret)
    {
        ASN1_INTEGER_free(serial);
        serial = NULL;
    }
    return serial;
}

static TS_RESP* create_response(BIO* query_bio, EVP_PKEY* inkey, X509* signer, STACK_OF(X509) * chain)
{
    int ret                 = 0;
    TS_RESP* response       = NULL;
    TS_RESP_CTX* resp_ctx   = nullptr;
    ASN1_OBJECT* policy_obj = nullptr;

    if ((resp_ctx = TS_RESP_CTX_new()) == NULL)
        goto end;

    TS_RESP_CTX_set_serial_cb(resp_ctx, serial_cb, nullptr);

    // #ifndef OPENSSL_NO_ENGINE
    //     if (!TS_CONF_set_crypto_device(conf, section, engine))
    //         goto end;
    // #endif

    if (!TS_RESP_CTX_set_signer_cert(resp_ctx, signer))
        goto end;
    if (!TS_RESP_CTX_set_certs(resp_ctx, chain))
        goto end;
    if (!TS_RESP_CTX_set_signer_key(resp_ctx, inkey))
        goto end;

    if (!TS_RESP_CTX_set_signer_digest(resp_ctx, EVP_sha256()))
        goto end;

    /*
    if (!TS_RESP_CTX_set_ess_cert_id_digest(resp_ctx, essCertId))
        goto end;
    if (!TS_CONF_set_def_policy(conf, section, policy, resp_ctx))
        goto end;
    if (!TS_CONF_set_policies(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_digests(conf, section, resp_ctx))
        goto end;
    */
    policy_obj = OBJ_txt2obj("1.2.840.113550.11.1.2.2", 0);
    if (!TS_RESP_CTX_set_def_policy(resp_ctx, policy_obj))
        goto end;
    if (!TS_RESP_CTX_add_md(resp_ctx, EVP_sha256()))
        goto end;

    /*
    if (!TS_CONF_set_accuracy(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_clock_precision_digits(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_ordering(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_tsa_name(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_ess_cert_id_chain(conf, section, resp_ctx))
        goto end;
    */

    TS_RESP_CTX_set_clock_precision_digits(resp_ctx, 3);

    TS_RESP_CTX_set_time_cb(
        resp_ctx,
        [](struct TS_resp_ctx* ctx, void* data, long* sec, long* usec)
        {
            if (!trustedTimeEnabled)
            {
                t3e_Test_time_ocall(sec);
                *usec = 0;
                return 1;
            }
            else
            {
                auto [available, trustedTime, counterTime] = t3e::getTrustedTime();
                auto time                                  = trustedTime / 1000;
                *sec                                       = time;
                *usec                                      = (trustedTime % 1000) * 1000; // microsecond
                // sgxtt_TrustedTime_debugPrintTime(0, trustedTime); // Uncomment to print the time each time request
                return 1;
            }
            return 0;
        },
        nullptr);

    if ((response = TS_RESP_create_response(resp_ctx, query_bio)) == NULL)
        goto end;
    ret = 1;

end:
    if (!ret)
    {
        TS_RESP_free(response);
        response = NULL;
    }
    TS_RESP_CTX_free(resp_ctx);
    BIO_free_all(query_bio);
    ASN1_OBJECT_free(policy_obj);
    return response;
}

static void sign_timestamp(uint8_t const* buffer, size_t length, EVP_PKEY* inkey, X509* signer, STACK_OF(X509) * chain,
                           uint32_t seq = 0)
{
    auto query   = t3e::openssl::WrapOpenSSLObject(create_query(buffer, length, EVP_sha256(), nullptr, 0, 1));
    auto out_bio = t3e::openssl::WrapOpenSSLObject(BIO_new(BIO_s_mem()));

    if (!i2d_TS_REQ_bio(out_bio.get(), query.get()))
        return;

    auto resp = t3e::openssl::WrapOpenSSLObject(create_response(out_bio.release(), inkey, signer, chain));

    if (seq != 0)
    {
        auto out_bio_again = t3e::openssl::WrapOpenSSLObject(BIO_new(BIO_s_mem()));

        auto tstInfo       = TS_RESP_get_tst_info(resp.get());
        auto tsTime        = TS_TST_INFO_get_time(tstInfo);
        ASN1_GENERALIZEDTIME_print(out_bio_again.get(), tsTime);

        char* pp = nullptr;
        auto len = BIO_get_mem_data(out_bio_again.get(), &pp);
        t3e_Test_ReceiveTimestamp(seq, pp, len);
    }

    //     auto timestampout = t3e::openssl::WrapOpenSSLObject(BIO_new(BIO_s_mem()));
    //     TS_TST_INFO_print_bio(timestampout.get(), TS_RESP_get_tst_info(resp));

    //     std::vector<uint8_t> buf;
    //     buf.resize(1024 * 10);
    //     auto read = BIO_read(timestampout.get(), buf.data(), buf.size());
    //     buf.resize(read);

    // #ifndef SGX

    //     std::cout.write(reinterpret_cast<char const*>(buf.data()), buf.size());
    //     std::cout << std::endl;
    // #else
    //     t3e_Test_PrintOut(reinterpret_cast<char const*>(buf.data()), buf.size());
    // #endif
}

/*
 * This part below represents the signing key for demonstration purpose. In the actual settings, the signing key should
 * be installed through trusted channel (i.e., remote attestation) or using encrypted enclave feature from Intel SGX SDK
 */

char const PRIVATE_KEY[] = R"PEM(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUmezBbL9uIe24
wlWTBGsydA2otTS73QueHiRVObpstEFOP2LroMrj2uMMLs4uZmrx5snJURk3/LQO
+6FCSb5vJsMSRGehdGi5J3pyEIOHQoY1GgcgseFO3+XcUmxjq7H1YZlFdAca7m9b
67xL/OPfP8zJkPrPaRjxKFDIZveVN2jSpEYIsh7hKozGe79s5A7esF7aSpQYkXBN
bIGK2L1rqBok0DESSlEOUGwfHJDE93vXUqhFaxcRlH4hAWNJFnudbhNm2pU0vCbr
NSozw7HiaanuGMSTPQtOGJPX/hIPKL3dPgG0wZVPaGFsjLpVISx2qmVg0lEs2V9W
jzl5SmIRAgMBAAECggEACDUeSlAWgpPfnZsugq3ILeckLxn6RIGlyPuWyV3AekF5
9zFsIia3qHTfAK2WpvzMFoVDb2DAr4wzXxP0q3aFehzp6VzPz6BK6fF5yRklO8G8
JMUJxwfI+AKdqQwbTDyA0vVa7X8Lhm0Tql27G+eiHDB2SWaOATd4Z5h36Gmtt5Jd
SvRRirCz37a8Erqajx5+GaBZ5s1mzsuglI3J/gNHsl2win2QXi0L6zi6TRcRrrGF
ng2zCH+kqpt+22Gb9F7+/V3ha8FwTfSJFtq/ScYbFaFmEXraBTskh8XKdzPrcB80
TXeQCqtCPdqwhOXWHIAaEzDjuMwzpiIFgnfIEep/oQKBgQD7UjCu/Efqw0iB1d/a
UyQ8exdsYex8LVwuosWSOFn3x8vVapgDsoVEJt+StRJUXcUmwsbQf60JKfmQ8VGs
BuqCNPcNfW+Bkkm3plvuLH31JVtJfVICfQngfWvmFJDhsPG40UL3/4vnaWX1zo4R
fg6GR4Nz16eA5U3uS1vtUdvr4QKBgQDYjzGtBFvUPcuaAqiaK7kb4V3qocV8Ondm
D8XPX+zOfdIYqBJclvrtXvlZeuZvC0hVY4nRFkKWc5Nq0VlcId4guBClqPqOCGSH
tAPTFItieMWUnn55roVnHcTbPvOG8FJigPsoPeP5/VBZwxsPOpPiWi8UHx2thVGd
Ens9xBm8MQKBgH3R1gGk17RWc/RcSKeavCdzUHS4SZaZdu76GoNrps7/vbJonRYs
x78o3wEpmbWXBF61YKd9Y/mUhBbmWYcQJ1NshMrCI5Lw0+sXZCrHJ4AVZbBTBz2r
r8gtwlj7rtTuqvVl/mr+CuKdx6fZ8xIa09ax8sOKEZfcNLm6DJmxQ7LBAoGARpJb
gOOTvVWp/PVy1lL7Tt+hiG3ReotfD46CSvMaq6wLBGf5G91DxokVvxgy8er+Vn1K
ky2q43akisHQWhrbVVRGcIXhqNmJUUPTnzzps1xiHu2Lj8HUzWbBGSWpnMbCQkGA
F3wbyALJ5YaUUeEoAjKbdvYw6LQyhXpZWSaHsHECgYEAt+v/3DKjVUraaYPtuk8Z
X4Z8aSyG81okYsgZe/5BGzXS3PdAypNkdqSrYswwvFuGdYRyaxx4HOVatnxfqrd/
fEIWv6OzMly+8WgxSr9jkT3ld24EhkWK2KbSc3em/A2mvq8D7Dfgy4Mei2pviVzg
EvrFxT5+tFF11vSp/6mwDno=
-----END PRIVATE KEY-----
)PEM";

char const SIGNER_CERT[] = R"PEM(
-----BEGIN CERTIFICATE-----
MIID6DCCAtCgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVFQx
CzAJBgNVBAgMAlRUMQswCQYDVQQHDAJUVDEVMBMGA1UECgwMVHJ1c3RlZCBUaW1l
MR0wGwYDVQQLDBRUcnVzdGVkIFRpbWUgUm9vdCBDQTEdMBsGA1UEAwwUVHJ1c3Rl
ZCBUaW1lIFJvb3QgQ0EwHhcNMjIwODI1MTEwMjQ4WhcNMjIwOTI0MTEwMjQ4WjB+
MQswCQYDVQQGEwJUVDELMAkGA1UECAwCVFQxCzAJBgNVBAcMAlRUMRUwEwYDVQQK
DAxUcnVzdGVkIFRpbWUxHjAcBgNVBAsMFVRydXN0ZWQgVGltZSBUU0EgQ2VydDEe
MBwGA1UEAwwVVHJ1c3RlZCBUaW1lIFRTQSBDZXJ0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA1JnswWy/biHtuMJVkwRrMnQNqLU0u90Lnh4kVTm6bLRB
Tj9i66DK49rjDC7OLmZq8ebJyVEZN/y0DvuhQkm+bybDEkRnoXRouSd6chCDh0KG
NRoHILHhTt/l3FJsY6ux9WGZRXQHGu5vW+u8S/zj3z/MyZD6z2kY8ShQyGb3lTdo
0qRGCLIe4SqMxnu/bOQO3rBe2kqUGJFwTWyBiti9a6gaJNAxEkpRDlBsHxyQxPd7
11KoRWsXEZR+IQFjSRZ7nW4TZtqVNLwm6zUqM8Ox4mmp7hjEkz0LThiT1/4SDyi9
3T4BtMGVT2hhbIy6VSEsdqplYNJRLNlfVo85eUpiEQIDAQABo3IwcDAJBgNVHRME
AjAAMB0GA1UdDgQWBBRlovPdrIDsCQNAieQRs4JNme003DAfBgNVHSMEGDAWgBRy
PHruJ9za7EumAGVKCdlLfNNlFjALBgNVHQ8EBAMCBsAwFgYDVR0lAQH/BAwwCgYI
KwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAGEZaCtl9r2QgHKHlcUNyo/62cr1
E5rrtrQhsoH9sU4Zy3vI3f3UlAQGuVA1cdRLJpKSnPBUheDdMH/QPc3jTnPiL9xi
rxYR/A14XZqtB/wJF3wD2JFHmZzqX4akn6i2/4HL4f4riaS7fjZBUDzi6dcAqBkt
fekjCXuyh7gLKJy4kWZUBp25eX23MqxHx2qWPxyL6U3bI7Ft8/+zWtJfv0Cm5vem
4/Q1g3AATLuYkWOZmhPm2FZ6V7QJUZ8nUWjo9/fX7p98nry0di6GiYDIoYbJTbtt
rCyp0Zva6tZp6IGs016D2BUNRnPREDdGf+KCFKL0UqYFMMaJKmh+8tEIebk=
-----END CERTIFICATE-----
)PEM";

char const ROOT_CA[]     = R"PEM(
-----BEGIN CERTIFICATE-----
MIID2TCCAsGgAwIBAgIUOot1uH+mbnDQkKsbVaAGY+i3CXYwDQYJKoZIhvcNAQEL
BQAwfDELMAkGA1UEBhMCVFQxCzAJBgNVBAgMAlRUMQswCQYDVQQHDAJUVDEVMBMG
A1UECgwMVHJ1c3RlZCBUaW1lMR0wGwYDVQQLDBRUcnVzdGVkIFRpbWUgUm9vdCBD
QTEdMBsGA1UEAwwUVHJ1c3RlZCBUaW1lIFJvb3QgQ0EwHhcNMjIwODI1MTA0NDE5
WhcNMjMwODI1MTA0NDE5WjB8MQswCQYDVQQGEwJUVDELMAkGA1UECAwCVFQxCzAJ
BgNVBAcMAlRUMRUwEwYDVQQKDAxUcnVzdGVkIFRpbWUxHTAbBgNVBAsMFFRydXN0
ZWQgVGltZSBSb290IENBMR0wGwYDVQQDDBRUcnVzdGVkIFRpbWUgUm9vdCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJvmqwVlJNaco184hSxtXCs
WmyZT19zN9BFCyLjCHW0mRC2nYTpJRTPiXLKYPAcZ0ZYtF1ZaIj8AHFypFIo1BdV
AXsLtsCFRIpFuQnH2XnHdTOBHD4J7V9edr7Hmvha6tCv/ofgFNA7t1hKhZ/stzCF
Vlu6hKES8we5thZ733Tq29Ktis0h7rIIfwpQ4gOh9/oykXKQNOuqeJzM462Ep6zc
LrhSZYpP/7vyEAkmThRJLHN1lAZjHdhl8Dva8eh60wEqxnoM6dsSI0OeP1pV53KY
kPbP4cBG8yG7Uy175HQcvomW2JKCS7YZQz39yqvO7N/O7lyyViNg813GoxtCoCEC
AwEAAaNTMFEwHQYDVR0OBBYEFHI8eu4n3NrsS6YAZUoJ2Ut802UWMB8GA1UdIwQY
MBaAFHI8eu4n3NrsS6YAZUoJ2Ut802UWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAB2umd+Gx2hGe4UQr4m93g83ZvhSCTrAjIyYkh0frxeDkk6w
Uy57ivCQ/kGYURjGn/oewcrxHOta2VUWL48yROgW0pj57xl8fq9Vo2YncGgwY2If
hgoE+Cg5We4hBhxkASDhfL5iFJwOwBOXCuKGEgDhKJdCmhOkoYiWR/0VR0Cg78Yk
GlR6DF9Wl/rfOjTXuKxetE0stsf6AMsHvRkRl2omokPMBLSQ1xzqAtec6AyCaPsN
d4Oqq9jJif2SzpvY4vkhISBmN9xTbEvbGC3lCDnplJ/addcMJYiAYHnlQjQkm5mS
fW3OdBIlR+2Dz20WWIY3nuUUiGTeZzwujrYdSng=
-----END CERTIFICATE-----
)PEM";

auto prepareKeys()
{
    auto privkey_bio = t3e::openssl::WrapOpenSSLObject(BIO_new_mem_buf(PRIVATE_KEY, sizeof(PRIVATE_KEY)));
    auto privkey =
        t3e::openssl::WrapOpenSSLObject(PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, nullptr));

    auto cert_bio   = t3e::openssl::WrapOpenSSLObject(BIO_new_mem_buf(SIGNER_CERT, sizeof(SIGNER_CERT)));
    auto signercert = t3e::openssl::WrapOpenSSLObject(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));

    auto cacert_bio = t3e::openssl::WrapOpenSSLObject(BIO_new_mem_buf(ROOT_CA, sizeof(ROOT_CA)));
    auto cacert     = t3e::openssl::WrapOpenSSLObject(PEM_read_bio_X509(cacert_bio.get(), nullptr, nullptr, nullptr));

    return std::make_tuple(std::move(privkey), std::move(signercert), std::move(cacert));
}

inline uint64_t rdtscp()
{
    uint64_t rax, rdx;
    uint32_t aux;
    asm volatile("rdtscp\n" : "=a"(rax), "=d"(rdx), "=c"(aux) : :);
    return (rdx << 32) + rax;
}

extern "C"
{
    /**
     * @brief Replace the sgxssl_time function which is used by several other APIs, including SGX OpenSSL SDK
     *
     * @param timer out pointer storing the current time value
     * @return time_t the current time value
     */
    time_t __wrap_sgxssl_time(time_t* timer)
    {
        if (!trustedTimeEnabled)
        {
            if (timer != nullptr)
                *timer = 0;
            return 0; // This is not good for error reporting, though
        }
        else
        {
            auto [available, trustedTime, counterTime] = t3e::getTrustedTime();
            auto time                                  = trustedTime / 1000;
            if (timer != nullptr)
                *timer = time;

            return time;
        }
    }

    /**
     * @brief Simulate a long running operation which is basically just a loop
     */
    void t3e_Test_LongRunningOperations()
    {
        constexpr uint64_t loopCount = 10000000;

        for (int i = 0; i < loopCount; i++)
            counter++;
    }

    void t3e_Test_DelayedTest(TestEntry* res, size_t size)
    {
        for (int i = 0; i < size; i++)
        {
            auto [available, trustedTime, counterTime] = t3e::getTrustedTime();

            res[i].seq                                 = i;
            res[i].trustedTime                         = trustedTime;
            res[i].counterTime                         = localCounter;

            t3e_Test_LongRunningOperations();
        }
    }

    void t3e_Test_DelayedTestControl(TestEntry* res, size_t size)
    {
        for (int i = 0; i < size; i++)
        {
            res[i].seq         = i;
            res[i].trustedTime = 0;
            t3e_Test_rdtsc_ocall(&res[i].counterTime);

            t3e_Test_LongRunningOperations();
        }
    }

    void t3e_Test_Sign(const uint8_t* buf, size_t bufsize, TestEntry* res, size_t size)
    {
        // Try to measure possible overhead from ECALL transition process
        uint64_t first;
        t3e_Test_rdtsc_ocall(&first);
        uint64_t second;
        t3e_Test_rdtsc_ocall(&second);
        uint64_t ocallOverhead = second - first;

        std::string str {"Ocall Overhead: "};
        str.append(std::to_string(ocallOverhead));
        t3e_Test_PrintOut(str.data(), str.size());

        auto [privkey, cert, cacert] = prepareKeys();

        STACK_OF(X509) * chain;
        chain = sk_X509_new_null();
        sk_X509_push(chain, cacert.get());

        for (int i = 0; i < size; i++)
        {
            res[i].seq         = i;
            res[i].trustedTime = 0;
            t3e_Test_rdtsc_ocall(&res[i].counterTime);

            sign_timestamp(buf, bufsize, privkey.get(), cert.get(), chain);
        }

        sk_X509_free(chain);
    }

    void t3e_Test_rdtsc()
    {
        auto res     = __rdtsc();
        uint64_t pid = 0;
        asm volatile("rdpid %0\n" : "=r"(pid));

        std::string str {"Time now: "};
        str.append(std::to_string(res));
        str.append(", PID: ");
        str.append(std::to_string(pid));
        t3e_Test_PrintOut(str.data(), str.size());
    }

    void t3e_Test_rdtscp()
    {
        uint32_t dummy;
        auto res = rdtscp();

        std::string str {"Time now: "};
        str.append(std::to_string(res));
        t3e_Test_PrintOut(str.data(), str.size());
    }

    void t3e_Test_EnableTrustedTime()
    {
        trustedTimeEnabled = true;
    }

    void t3e_Test_SingleSign(uint32_t sequence, const uint8_t* buf, size_t bufsize)
    {
        static auto [privkey, cert, cacert] = prepareKeys();
        STACK_OF(X509) * chain;
        chain = sk_X509_new_null();
        sk_X509_push(chain, cacert.get());
        sign_timestamp(buf, bufsize, privkey.get(), cert.get(), chain, sequence);
        sk_X509_free(chain);
    }
}