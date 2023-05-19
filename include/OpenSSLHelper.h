#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/ts.h>
#include<memory>

namespace t3e::openssl
{
    template<typename T, void (*FuncFree)(T*)>
    struct FuncDeleter
    {
        void operator()(T* param) const { FuncFree(param); }
    };

    template<typename T, void (*FuncFree)(T*)>
    struct OpenSSLObjectFactoryWrapper
    {
        auto wrap(T* obj) const
        {
            return std::unique_ptr<T, FuncDeleter<T, FuncFree>>{ obj };
        }
    };

    template<typename T, auto FuncNew, void (*FuncFree)(T*)>
    struct OpenSSLObjectFactoryMapper : OpenSSLObjectFactoryWrapper<T, FuncFree>
    {
        template<typename... TArgs>
        auto instantiate(TArgs... args) const
        {
            return std::unique_ptr<T, FuncDeleter<T, FuncFree>>{ FuncNew(std::forward<TArgs>(args)...) };
        }
    };

    


    template<typename T> struct OpenSSLObjectFactory;
    template<> struct OpenSSLObjectFactory<BIGNUM> : OpenSSLObjectFactoryMapper<BIGNUM, BN_new, BN_free> { };
    template<> struct OpenSSLObjectFactory<EVP_PKEY> : OpenSSLObjectFactoryMapper<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free> { };
    template<> struct OpenSSLObjectFactory<RSA> : OpenSSLObjectFactoryMapper<RSA, RSA_new, RSA_free> { };
    template<> struct OpenSSLObjectFactory<EVP_MD_CTX> : OpenSSLObjectFactoryMapper<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free> { };
    template<> struct OpenSSLObjectFactory<HMAC_CTX> : OpenSSLObjectFactoryMapper<HMAC_CTX, HMAC_CTX_new, HMAC_CTX_free> { };
    template<> struct OpenSSLObjectFactory<EVP_CIPHER_CTX> : OpenSSLObjectFactoryMapper<EVP_CIPHER_CTX, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free> { };
    template<> struct OpenSSLObjectFactory<EC_GROUP> : OpenSSLObjectFactoryWrapper<EC_GROUP, EC_GROUP_free> { };
    template<> struct OpenSSLObjectFactory<EC_POINT> : OpenSSLObjectFactoryMapper<EC_POINT, EC_POINT_new, EC_POINT_free> { };
    template<> struct OpenSSLObjectFactory<EC_KEY> : OpenSSLObjectFactoryMapper<EC_KEY, EC_KEY_new, EC_KEY_free> { };
    template<> struct OpenSSLObjectFactory<EVP_PKEY_CTX> : OpenSSLObjectFactoryMapper<EVP_PKEY_CTX, EVP_PKEY_CTX_new, EVP_PKEY_CTX_free> { };
    template<> struct OpenSSLObjectFactory<BIO> : OpenSSLObjectFactoryWrapper<BIO, [] (auto bio) { BIO_free(bio); }> { };
    template<> struct OpenSSLObjectFactory<X509> : OpenSSLObjectFactoryWrapper<X509, X509_free> { };
    template<> struct OpenSSLObjectFactory<ECDSA_SIG> : OpenSSLObjectFactoryMapper<ECDSA_SIG, ECDSA_SIG_new, ECDSA_SIG_free> { };
    template<> struct OpenSSLObjectFactory<TS_RESP> : OpenSSLObjectFactoryMapper<TS_RESP, TS_RESP_new, TS_RESP_free> { };
    template<> struct OpenSSLObjectFactory<TS_REQ> : OpenSSLObjectFactoryMapper<TS_REQ, TS_REQ_new, TS_REQ_free> { };

    template<typename T, typename... TArgs>
    auto MakeOpenSSLObject(TArgs... args) { return OpenSSLObjectFactory<T>().instantiate(std::forward<TArgs>(args)...); }

    template<typename T> struct OpenSSLWrapperFactory;
    
    template<> struct OpenSSLWrapperFactory<EVP_PKEY> : OpenSSLObjectFactoryWrapper<EVP_PKEY, EVP_PKEY_free> { };

    template<typename T>
    auto WrapOpenSSLObject(T* o) { return OpenSSLObjectFactory<T>().wrap(o); }
}