#ifndef LP_CRYPTO_H
#define LP_CRYPTO_H

// proxy header for openssl/crypto

#ifndef NO_OSSL_DEV
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#else
// BN
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
BN_CTX *BN_CTX_new(void);
//BN_CTX *BN_CTX_secure_new(void);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
BIGNUM *BN_new(void);
//BIGNUM *BN_secure_new(void);
void BN_clear(BIGNUM *a);
void BN_free(BIGNUM *a);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);
BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from);
int BN_set_word(BIGNUM *a, unsigned long w);
unsigned long BN_get_word(BIGNUM *a);

// EVP
typedef struct evp_md_st EVP_MD;
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen,
	int iter, const EVP_MD *digest, int keylen, unsigned char *out);

#include <stddef.h>
void *CRYPTO_malloc(size_t num, const char *file, int line);
void CRYPTO_free(void *str, const char *file, int line);
void OPENSSL_cleanse(void *ptr, size_t len);

#endif //NO_OSSL_DEV

#endif //LP_CRYPTO_H