#include "lp_crypto.h"
#include "lp.h"

typedef const EVP_MD* (*evpmd_f)(void);
#define DIGEST_ID(A) LP_MD_##A

#define DIGEST_LIST \
	X(md5), X(sha1), X(sha224), \
	X(sha256), X(sha384), X(sha512) \

#define X(A) DIGEST_ID(A)
enum { DIGEST_LIST };
#undef X

#define X(A) EVP_##A
static const evpmd_f mdlist[] = { DIGEST_LIST };
#undef X

#undef DIGEST_LIST
//static const unsigned mdlistsize = sizeof(mdlist)/sizeof(mdlist[0]);

typedef enum
{
	LP_VER_DEF    = 2,
	LP_KEYLEN_DEF = 32,
	LP_ITERS_DEF  = 100000,
	LP_DIGEST_DEF = DIGEST_ID(sha256)
} lp_defaults;

// Start Autogen Charsets (indexed by flag)
typedef struct charset_s
{
	const char *value;
	unsigned char length; // set length
	unsigned char numsets; // number of sets used
	unsigned char lensets[4]; // lengths of sets used
} charset_t;

static const charset_t cslist[] = 
{
	{"", 0, 0, {0, 0, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyz", 26, 1, {26, 0, 0, 0}},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26, 1, {26, 0, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 52, 2, {26, 26, 0, 0}},
	{"0123456789", 10, 1, {10, 0, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyz0123456789", 36, 2, {26, 10, 0, 0}},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 36, 2, {26, 10, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 62, 3, {26, 26, 10, 0}},
	{"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 32, 1, {32, 0, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 58, 2, {26, 32, 0, 0}},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 58, 2, {26, 32, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 84, 3, {26, 26, 32, 0}},
	{"0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 42, 2, {10, 32, 0, 0}},
	{"abcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 68, 3, {26, 10, 32, 0}},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 68, 3, {26, 10, 32, 0}},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 94, 4, {26, 26, 10, 32}}
};

//static const unsigned cslistsize = sizeof(cslist)/sizeof(cslist[0]); // = 16
#define CSLISTFLAG 15
// End Autogen Charsets

#if LP_CSF_ALL != CSLISTFLAG
#error Something
#endif

struct lp_ctx_st
{
	unsigned version;
	unsigned keylen;
	unsigned iterations;
	unsigned digest;

	unsigned counter;
	unsigned length;
	unsigned charsets;
	
	BN_CTX *bnctx;
	BIGNUM *entropy;
	BIGNUM *dv, *d, *rem;
};

static unsigned long longdivEntropy(BIGNUM *dv, BIGNUM *rem, BIGNUM *ent, const BIGNUM *d, BN_CTX *bnctx)
{
	BN_div(dv, rem, ent, d, bnctx);
	BN_copy(ent, dv);
	return BN_get_word(rem);
}

static void consumeEntropy(LP_CTX *ctx, char *dst, unsigned dstlen, const char *set, unsigned setlen)
{
	BN_set_word(ctx->d, setlen);
	unsigned i = 0;
	for(i = 0; i < dstlen; i++)
	{
		dst[i] = set[longdivEntropy(ctx->dv, ctx->rem, ctx->entropy, ctx->d, ctx->bnctx)];
	}
}

static char consumeEntropyChar(LP_CTX *ctx, const char *set, int setlen)
{
	BN_set_word(ctx->d, setlen);
	return set[longdivEntropy(ctx->dv, ctx->rem, ctx->entropy, ctx->d, ctx->bnctx)];
}

static unsigned consumeEntropyInt(LP_CTX *ctx, int setlen)
{
	BN_set_word(ctx->d, setlen);
	return longdivEntropy(ctx->dv, ctx->rem, ctx->entropy, ctx->d, ctx->bnctx);
}

static unsigned mystrnlen(const char *s, unsigned max)
{
	if(!s || !*s)
		return 0;
	unsigned i;
	for(i = 0; (i < max) && s[i]; i++);
	return i;
}

/*
static unsigned mystrlen(const char *s)
{
	return mystrnlen(s, LPMAXSTRLEN);
}
*/

static unsigned myhexlen(unsigned u)
{
	if(u == 0)
		return 1;
	unsigned d;
	for(d = 0; u; d++)
		u >>= 4;
	return d;
}

static void mysprinthex(char *dst, unsigned dlen, unsigned u)
{
	static const char hexchars[] = "0123456789abcdef";

	unsigned d;
	for(d = dlen; d > 0; d--)
	{
		dst[d - 1] = hexchars[u & 0xF];
		u >>= 4;
	}
}

static void mymemcpy(char *dst, const char *src, unsigned count)
{
	for(; count > 0; count--)
	{
		dst[count - 1] = src[count - 1];
	}
}

static void mypushchar(char *dst, unsigned len, unsigned pos, char c)
{
	/* Alt. method
	for(i = len - 1; i > pos; i--)
	{
		dst[i] = dst[i - 1];
	}
	*/
	mymemcpy(dst + pos + 1, dst + pos, len - pos - 1);
	dst[pos] = c;
}

/*
Using OPENSSL_cleanse instead (which uses a volatile ptr to memset so supposedly not optimized by the compiler)
static void mymemzero(void *dst, size_t len)
{
	if(dst == NULL)
		return;
	volatile unsigned char *p = dst;
	while (len--)
	{
	*p++ = 0;
	}
}
*/

// (const) string
typedef struct lp_str_s
{
	const char *value;
	unsigned length;
} LP_STR;

// variable string
typedef struct lp_vstr_s
{
	char *value;
	unsigned length;
} LP_VSTR;

static int generatePassword(LP_CTX *ctx, const LP_STR *site,  const LP_STR *login, const LP_STR *secret, LP_VSTR *pass)
{
	if(pass->length == 0)
		return 0;
	
	unsigned len = myhexlen(ctx->counter);
	unsigned saltlen = site->length + login->length + len;
	char buffer[saltlen > ctx->length ? saltlen : ctx->length];
	
	// Create salt string in buffer: site|login|hex(counter)
	char *p = buffer;
	mymemcpy(p, site->value, site->length);
	p += site->length;
	mymemcpy(p, login->value, login->length);
	p += login->length;
	mysprinthex(p, len, ctx->counter);
	
	// Create entropy number from PBKDF2
	unsigned char keybuf[ctx->keylen];
	PKCS5_PBKDF2_HMAC(secret->value, secret->length, (unsigned char *)buffer, saltlen, ctx->iterations, mdlist[ctx->digest](), sizeof keybuf, keybuf);
	BN_bin2bn(keybuf, sizeof keybuf, ctx->entropy);
	OPENSSL_cleanse(keybuf, sizeof keybuf);
	
	// Select len (= length - numsets) characters from the merged charset
	const charset_t *charset = &cslist[ctx->charsets & LP_CSF_ALL];
	len = ctx->length - charset->numsets;
	consumeEntropy(ctx, buffer, len, charset->value, charset->length);
	
	// Select numsets characters (one from each subset of charset)
	unsigned i;
	unsigned offset = 0;
	for(i = 0; i < charset->numsets; i++)
	{
		buffer[len + i] = consumeEntropyChar(ctx, charset->value + offset, charset->lensets[i]);
		offset += charset->lensets[i];
	}

	// Combine last numsets characters into the first len characters
	for(; len < ctx->length; len++)
	{
		mypushchar(buffer, len + 1, consumeEntropyInt(ctx, len), buffer[len]);
	}

	mymemcpy(pass->value, buffer, pass->length > len ? len : pass->length);
	OPENSSL_cleanse(buffer, sizeof buffer);
	return len;
}

LP_CTX* LP_CTX_new(void)
{
	LP_CTX *ctx = CRYPTO_malloc(sizeof(LP_CTX), __FILE__, __LINE__);
	ctx->version = LP_VER_DEF;
	ctx->keylen = LP_KEYLEN_DEF;
	ctx->iterations = LP_ITERS_DEF;
	ctx->digest = LP_DIGEST_DEF;

	ctx->counter = LP_COUNTER_DEF;
	ctx->length = LP_LENGTH_DEF;
	ctx->charsets = LP_CSF_DEF;
	
	ctx->bnctx = BN_CTX_new();
	ctx->entropy = BN_new();
	ctx->dv = BN_new();
	ctx->d = BN_new();
	ctx->rem = BN_new();
	return ctx;
}

void LP_CTX_free(LP_CTX *ctx)
{
	BN_clear_free(ctx->entropy);
	BN_clear_free(ctx->dv);
	BN_clear_free(ctx->d);
	BN_clear_free(ctx->rem);
	BN_CTX_free(ctx->bnctx);
	OPENSSL_cleanse(ctx, sizeof *ctx);
	CRYPTO_free(ctx, __FILE__, __LINE__);
}

unsigned LP_set_counter(LP_CTX *ctx, unsigned counter)
{
	if(counter >= LP_COUNTER_MIN && counter <= LP_COUNTER_MAX)
	{
		ctx->counter = counter;
	}
	return ctx->counter;
}

unsigned LP_set_length(LP_CTX *ctx, unsigned length)
{
	if(length >= LP_LENGTH_MIN && length <= LP_LENGTH_MAX)
	{
		ctx->length = length;
	}
	return ctx->length;
}

unsigned LP_set_charsets(LP_CTX *ctx, unsigned charsets)
{
	if(charsets & LP_CSF_ALL)
	{
		ctx->charsets = charsets & LP_CSF_ALL;
	}
	return ctx->charsets;
}


int LP_get_pass(LP_CTX *ctx, const char* site,  const char* login, const char* secret, char* pass, unsigned passlen)
{
	if(site == NULL)
		return LP_ERR_NULL_SITE;
	if(login == NULL)
		return LP_ERR_NULL_LOGIN;
	if(secret == NULL)
		return LP_ERR_NULL_SECRET;
	if(pass == NULL)
		return LP_ERR_NULL_PASS;
	
	if(ctx == NULL)
		return LP_ERR_INIT;
	if(ctx->version != LP_VER_DEF)
		return LP_ERR_VERSION;
	if(ctx->keylen != LP_KEYLEN_DEF)
		return LP_ERR_KEYLEN;
	if(ctx->iterations != LP_ITERS_DEF)
		return LP_ERR_ITER;
	if(ctx->digest != LP_DIGEST_DEF)
		return LP_ERR_DIGEST;
	//if(ctx->digest >= mdlistsize)
	//{
	//	return LP_ERR_DIGEST;
	//}
	
	if(ctx->length > LP_LENGTH_MAX || ctx->length < LP_LENGTH_MIN)
		return LP_ERR_LENGTH;
	if(ctx->counter > LP_COUNTER_MAX || ctx->counter < LP_COUNTER_MIN)
		return LP_ERR_COUNTER;
	if((ctx->charsets & LP_CSF_ALL) == 0)
		return LP_ERR_FLAGS;

	unsigned len;
	len = mystrnlen(site, LPMAXSTRLEN);
	if(len >= LPMAXSTRLEN)
		return LP_ERR_LONG_SITE;
	LP_STR site_str = {.value = site, .length = len};
	
	len = mystrnlen(login, LPMAXSTRLEN);
	if(len >= LPMAXSTRLEN)
		return LP_ERR_LONG_LOGIN;
	LP_STR login_str = {.value = login, .length = len};
	
	len = mystrnlen(secret, LPMAXSTRLEN);
	if(len >= LPMAXSTRLEN)
		return LP_ERR_LONG_SECRET;
	LP_STR secret_str = {.value = secret, .length = len};
	
	LP_VSTR pass_str = {.value = pass, .length = passlen};
	
	return generatePassword(ctx, &site_str, &login_str, &secret_str, &pass_str);
}
