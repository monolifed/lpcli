#include "lp_crypto.h"

#include "lp.h"

typedef enum
{
	LP_MD_MD5    = 0,
	LP_MD_SHA1   = 1,
	LP_MD_SHA224 = 2,
	LP_MD_SHA256 = 3, // only valid value for v2
	LP_MD_SHA384 = 4,
	LP_MD_SHA512 = 5,

} lp_digest;


typedef enum
{
	LP_VER_DEF    = 2,
	LP_KEYLEN_DEF = 32,
	LP_ITERS_DEF  = 100000,
	LP_DIGEST_DEF = LP_MD_SHA256
} lp_defaults;

typedef const EVP_MD* (*evpmd_f)(void);

typedef struct evpmd_s
{
	int id;
	evpmd_f md;
} evpmd_t;

static const evpmd_t mdlist[] =
{
	{LP_MD_MD5   , EVP_md5   },
	{LP_MD_SHA1  , EVP_sha1  },
	{LP_MD_SHA224, EVP_sha224},
	{LP_MD_SHA256, EVP_sha256},
	{LP_MD_SHA384, EVP_sha384},
	{LP_MD_SHA512, EVP_sha512},
};
static const unsigned mdlistsize = sizeof(mdlist)/sizeof(mdlist[0]);

// Start Autogen Charsets
typedef struct charset_s
{
	const char *set;
	unsigned setlen; // set length
	unsigned numsets; // number of sets used
} charset_t;

static const charset_t cslist[] = 
{
	{"", 0, 0},
	{"abcdefghijklmnopqrstuvwxyz", 26, 1},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26, 1},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 52, 2},
	{"0123456789", 10, 1},
	{"abcdefghijklmnopqrstuvwxyz0123456789", 36, 2},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 36, 2},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 62, 3},
	{"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 32, 1},
	{"abcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 58, 2},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 58, 2},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 84, 3},
	{"0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 42, 2},
	{"abcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 68, 3},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 68, 3},
	{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 94, 4},
};

static const unsigned cslistsize = sizeof(cslist)/sizeof(cslist[0]); // = 16
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
	int digest;

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

static void consumeEntropy(LP_CTX *ctx, char *pass, int passlen, const char *set, int setlen)
{
	BN_set_word(ctx->d, setlen);
	int i = 0;
	for(i = 0; i < passlen; i++)
	{
		pass[i] = set[longdivEntropy(ctx->dv, ctx->rem, ctx->entropy, ctx->d, ctx->bnctx)];
	}
}

static int consumeEntropyInt(LP_CTX *ctx, int setlen)
{
	BN_set_word(ctx->d, setlen);
	return longdivEntropy(ctx->dv, ctx->rem, ctx->entropy, ctx->d, ctx->bnctx);
}

static unsigned mystrnlen(const char *s)
{
	if(!s || !*s)
		return 0;
	unsigned i;
	for(i = 0; (i < LPMAXSTRLEN) && s[i]; i++);
	return i;
}

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
	for(i = len; i > pos; count--)
	{
		dst[i] = dst[i - 1];
	}
	*/
	mymemcpy(dst + pos + 1, dst + pos, len - pos);
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

static int LP_generate(LP_CTX *ctx, const char* site,  const char* login, const char* secret, char* pass, unsigned passlen)
{
	if((ctx->charsets & LP_CSF_ALL) == 0 || ctx->length == 0 || passlen == 0)
		return 0;
	
	if(mystrnlen(site) + mystrnlen(login) + myhexlen(ctx->counter) > LPMAXSTRLEN)
		return LP_ERR_SALTLEN;
	
	if(mystrnlen(secret) > LPMAXSTRLEN)
		return LP_ERR_SECRET;
	
	evpmd_f md = NULL;
	unsigned i;
	for(i = 0; i < mdlistsize; i++)
	{
		if(ctx->digest == mdlist[i].id)
		{
			md = mdlist[i].md;
			break;
		}
	}
	if(md == NULL)
		return LP_ERR_DIGEST;
	
	unsigned saltlen = 0;
	char outbuf[LPMAXSTRLEN];
	
	unsigned len = 0;
	
	
	len = mystrnlen(site);
	mymemcpy(outbuf, site, len);
	saltlen += len;
	
	len = mystrnlen(login);
	mymemcpy(outbuf + saltlen, login, len);
	saltlen += len;
	
	len = myhexlen(ctx->counter);
	mysprinthex(outbuf + saltlen, len, ctx->counter);
	saltlen += len;
	
	
	len = mystrnlen(secret);
	
	unsigned char keybuf[ctx->keylen];
	PKCS5_PBKDF2_HMAC(secret, len, (unsigned char *)outbuf, saltlen, ctx->iterations, md(), sizeof keybuf, keybuf);
	
	BN_bin2bn(keybuf, sizeof keybuf, ctx->entropy);
	OPENSSL_cleanse(keybuf, sizeof keybuf);
	const charset_t *charset = &cslist[ctx->charsets & LP_CSF_ALL];
	len = ctx->length - charset->numsets;
	consumeEntropy(ctx, outbuf, len, charset->set, charset->setlen);
	
	char toadd[charset->numsets];
	char *p = toadd;
	for(i = 1; i < cslistsize; i <<= 1)
	{
		if(ctx->charsets & i)
		{
			*p++ = cslist[i].set[consumeEntropyInt(ctx, cslist[i].setlen)];
		}
	}

	int sep = 0;
	for(i = 0; i < charset->numsets; i++)
	{
		sep = consumeEntropyInt(ctx, len);
		mypushchar(outbuf, len, sep, toadd[i]);
		len++;
	}

	mymemcpy(pass, outbuf, passlen > len ? len : passlen);
	OPENSSL_cleanse(outbuf, sizeof outbuf);
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
	
	if(ctx->length > LP_LENGTH_MAX || ctx->length < LP_LENGTH_MIN)
		return LP_ERR_PASSLEN;

	if(ctx->counter > LP_COUNTER_MAX || ctx->counter < LP_COUNTER_MIN)
		return LP_ERR_COUNTER;
	
	if((ctx->charsets & LP_CSF_ALL) == 0)
		return LP_ERR_FLAGS;

	return LP_generate(ctx, site, login, secret, pass, passlen);
}
