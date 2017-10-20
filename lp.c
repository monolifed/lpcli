#include "lp_crypto.h"

#include "lp.h"

struct lp_ctx_st
{
	unsigned version;
	unsigned keylen;
	unsigned iterations;
	int digest;

	unsigned counter;
	unsigned length;
	unsigned charsets;
};

typedef enum
{
	LP_MD_MD5    = 0,
	LP_MD_SHA1   = 1,
	LP_MD_SHA224 = 2,
	LP_MD_SHA256 = 3, // only valid value
	LP_MD_SHA384 = 4,
	LP_MD_SHA512 = 5,

} lp_digest;


typedef enum
{
	LP_VERSION     = 2,
	LP_KEYLEN      = 32,
	LP_ITERS       = 100000,
	LP_DIGEST      = LP_MD_SHA256
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

#define CSSETLEN  50
typedef struct charset_s
{
	int flag;
	const char set[CSSETLEN];
	int setlen;
} charset_t;

static const charset_t cslist[] =
{
	{LP_CSF_LOWERCASE, "abcdefghijklmnopqrstuvwxyz"        , 26},
	{LP_CSF_UPPERCASE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"        , 26},
	{LP_CSF_DIGITS , "0123456789"                        , 10},
	{LP_CSF_SYMBOLS  , "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 32}
};
static const unsigned cslistsize = sizeof(cslist)/sizeof(cslist[0]);
#define MAXSETLEN 94

static unsigned long longdivEntropy(BIGNUM *dv, BIGNUM *rem, BIGNUM *ent, const BIGNUM *d, BN_CTX *bnctx)
{
	BN_div(dv, rem, ent, d, bnctx);
	BN_copy(ent, dv);
	return BN_get_word(rem);
}

static void consumeEntropy(BN_CTX *bnctx, BIGNUM *ent, char *pass, int passlen, const char *set, int setlen)
{
	BN_CTX_start(bnctx);
	BIGNUM *dv = BN_CTX_get(bnctx);
	BIGNUM *rem = BN_CTX_get(bnctx);
	BIGNUM *d = BN_CTX_get(bnctx); BN_set_word(d, setlen);
	int i = 0;
	for(i = 0; i < passlen; i++)
	{
		pass[i] = set[longdivEntropy(dv, rem, ent, d, bnctx)];
	}
	
	BN_CTX_end(bnctx);
}

static int consumeEntropyInt(BN_CTX *bnctx, BIGNUM *ent, int setlen)
{
	BN_CTX_start(bnctx);
	BIGNUM *dv = BN_CTX_get(bnctx);
	BIGNUM *rem = BN_CTX_get(bnctx);
	BIGNUM *d = BN_CTX_get(bnctx); BN_set_word(d, setlen);
	int i = 0;
	i = longdivEntropy(dv, rem, ent, d, bnctx);
	BN_CTX_end(bnctx);
	return i;
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
	//for(i = len; i > pos; count--)
	//{
	//	dst[i] = dst[i - 1];
	//}
	
	mymemcpy(dst + pos + 1, dst + pos, len - pos);
	dst[pos] = c;
}

int LP_generate( LP_CTX *ctx, const char* site,  const char* login, const char* secret, char* pass, unsigned passlen)
{
	if((ctx->charsets & LP_CSF_ALL) == 0 || ctx->length == 0 || passlen == 0)
		return 0;
	
	if(mystrnlen(site) + mystrnlen(login) + myhexlen(ctx->counter) > LPMAXSTRLEN)
		return LP_ERR_SALTLEN;
	
	if(mystrnlen(secret) > LPMAXSTRLEN)
		return LP_ERR_SECRET;
	
	evpmd_f md = (void *)0;
	unsigned i;
	for(i = 0; i < mdlistsize; i++)
	{
		if(ctx->digest == mdlist[i].id)
		{
			md = mdlist[i].md;
			break;
		}
	}
	if(md == (void *)0)
		return LP_ERR_DIGEST;
	
	char set[MAXSETLEN];
	unsigned setlen = 0; // len. of merged set
	unsigned setnum = 0; // num. of sets used
	for(i = 0; i < cslistsize; i++)
	{
		if(ctx->charsets & cslist[i].flag)
		{
			mymemcpy(set + setlen, cslist[i].set, cslist[i].setlen);
			setlen += cslist[i].setlen;
			setnum++;
		}
	}
	
	unsigned saltlen = 0;
	char outbuf[LPMAXSTRLEN];
	//saltlen = snprintf(outbuf, sizeof outbuf, "%s%s%x", site, login, ctx->counter);
	
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
	
	BN_CTX *bnctx = BN_CTX_new();
	BIGNUM *entropy = BN_new();
	BN_bin2bn(keybuf, sizeof keybuf, entropy);
	len = ctx->length - setnum;
	consumeEntropy(bnctx, entropy, outbuf, len, set, setlen);
	
	char toadd[setnum];
	char *p = toadd;
	for(i = 0; i < cslistsize; i++)
	{
		if(ctx->charsets & cslist[i].flag)
		{
			*p++ = cslist[i].set[consumeEntropyInt(bnctx, entropy, cslist[i].setlen)];
		}
	}

	int sep = 0;
	for(i = 0; i < setnum; i++)
	{
		sep = consumeEntropyInt(bnctx, entropy, len);
		//memmove(outbuf + sep + 1, outbuf + sep, len - sep);
		//outbuf[sep] = toadd[i];
		mypushchar(outbuf, len, sep, toadd[i]);
		len++;
	}

	BN_free(entropy);
	BN_CTX_free(bnctx);

	mymemcpy(pass, outbuf, passlen > len ? len : passlen);

	return len;
}

LP_CTX* LP_CTX_new(void)
{
	LP_CTX *lpctx = CRYPTO_malloc(sizeof(LP_CTX), __FILE__, __LINE__);
	lpctx->version = LP_VERSION;
	lpctx->keylen = LP_KEYLEN;
	lpctx->iterations = LP_ITERS;
	lpctx->digest = LP_DIGEST;

	lpctx->counter = LP_COUNTER_DEF;
	lpctx->length = LP_LENGTH_DEF;
	lpctx->charsets = LP_CSF_DEF;
	return lpctx;
}

void LP_CTX_free(LP_CTX *ctx)
{
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
	if(ctx->version != LP_VERSION)
		return LP_ERR_VERSION;
	if(ctx->keylen != LP_KEYLEN)
		return LP_ERR_KEYLEN;
	if(ctx->iterations != LP_ITERS)
		return LP_ERR_ITER;
	if(ctx->digest != LP_MD_SHA256)
		return LP_ERR_DIGEST;
	
	if(ctx->length > LP_LENGTH_MAX || ctx->length < LP_LENGTH_MIN)
		return LP_ERR_PASSLEN;

	if(ctx->counter > LP_COUNTER_MAX || ctx->counter < LP_COUNTER_MIN)
		return LP_ERR_COUNTER;
	
	if((ctx->charsets & LP_CSF_ALL) == 0)
		return LP_ERR_FLAGS;

	return LP_generate(ctx, site, login, secret, pass, passlen);
}
