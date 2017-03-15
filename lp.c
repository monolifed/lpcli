typedef struct evp_md_st EVP_MD;
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                       const unsigned char *salt, int saltlen, int iter,
                       const EVP_MD *digest,
                       int keylen, unsigned char *out);

const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_md5_sha1(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);


typedef struct bignum_st BIGNUM;
BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);

typedef struct bignum_ctx BN_CTX;
BN_CTX *BN_CTX_new(void);
void BN_CTX_free(BN_CTX *c);

void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_set_word(BIGNUM *a, unsigned long w);
unsigned long BN_get_word(BIGNUM *a);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
         BN_CTX *ctx);

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);

#include "lp.h"
#include <stdio.h>
#include <string.h>

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
	{LP_CSF_NUMBERIC , "0123456789"                        , 10},
	{LP_CSF_SYMBOLS  , "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 32}
};
static const unsigned cslistsize = sizeof(cslist)/sizeof(cslist[0]);
#define MAXSETLEN 94

const lp_opts defopts =
{
	.version = LP_OV_VERSION,
	.keylen = LP_OV_KEYLEN,
	.iterations = LP_OV_ITER,
	.digest = LP_MD_SHA256,

	.counter = LP_OV_COUNTER,
	.length = LP_OV_LENGTH,
	.flags = LP_OV_FLAGS,
};

void lp_defaultopts(lp_opts *opts)
{
	memcpy(opts, &defopts, sizeof defopts);
}


static unsigned long longdivEntropy(BIGNUM *dv, BIGNUM *rem, BIGNUM *ent, const BIGNUM *d, BN_CTX *ctx)
{
	BN_div(dv, rem, ent, d, ctx);
	BN_copy(ent, dv);
	return BN_get_word(rem);
}

static void consumeEntropy(BN_CTX *ctx, BIGNUM *ent, char *pass, int passlen, const char *set, int setlen)
{
	BN_CTX_start(ctx);
	BIGNUM *dv = BN_CTX_get(ctx);
	BIGNUM *rem = BN_CTX_get(ctx);
	BIGNUM *d = BN_CTX_get(ctx); BN_set_word(d, setlen);
	int i = 0;
	for(i = 0; i < passlen; i++)
	{
		pass[i] = set[longdivEntropy(dv, rem, ent, d, ctx)];
	}
	
	BN_CTX_end(ctx);
}

static int consumeEntropyInt(BN_CTX *ctx, BIGNUM *ent, int setlen)
{
	BN_CTX_start(ctx);
	BIGNUM *dv = BN_CTX_get(ctx);
	BIGNUM *rem = BN_CTX_get(ctx);
	BIGNUM *d = BN_CTX_get(ctx); BN_set_word(d, setlen);
	int i = 0;
	i = longdivEntropy(dv, rem, ent, d, ctx);
	BN_CTX_end(ctx);
	return i;
}

size_t mystrnlen(const char *s)
{
    size_t i;
    for(i = 0; (i < LPMAXSTRLEN) && s[i]; i++);
    return i;
}

static size_t myhexlen(unsigned i)
{
	if(!i)
		return 1;
	size_t d;
	for(d = 0; i; d++)
		i >>= 4;
	return d;
}

void mysprinthex(char *dst, unsigned dlen, unsigned i)
{
	static const char hexchars[] = "0123456789ABCDEF";

	unsigned d;
	for(d = dlen; d > 0; d--)
	{
		dst[d - 1] = hexchars[i & 0xF];
		i >>= 4;
	}
}

int lp_generate(const char* site,  const char* login, const char* secret, lp_opts *opts, char* pass, unsigned passlen)
{
	//validation start
	
	if(opts->version != LP_OV_VERSION)
		return LP_ERR_VERSION;
	if(opts->keylen > LP_OV_KEYLEN_MAX || opts->keylen == 0)
		return LP_ERR_KEYLEN;
	if(opts->length > (opts->keylen - cslistsize) || opts->length == 0)
		return LP_ERR_PASSLEN;
	if(opts->iterations > LP_OV_ITER_MAX || opts->iterations == 0)
		return LP_ERR_ITER;
	if(opts->counter > LP_OV_COUNTER_MAX || opts->counter == 0)
		return LP_ERR_COUNTER;
	
	if(mystrnlen(site) + mystrnlen(login) + myhexlen(opts->counter) > LPMAXSTRLEN)
		return LP_ERR_SALTLEN;
	
	if(mystrnlen(secret) > LPMAXSTRLEN)
		return LP_ERR_SECRET;
	
	evpmd_f md = NULL;
	unsigned i;
	for(i = 0; i < mdlistsize; i++)
	{
		if(opts->digest == mdlist[i].id)
		{
			md = mdlist[i].md;
			break;
		}
	}
	if(md == NULL)
		return LP_ERR_DIGEST;
	
	
	if(!(opts->flags & LP_CSF_ALL))
		return LP_ERR_FLAGS;
	
	//validation end
	
	
	char set[MAXSETLEN];
	unsigned setlen = 0;
	unsigned setnum = 0;
	for(i = 0; i < cslistsize; i++)
	{
		if(opts->flags & cslist[i].flag)
		{
			memcpy(set + setlen, cslist[i].set, cslist[i].setlen);
			setlen += cslist[i].setlen;
			setnum++;
		}
	}
	
	unsigned saltlen = 0;
	char outbuf[LPMAXSTRLEN];
	saltlen = snprintf(outbuf, sizeof outbuf, "%s%s%x", site, login, opts->counter);
	
	unsigned len = 0;
	
	/*
	len = mystrnlen(site);
	memcpy(outbuf, site, len);
	saltlen += len;
	
	len = mystrnlen(login);
	memcpy(outbuf + saltlen, login, len);
	saltlen += len;
	
	len = myhexlen(opts->counter);
	mysprinthex(outbuf + saltlen, len, opts->counter);
	saltlen += len;
	*/
	
	len = mystrnlen(secret);
	
	unsigned char keybuf[opts->keylen];
	PKCS5_PBKDF2_HMAC(secret, len, (unsigned char *)outbuf, saltlen, opts->iterations, md(), sizeof keybuf, keybuf);
	
	BN_CTX *bn_ctx = BN_CTX_new();
	BIGNUM *entropy = BN_new();
	BN_bin2bn(keybuf, sizeof keybuf, entropy);
	len = opts->length - setnum;
	consumeEntropy(bn_ctx, entropy, outbuf, len, set, setlen);
	
	char toadd[setnum];
	char *p = toadd;
	for(i = 0; i < cslistsize; i++)
	{
		if(opts->flags & cslist[i].flag)
		{
			*p++ = cslist[i].set[consumeEntropyInt(bn_ctx, entropy, cslist[i].setlen)];
		}
	}
	
	int sep = 0;
	for(i = 0; i < setnum; i++)
	{
		sep = consumeEntropyInt(bn_ctx, entropy, len);
		memmove(outbuf + sep + 1, outbuf + sep, len - sep);
		outbuf[sep] = toadd[i];
		len++;
	}
	
	outbuf[len] = 0;
	memcpy(pass, outbuf, passlen);
	
	
	BN_free(entropy);
	BN_CTX_free(bn_ctx);
	
	return len + 1;
}

