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

static void mypushchar(char *dst, unsigned dlen, unsigned pos, char c)
{
	unsigned i;
	for(i = dlen; i > pos; i--)
	{
		dst[i - 1] = dst[i - 2];
	}
	dst[i] = c;
}

int lp_generate(const char* site,  const char* login, const char* secret, lp_opts *opts, char* pass, unsigned passlen)
{
	if((opts->flags & LP_CSF_ALL) == 0 || opts->length == 0 || passlen == 0)
		return 0;
	
	if(mystrnlen(site) + mystrnlen(login) + myhexlen(opts->counter) > LPMAXSTRLEN)
		return LP_ERR_SALTLEN;
	
	if(mystrnlen(secret) > LPMAXSTRLEN)
		return LP_ERR_SECRET;
	
	evpmd_f md = (void *)0;
	unsigned i;
	for(i = 0; i < mdlistsize; i++)
	{
		if(opts->digest == mdlist[i].id)
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
		if(opts->flags & cslist[i].flag)
		{
			mymemcpy(set + setlen, cslist[i].set, cslist[i].setlen);
			setlen += cslist[i].setlen;
			setnum++;
		}
	}
	
	unsigned saltlen = 0;
	char outbuf[LPMAXSTRLEN];
	//saltlen = snprintf(outbuf, sizeof outbuf, "%s%s%x", site, login, opts->counter);
	
	unsigned len = 0;
	
	
	len = mystrnlen(site);
	mymemcpy(outbuf, site, len);
	saltlen += len;
	
	len = mystrnlen(login);
	mymemcpy(outbuf + saltlen, login, len);
	saltlen += len;
	
	len = myhexlen(opts->counter);
	mysprinthex(outbuf + saltlen, len, opts->counter);
	saltlen += len;
	
	
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
		//memmove(outbuf + sep + 1, outbuf + sep, len - sep);
		//outbuf[sep] = toadd[i];
		mypushchar(outbuf, opts->length, sep, toadd[i]);
		len++;
	}
	BN_free(entropy);
	BN_CTX_free(bn_ctx);
	
	mymemcpy(pass, outbuf, passlen > len ? len : passlen);
	
	return len;
}

void lp_setopts_v2(lp_opts *opts, unsigned counter, unsigned length, unsigned flags)
{
	opts->version = LP_OV_VERSION;
	opts->keylen = LP_OV_KEYLEN;
	opts->iterations = LP_OV_ITER;
	opts->digest = LP_OV_DIGEST;

	opts->counter = LP_OV_COUNTER;
	opts->length = LP_OV_LENGTH;
	opts->flags = LP_OV_FLAGS;
	
	if(counter >= LP_OV_COUNTER_MIN && counter <= LP_OV_COUNTER_MAX)
		opts->counter = counter;
	if(length >= LP_OV_LENGTH_MIN && length <= LP_OV_LENGTH_MAX)
		opts->length = length;
	if(flags & LP_CSF_ALL)
		opts->flags = flags;
}

int lp_genpass_v2(const char* site,  const char* login, const char* secret, lp_opts *opts, char* pass, unsigned passlen)
{
	if(opts->version != LP_OV_VERSION)
		return LP_ERR_VERSION;
	if(opts->keylen != LP_OV_KEYLEN)
		return LP_ERR_KEYLEN;
	if(opts->iterations != LP_OV_ITER)
		return LP_ERR_ITER;
	if(opts->digest != LP_MD_SHA256)
		return LP_ERR_DIGEST;
	
	if(opts->length > LP_OV_LENGTH_MAX || opts->length < LP_OV_LENGTH_MIN)
		return LP_ERR_PASSLEN;

	if(opts->counter > LP_OV_COUNTER_MAX || opts->counter < LP_OV_COUNTER_MIN)
		return LP_ERR_COUNTER;
	
	if((opts->flags & LP_CSF_ALL) == 0)
		return LP_ERR_FLAGS;

	
	return lp_generate(site, login, secret, opts, pass, passlen);
}