#include "lp.h"
#include "stdlib.h"

#include "pbkdf2_hmac_sha256.h"
//#include "bn.h"

enum
{
	LP_VER_DEF    = 2,
	LP_KEYLEN_DEF = 32,
	LP_ITERS_DEF  = 100000,
};

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

// End Autogen Charsets

// ~(max dk len)/(sizeof uint32_t)
#define ENT_LEN  10
// typedef struct lp_ctx_st LP_CTX
struct lp_ctx_st
{
	unsigned version;
	unsigned keylen;
	unsigned iterations;
	
	unsigned counter;
	unsigned length;
	unsigned charsets;
	
	uint32_t entropy[ENT_LEN];
};

#ifndef BIG_ENDIAN
#define BE_VALUE(S) (S[0]<<24 | S[1]<<16 | S[2]<<8 | S[3])
#else
#define BE_VALUE(S) (* (DTYPE *) (S))
#endif
static void init_entropy(uint32_t *ent, uint8_t *buffer, uint32_t buflen)
{
	int i = buflen - 4;
	int j = 0;
	// NOTE: only works if buflen = 4*K (but keylen is 32)
	for (; i >= 0; i -= 4, j++)
	{
		ent[j] = BE_VALUE((buffer + i));
	}
	
	for (; j < ENT_LEN; j++)
	{
		ent[j] = 0;
	}
}
#undef BE_VALUE

static uint32_t div_entropy(uint32_t *ent, uint32_t d)
{
	int i = ENT_LEN - 1;
	for (; i >= 0; i--)
	{
		if (ent[i] != 0)
			break;
	}
	
	if (i == -1)
	{
		return 0;
	}
	
	uint64_t qt = 0;
	uint64_t r = 0;
	for (; i >= 0; i--)
	{
		qt = r << 32;
		qt |= ent[i];
		r = qt % d;
		ent[i] = qt / d;
	}
	return r;
}

static void generate_chars(LP_CTX *ctx, char *dst, unsigned dstlen, const char *set, unsigned setlen)
{
	//bn_from_int(&ctx->d, setlen);
	unsigned i = 0;
	for (i = 0; i < dstlen; i++)
	{
		dst[i] = set[div_entropy(ctx->entropy, setlen)];
	}
}

static char generate_char(LP_CTX *ctx, const char *set, int setlen)
{
	return set[div_entropy(ctx->entropy, setlen)];
}

static unsigned generate_int(LP_CTX *ctx, int setlen)
{
	return div_entropy(ctx->entropy, setlen);
}

static unsigned mystrnlen(const char *s, unsigned max)
{
	if (!s || !*s)
		return 0;
	unsigned i;
	for (i = 0; (i < max) && s[i]; i++);
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
	if (u == 0)
		return 1;
	unsigned d;
	for (d = 0; u; d++)
		u >>= 4;
	return d;
}

static void mysprinthex(char *dst, unsigned dlen, unsigned u)
{
	static const char hexchars[] = "0123456789abcdef";
	
	unsigned d;
	for (d = dlen; d > 0; d--)
	{
		dst[d - 1] = hexchars[u & 0xF];
		u >>= 4;
	}
}

static void mymemcpy(char *dst, const char *src, unsigned count)
{
	for (; count > 0; count--)
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

void zeromem(void *, size_t);

static int generate(LP_CTX *ctx, const LP_STR *site,  const LP_STR *login, const LP_STR *secret, LP_VSTR *pass)
{
	if (pass->length == 0)
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
	pbkdf2_sha256((uint8_t *) secret->value, secret->length, (uint8_t *) buffer, saltlen,
		ctx->iterations, keybuf, sizeof keybuf);
	init_entropy(ctx->entropy, keybuf, sizeof keybuf);
	zeromem(keybuf, sizeof keybuf);
	
	// Select len (= length - numsets) characters from the merged charset
	const charset_t *charset = &cslist[ctx->charsets & LP_CSF_ALL];
	len = ctx->length - charset->numsets;
	generate_chars(ctx, buffer, len, charset->value, charset->length);
	
	// Select numsets characters (one from each subset of charset)
	unsigned i;
	unsigned offset = 0;
	for (i = 0; i < charset->numsets; i++)
	{
		buffer[len + i] = generate_char(ctx, charset->value + offset, charset->lensets[i]);
		offset += charset->lensets[i];
	}
	
	// Combine last numsets characters into the first len characters
	for (; len < ctx->length; len++)
	{
		mypushchar(buffer, len + 1, generate_int(ctx, len), buffer[len]);
	}
	zeromem(ctx->entropy, sizeof ctx->entropy);
	
	mymemcpy(pass->value, buffer, pass->length > len ? len : pass->length);
	zeromem(buffer, sizeof buffer);
	return len;
}

LP_CTX *LP_CTX_new(void)
{
	LP_CTX *ctx = malloc(sizeof(LP_CTX));
	ctx->version = LP_VER_DEF;
	ctx->keylen = LP_KEYLEN_DEF;
	ctx->iterations = LP_ITERS_DEF;
	
	ctx->counter = LP_COUNTER_DEF;
	ctx->length = LP_LENGTH_DEF;
	ctx->charsets = LP_CSF_DEF;
	
	return ctx;
}

void LP_CTX_free(LP_CTX *ctx)
{
	zeromem(ctx, sizeof(LP_CTX));
	free(ctx);
}

unsigned LP_set_counter(LP_CTX *ctx, unsigned counter)
{
	if (counter >= LP_COUNTER_MIN && counter <= LP_COUNTER_MAX)
	{
		ctx->counter = counter;
	}
	return ctx->counter;
}

unsigned LP_set_length(LP_CTX *ctx, unsigned length)
{
	if (length >= LP_LENGTH_MIN && length <= LP_LENGTH_MAX)
	{
		ctx->length = length;
	}
	return ctx->length;
}

unsigned LP_set_charset(LP_CTX *ctx, unsigned charsets)
{
	if (charsets & LP_CSF_ALL)
	{
		ctx->charsets = charsets & LP_CSF_ALL;
	}
	return ctx->charsets;
}


int LP_generate(LP_CTX *ctx, const char *site,  const char *login, const char *secret, char *pass, unsigned passlen)
{
	if (site == NULL)
		return LP_ERR_NULL_SITE;
	if (login == NULL)
		return LP_ERR_NULL_LOGIN;
	if (secret == NULL)
		return LP_ERR_NULL_SECRET;
	if (pass == NULL)
		return LP_ERR_NULL_PASS;
		
	if (ctx == NULL)
		return LP_ERR_INIT;
	if (ctx->version != LP_VER_DEF)
		return LP_ERR_VERSION;
	if (ctx->keylen != LP_KEYLEN_DEF)
		return LP_ERR_KEYLEN;
	if (ctx->iterations != LP_ITERS_DEF)
		return LP_ERR_ITER;
		
	if (ctx->length > LP_LENGTH_MAX || ctx->length < LP_LENGTH_MIN)
		return LP_ERR_LENGTH;
	if (ctx->counter > LP_COUNTER_MAX || ctx->counter < LP_COUNTER_MIN)
		return LP_ERR_COUNTER;
	if ((ctx->charsets & LP_CSF_ALL) == 0)
		return LP_ERR_FLAGS;
		
	unsigned len;
	len = mystrnlen(site, LPMAXSTRLEN);
	if (len >= LPMAXSTRLEN)
		return LP_ERR_LONG_SITE;
	LP_STR site_str = {.value = site, .length = len};
	
	len = mystrnlen(login, LPMAXSTRLEN);
	if (len >= LPMAXSTRLEN)
		return LP_ERR_LONG_LOGIN;
	LP_STR login_str = {.value = login, .length = len};
	
	len = mystrnlen(secret, LPMAXSTRLEN);
	if (len >= LPMAXSTRLEN)
		return LP_ERR_LONG_SECRET;
	LP_STR secret_str = {.value = secret, .length = len};
	
	LP_VSTR pass_str = {.value = pass, .length = passlen};
	
	return generate(ctx, &site_str, &login_str, &secret_str, &pass_str);
}
