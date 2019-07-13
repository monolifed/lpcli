#ifndef LP_INCLUDE
#define LP_INCLUDE

#include "pbkdf2_sha256.h"
#include <stdint.h>

#define LPMAXSTRLEN 2048

#define LP_VER    2      // default version
#ifndef LP_KEYLEN
#define LP_KEYLEN 32     // pbkdf2 keylen for version 2
#endif
#ifndef LP_ITERS
#define LP_ITERS  100000 // pbkdf2 iterations for version 2
#endif

#define LP_NUM_CHARSETS 4
#define LP_CHARSETS_X \
	X(LOWERCASE, "abcdefghijklmnopqrstuvwxyz") \
	X(UPPERCASE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") \
	X(DIGITS,    "0123456789") \
	X(SYMBOLS,   "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~") \

//LP_CS_XXX
#define X(A, B) LP_CS_##A,
typedef enum
{
	LP_CHARSETS_X
} lp_cs_index;
#undef X

//LP_CSF_XXX = (1 << LP_CS_XXX)
#define X(A, B) LP_CSF_##A = (1 << LP_CS_##A),
typedef enum
{
	LP_CHARSETS_X
} lp_cs_flag;
#undef X

#define LP_CSF_ALL ((1 << LP_NUM_CHARSETS) - 1)

#undef LP_CHARSETS_X

typedef enum
{
	LP_COUNTER_DEF = 1, LP_COUNTER_MIN = 1, LP_COUNTER_MAX = 0x0FFFFFFF,
	LP_LENGTH_DEF  = 16, LP_LENGTH_MIN = 5, LP_LENGTH_MAX = 35,
	LP_CSF_DEF = LP_CSF_ALL,
} lp_options;

#define ENT_LEN  10 // LP_LENGTH_MAX / sizeof(uint32_t) + 1
typedef struct lp_ctx_st
{
	unsigned version;
	unsigned keylen;
	unsigned iterations;
	
	unsigned counter;
	unsigned length;
	unsigned charsets;
	
	uint32_t entropy[ENT_LEN];
	HMAC_SHA256_CTX hmac;
    unsigned saltlen;
	char buffer[LPMAXSTRLEN];
	uint8_t keybuf[LP_KEYLEN];
} LP_CTX;

typedef enum
{
	LP_ERR_GENERIC = -64,
	LP_ERR_VERSION, // version is not 2 (internal)
	LP_ERR_KEYLEN,  // keylen is not 32 (internal)
	LP_ERR_ITER,    // iterations is not 100000 (internal)
	//LP_ERR_DIGEST,  // digest is not sha256 (internal)
	
	LP_ERR_LENGTH,  // passlen out of range
	LP_ERR_COUNTER, // counter out of range
	LP_ERR_FLAGS,   // no charsets flags selected
	LP_ERR_INIT,    // LP_CTX is not initialized
	LP_ERR_NULL_SITE,
	LP_ERR_NULL_LOGIN,
	LP_ERR_LONG_SALT, // generated salt too long (>=LPMAXSTRLEN)
	LP_ERR_NULL_SECRET, LP_ERR_LONG_SECRET, // (>=LPMAXSTRLEN)
	LP_ERR_NULL_PASS
	
} lp_error;

void LP_CTX_init(LP_CTX *ctx);

// Sets the value if valid, returns to current value
// ret = LP_set_xxx(ctx, 0); is a getter
// Since 0 is invalid for counter, length and charset
unsigned LP_set_counter(LP_CTX *ctx, unsigned);
unsigned LP_set_length(LP_CTX *ctx, unsigned);
unsigned LP_set_charset(LP_CTX *ctx, unsigned);

// returns ctx->length on success,
// returns negative LP_ERR_xxx value on failure
int LP_generate(LP_CTX *ctx, const char *site,  const char *login, const char *secret, char *pass, unsigned passlen);
#endif // LP_INCLUDE

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

#ifdef LP_IMPLEMENTATION

#define PBKDF2_SHA256_STATIC
#define PBKDF2_SHA256_IMPLEMENTATION
#include "pbkdf2_sha256.h"

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


#ifndef BIG_ENDIAN
#define BE_VALUE(S) (S[0]<<24 | S[1]<<16 | S[2]<<8 | S[3])
#else
#define BE_VALUE(S) (* (uint32_t *) (S))
#endif
static void init_entropy(uint32_t *ent, uint8_t *buffer, uint32_t buflen)
{
	int i = buflen - 4;
	int j = 0;
	// NOTE: assumes buflen is a multiple of 4
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
	
	if (i == -1) {return 0;}
	
	uint64_t qt = 0;
	uint64_t r = 0;
	for (; i >= 0; i--)
	{
		qt = (r << 32) | ent[i];
		r = qt % d;
		ent[i] = qt / d;
	}
	return r;
}

static void generate_chars(LP_CTX *ctx, char *dst, unsigned dstlen, const char *set, unsigned setlen)
{
	for (unsigned i = 0; i < dstlen; i++)
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
	if (!s || !*s) {return 0;}
	
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
	if (u == 0) {return 1;}
	
	unsigned d;
	for (d = 0; u; d++)
	{
		u >>= 4;
	}
	return d;
}

static void mysprinthex(char *dst, unsigned dlen, unsigned u)
{
	static const char hexchars[] = "0123456789abcdef"; //version 2 uses small letters
	
	for (unsigned d = dlen; d > 0; d--)
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
	mymemcpy(dst + pos + 1, dst + pos, len - pos - 1);
	dst[pos] = c;
}

static int generate(LP_CTX *ctx, const char *secret, unsigned secretlen, char *pass, unsigned passlen)
{
	if (passlen == 0)
		return 0;
	
	// Create entropy number from PBKDF2
	pbkdf2_sha256(&ctx->hmac, (uint8_t *) secret, secretlen,
		(uint8_t *) ctx->buffer, ctx->saltlen, ctx->iterations, ctx->keybuf, LP_KEYLEN);
	
	init_entropy(ctx->entropy, ctx->keybuf, LP_KEYLEN);
	
	// Select len (= length - numsets) characters from the merged charset
	const charset_t *charset = &cslist[ctx->charsets & LP_CSF_ALL];
	unsigned len = ctx->length - charset->numsets;
	generate_chars(ctx, ctx->buffer, len, charset->value, charset->length);
	
	// Select numsets characters (one from each subset of charset)
	unsigned i;
	unsigned offset = 0;
	for (i = 0; i < charset->numsets; i++)
	{
		ctx->buffer[len + i] = generate_char(ctx, charset->value + offset, charset->lensets[i]);
		offset += charset->lensets[i];
	}
	
	// Combine last numsets characters into the first len characters
	for (; len < ctx->length; len++)
	{
		mypushchar(ctx->buffer, len + 1, generate_int(ctx, len), ctx->buffer[len]);
	}
	
	mymemcpy(pass, ctx->buffer, passlen > len ? len : passlen);
	return len;
}

void LP_CTX_init(LP_CTX *ctx)
{
	ctx->version = LP_VER;
	ctx->keylen = LP_KEYLEN;
	ctx->iterations = LP_ITERS;
	
	ctx->counter = LP_COUNTER_DEF;
	ctx->length = LP_LENGTH_DEF;
	ctx->charsets = LP_CSF_DEF;
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
	if (ctx->version != LP_VER)
		return LP_ERR_VERSION;
	if (ctx->keylen != LP_KEYLEN)
		return LP_ERR_KEYLEN;
	if (ctx->iterations != LP_ITERS)
		return LP_ERR_ITER;
		
	if (ctx->length > LP_LENGTH_MAX || ctx->length < LP_LENGTH_MIN)
		return LP_ERR_LENGTH;
	if (ctx->counter > LP_COUNTER_MAX || ctx->counter < LP_COUNTER_MIN)
		return LP_ERR_COUNTER;
	if ((ctx->charsets & LP_CSF_ALL) == 0)
		return LP_ERR_FLAGS;
		
	unsigned sitelen  = mystrnlen(site, LPMAXSTRLEN);
	unsigned loginlen = mystrnlen(login, LPMAXSTRLEN);
	unsigned ctrlen   = myhexlen(ctx->counter);
	ctx->saltlen = sitelen + loginlen + ctrlen;
	
	if (ctx->saltlen >= LPMAXSTRLEN)
		return LP_ERR_LONG_SALT;

	// Create salt string in ctx->buffer: site|login|hex(counter)
	char *p = ctx->buffer;
	mymemcpy(p, site, sitelen);
	p += sitelen;
	mymemcpy(p, login, loginlen);
	p += loginlen;
	mysprinthex(p, ctrlen, ctx->counter);
    
	unsigned secretlen = mystrnlen(secret, LPMAXSTRLEN);
	if (secretlen >= LPMAXSTRLEN)
		return LP_ERR_LONG_SECRET;
	
	return generate(ctx, secret, secretlen, pass, passlen);
}
#endif // LP_IMPLEMENTATION
