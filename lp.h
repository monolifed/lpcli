#ifndef LP_INCLUDE
#define LP_INCLUDE

#include "pbkdf2_sha256.h"
#include <stdint.h>

#ifndef LP_STATIC
#define LP_DEF extern
#else
#define LP_DEF static
#endif

#define LPMAXSTRLEN 2048

#define LP_VER    2      // default version

#ifndef LP_KEYLEN
#define LP_KEYLEN 32     // pbkdf2 keylen for version 2
#endif

#ifndef LP_ITERS
#define LP_ITERS  100000 // pbkdf2 iterations for version 2
#endif

#define LP_NUM_CHARSETS 4
#define LP_CSF_LOWERCASE 0x01
#define LP_CSF_UPPERCASE 0x02
#define LP_CSF_DIGITS    0x04
#define LP_CSF_SYMBOLS   0x08
#define LP_CSF_ALL       0x0F

typedef enum
{
	LP_COUNTER_DEF = 1, LP_COUNTER_MIN = 1, LP_COUNTER_MAX = 0x0FFFFFFF,
	LP_LENGTH_DEF  = 16, LP_LENGTH_MIN = 5, LP_LENGTH_MAX = 35,
	LP_CSF_DEF = LP_CSF_ALL,
} lp_options;

#define ENT_LEN  10 // >= LP_LENGTH_MAX / sizeof(uint32_t) + 1
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
	unsigned buflen;
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
	LP_ERR_NULL_SECRET,
	LP_ERR_LONG_SECRET, // (>=LPMAXSTRLEN)
	LP_ERR_NULL_PASS
	
} lp_error;

LP_DEF void LP_CTX_init(LP_CTX *ctx);

// returns the value if valid, 0 (which is invalid) otherwise
LP_DEF unsigned LP_check_counter(unsigned);
LP_DEF unsigned LP_check_length(unsigned);
LP_DEF unsigned LP_check_charsets(unsigned);

// returns ctx->length on success,
// returns negative LP_ERR_xxx value on failure
LP_DEF int LP_generate(LP_CTX *ctx, const char *site,  const char *login, const char *secret);
#endif // LP_INCLUDE

//------------------------------------------------------------------------------

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
	int j = 0;
	// NOTE: assumes buflen is a multiple of 4
	for (int i = buflen - 4; i >= 0; i -= 4, j++)
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
	int i;
	for (i = ENT_LEN - 1; i >= 0; i--)
	{
		if (ent[i] != 0)
			break;
	}
	
	if (i == -1)
		return 0;
		
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

static int generate(LP_CTX *ctx, const char *secret, unsigned secretlen)
{
	// Create entropy number from PBKDF2
	pbkdf2_sha256(&ctx->hmac, (uint8_t *) secret, secretlen,
	    (uint8_t *) ctx->buffer, ctx->buflen, ctx->iterations, ctx->keybuf, LP_KEYLEN);
	    
	init_entropy(ctx->entropy, ctx->keybuf, LP_KEYLEN);
	
	// Select len (= length - numsets) characters from the merged charset
	const charset_t *charset = &cslist[ctx->charsets & LP_CSF_ALL];
	unsigned len = ctx->length - charset->numsets;
	generate_chars(ctx, ctx->buffer, len, charset->value, charset->length);
	
	// Select numsets characters (one from each subset of charset)
	unsigned offset = 0;
	for (unsigned i = 0; i < charset->numsets; i++)
	{
		ctx->buffer[len + i] = generate_char(ctx, charset->value + offset, charset->lensets[i]);
		offset += charset->lensets[i];
	}
	
	// Combine last numsets characters into the first len characters
	for (; len < ctx->length; len++)
	{
		mypushchar(ctx->buffer, len + 1, generate_int(ctx, len), ctx->buffer[len]);
	}
	
	ctx->buffer[len] = 0;
	ctx->buflen = len;
	return len;
}

LP_DEF void LP_CTX_init(LP_CTX *ctx)
{
	ctx->version = LP_VER;
	ctx->keylen = LP_KEYLEN;
	ctx->iterations = LP_ITERS;
	
	ctx->counter = LP_COUNTER_DEF;
	ctx->length = LP_LENGTH_DEF;
	ctx->charsets = LP_CSF_DEF;
}

LP_DEF unsigned LP_check_counter(unsigned counter)
{
	if (counter >= LP_COUNTER_MIN && counter <= LP_COUNTER_MAX)
	{
		return counter;
	}
	return 0;
}

LP_DEF unsigned LP_check_length(unsigned length)
{
	if (length >= LP_LENGTH_MIN && length <= LP_LENGTH_MAX)
	{
		return length;
	}
	return 0;
}

LP_DEF unsigned LP_check_charsets(unsigned charsets)
{
	return charsets & LP_CSF_ALL;
}

#define LP_ASSERT(COND,VAL) if (!(COND)) {return LP_ERR_##VAL;}
LP_DEF int LP_generate(LP_CTX *ctx, const char *site,  const char *login, const char *secret)
{
	LP_ASSERT(ctx, INIT);
	LP_ASSERT(ctx->version == 2, VERSION);
	LP_ASSERT(ctx->keylen == LP_KEYLEN, KEYLEN);
	LP_ASSERT(ctx->iterations == LP_ITERS, ITER);
	
	LP_ASSERT(site, NULL_SITE);
	LP_ASSERT(login, NULL_LOGIN);
	LP_ASSERT(secret, NULL_SECRET);
	
	LP_ASSERT(LP_check_length(ctx->length), LENGTH);
	LP_ASSERT(LP_check_counter(ctx->counter), COUNTER);
	LP_ASSERT(LP_check_charsets(ctx->charsets), FLAGS);
	
	unsigned sitelen  = mystrnlen(site, LPMAXSTRLEN);
	unsigned loginlen = mystrnlen(login, LPMAXSTRLEN);
	unsigned ctrlen   = myhexlen(ctx->counter);
	unsigned saltlen = sitelen + loginlen + ctrlen;
	LP_ASSERT(saltlen < LPMAXSTRLEN, LONG_SALT);
	
	unsigned secretlen = mystrnlen(secret, LPMAXSTRLEN);
	LP_ASSERT(secretlen < LPMAXSTRLEN, LONG_SECRET);
	
	// Create salt string in ctx->buffer: site|login|hex(counter)
	char *p = ctx->buffer;
	mymemcpy(p, site, sitelen);
	p += sitelen;
	mymemcpy(p, login, loginlen);
	p += loginlen;
	mysprinthex(p, ctrlen, ctx->counter);
	ctx->buflen = saltlen;
	
	return generate(ctx, secret, secretlen);
}
#undef LP_ASSERT

#endif // LP_IMPLEMENTATION
