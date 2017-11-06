#ifndef LP_H
#define LP_H

#define LPMAXSTRLEN 2048

#define LP_NUM_CHARSETS 4
#define LP_CHARSETS_X \
	X(LOWERCASE, "abcdefghijklmnopqrstuvwxyz") \
	X(UPPERCASE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") \
	X(DIGITS, "0123456789") \
	X(SYMBOLS, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~") \

#define X(A, B) LP_CS_##A,
typedef enum
{
	LP_CHARSETS_X
} lp_cs_indexes;
#undef X

#define X(A, B) LP_CSF_##A = (1 << LP_CS_##A),
typedef enum
{
	LP_CHARSETS_X
} lp_cs_flags;
#undef X

#define LP_CSF_ALL ((1 << LP_NUM_CHARSETS) - 1)

#ifdef LP_AUTOGEN
#define X(A, B) B,
static const char *charsets[] =
{
	LP_CHARSETS_X
};
#undef X
#endif

#undef LP_CHARSETS_X

typedef enum
{
	LP_COUNTER_DEF = 1, LP_COUNTER_MIN = 1, LP_COUNTER_MAX = 0x0FFFFFFF,
	LP_LENGTH_DEF  = 16, LP_LENGTH_MIN = 5, LP_LENGTH_MAX = 35,
	LP_CSF_DEF = LP_CSF_ALL,
} lp_options;

typedef struct lp_ctx_st LP_CTX;

typedef enum
{
	LP_ERR_GENERIC = -64,
	LP_ERR_VERSION, // version is not 2 (internal)
	LP_ERR_KEYLEN,  // keylen is not 32 (internal)
	LP_ERR_ITER,    // iterations is not 100000 (internal)
	LP_ERR_DIGEST,  // digest is not sha256 (internal)

	LP_ERR_LENGTH,  // passlen out of range
	LP_ERR_COUNTER, // counter out of range
	LP_ERR_FLAGS,   // no charsets flags selected
	LP_ERR_INIT,    // LP_CTX is not initialized
	LP_ERR_NULL_SITE, LP_ERR_LONG_SITE,     // (>=LPMAXSTRLEN)
	LP_ERR_NULL_LOGIN, LP_ERR_LONG_LOGIN,   // (>=LPMAXSTRLEN)
	LP_ERR_NULL_SECRET, LP_ERR_LONG_SECRET, // (>=LPMAXSTRLEN)
	LP_ERR_NULL_PASS
	
} lp_error;

LP_CTX* LP_CTX_new(void);
void LP_CTX_free(LP_CTX *opts);

// Sets the value if valid, returns to current value
// ret = LP_set_xxx(ctx, 0); is a getter
// Since 0 is invalid for counter, length and charset
unsigned LP_set_counter(LP_CTX *ctx, unsigned);
unsigned LP_set_length(LP_CTX *ctx, unsigned);
unsigned LP_set_charsets(LP_CTX *ctx, unsigned);

// returns ctx->length on success,
// returns negative LP_ERR_xxx value on failure
int LP_generate(LP_CTX *ctx, const char* site,  const char* login, const char* secret, char* pass, unsigned passlen);
#endif //LP_H
