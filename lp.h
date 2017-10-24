#ifndef LP_H
#define LP_H

#define LPMAXSTRLEN 1024

typedef enum
{
	LP_CSF_L = (1 << 0), // Lowecase  : 0001
	LP_CSF_U = (1 << 1), // Uppercase : 0010
	LP_CSF_D = (1 << 2), // Digits    : 0100
	LP_CSF_S = (1 << 3), // Symbols   : 1000
} lp_csflag;

#define LP_CSF_ALL ((1 << 4) - 1)  // All flags set: 1111


typedef enum
{
	LP_COUNTER_DEF    = 1, LP_COUNTER_MIN = 1, LP_COUNTER_MAX = 0x0FFFFFFF,
	LP_LENGTH_DEF     = 16, LP_LENGTH_MIN = 5, LP_LENGTH_MAX = 35,
	LP_CSF_DEF        = LP_CSF_ALL,
} lp_options;

typedef struct lp_ctx_st LP_CTX;

typedef enum
{
	LP_ERR_VERSION = -1, // version is not 2 (internal)
	LP_ERR_KEYLEN  = -2, // keylen is not 32 (internal)
	LP_ERR_PASSLEN = -3, // passlen out of range
	LP_ERR_ITER    = -4, // iterations is not 100000 (internal)
	LP_ERR_COUNTER = -5, // counter out of range
	LP_ERR_SALTLEN = -6, // salt (site+login+counter) too long (>LPMAXSTRLEN)
	LP_ERR_SECRET  = -7, // secret too long  (>LPMAXSTRLEN)
	LP_ERR_DIGEST  = -8, // digest is not sha256 (internal)
	LP_ERR_FLAGS   = -9, // no charsets flags selected
	LP_ERR_INIT    = -10,// not initialized
	
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
int LP_get_pass(LP_CTX *ctx, const char* site,  const char* login, const char* secret, char* pass, unsigned passlen);
#endif //LP_H
