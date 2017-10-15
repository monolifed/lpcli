#ifndef LP_H
#define LP_H

#define LPMAXSTRLEN 1024

typedef enum
{
	LP_CSF_LOWERCASE    = 0x01, //L
	LP_CSF_UPPERCASE    = 0x02, //U
	LP_CSF_DIGITS       = 0x04, //D
	LP_CSF_SYMBOLS      = 0x08, //S
	LP_CSF_LETTERS      = 0x03, //L|U
	LP_CSF_ALPHANUMERIC = 0x07, //L|U|D
	LP_CSF_ALL          = 0x0F  //L|U|D|S
} lp_csflag;


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
	LP_ERR_SALTLEN = -6, // salt too long (>LPMAXSTRLEN)
	LP_ERR_SECRET  = -7, // secret too long  (>LPMAXSTRLEN)
	LP_ERR_DIGEST  = -8, // digest is not sha256 (internal)
	LP_ERR_FLAGS   = -9, // no charsets flags selected
	
} lp_error;

LP_CTX* LP_CTX_new(void);
void LP_CTX_free(LP_CTX *opts);

// Sets the value if valid, returns to current value
// Something like ret = LP_set_xxx(ctx, 0); is a getter (since 0 is invalid for all three)
unsigned LP_set_counter(LP_CTX *ctx, unsigned);
unsigned LP_set_length(LP_CTX *ctx, unsigned);
unsigned LP_set_charsets(LP_CTX *ctx, unsigned);

int LP_get_pass(LP_CTX *ctx, const char* site,  const char* login, const char* secret, char* pass, unsigned passlen);
#endif //LP_H