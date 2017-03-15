#ifndef LP_H
#define LP_H

#define LPMAXSTRLEN 1024

typedef enum
{
	LP_CSF_LOWERCASE    = 0x01,
	LP_CSF_UPPERCASE    = 0x02,
	LP_CSF_NUMBERIC     = 0x04,
	LP_CSF_SYMBOLS      = 0x08,
	LP_CSF_LETTERS      = 0x03,
	LP_CSF_ALPHANUMERIC = 0x07,
	LP_CSF_ALL          = 0x0F
} lp_csflag;

typedef enum
{
	LP_MD_MD5    = 0,
	LP_MD_SHA1   = 1,
	LP_MD_SHA224 = 2,
	LP_MD_SHA256 = 3,
	LP_MD_SHA384 = 4,
	LP_MD_SHA512 = 5,
	
} lp_digest;

typedef enum
{
	LP_OV_VERSION     = 2,
	LP_OV_KEYLEN      = 32    , LP_OV_KEYLEN_MAX = 128,
	LP_OV_ITER        = 100000, LP_OV_ITER_MAX = 0x100000,
	LP_OV_COUNTER     = 1,
	LP_OV_COUNTER_MAX = 0xFFFF, LP_OV_COUNTERLEN = 4,
	LP_OV_LENGTH      = 16,
	LP_OV_FLAGS       = LP_CSF_ALPHANUMERIC,
} lp_optvalues;

typedef struct lp_opts_s
{
	unsigned version;
	unsigned keylen;
	unsigned iterations;
	int digest;

	unsigned counter;
	unsigned length;
	int flags;
} lp_opts;

//extern lp_opts_t defopts;
void lp_defaultopts(lp_opts *opts);


typedef enum
{
	LP_ERR_VERSION = -1,
	LP_ERR_KEYLEN  = -2,
	LP_ERR_PASSLEN = -3,
	LP_ERR_ITER    = -4,
	LP_ERR_COUNTER = -5,
	LP_ERR_SALTLEN = -6,
	LP_ERR_SECRET  = -7,
	LP_ERR_DIGEST  = -8,
	LP_ERR_FLAGS   = -9,
	
} lp_error;

int lp_generate(const char* site,  const char* login, const char* secret, lp_opts *opts, char* pass, unsigned passlen);

#endif //LP_H