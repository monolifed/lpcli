#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "lp.h"
#include "lpcli.h"

#define ERRORS_X \
	X(none, "Not an error") \
	X(unrecognized_options, "Unrecognized or incorrect options specified") \
	X(cannot_set_to, "Cannot set %s value to %i") \
	X(clipboard, "Cannot copy to clipboard") \
	X(read_password, "Failed to read the password") \
	X(inc_exc ,"Character set inclusion and exclusion options cannot be used together") \

// ERR_XXX
#define X(A, B) ERR_##A,
enum
{
	ERRORS_X
};
#undef X

// "XXX\n"
#define X(A, B) B "\n",
static const char *errstr[] =
{
	ERRORS_X
};
#undef X

#undef ERRORS_X

int print_usage(void)
{
	fprintf(stderr,
	"Usage: lpcli <site> <login> [options]" "\n"
	"Options:" "\n"
	"  -l                  add lowercase in password" "\n"
	"  -u                  add uppercase in password" "\n"
	"  -d                  add digits in password" "\n"
	"  -s                  add symbols in password" "\n"
	"\n"
	"  --no-lowercase      remove lowercase from password" "\n"
	"  --no-uppercase      remove uppercase from password" "\n"
	"  --no-digits         remove digits from password" "\n"
	"  --no-symbols        remove symbols from password" "\n"
	"\n"
	"  --length, -L        int (default 16)" "\n"
	"  --counter, -c       int (default 1)" "\n"
	"\n"
	"  --clipboard, -C     copy to clipboard instead of displaying it." "\n"
	"                      xclip (Linux) or clip (Windows) is required." "\n"
	);
	fflush(stderr);
	return LPCLI_FAIL;
}

int print_error(const char * format, ...)
{
	fputs("Error: ", stderr);
	va_list args;
	va_start (args, format);
	vfprintf (stderr, format, args);
	va_end (args);
	fflush(stderr);
	
	return LPCLI_FAIL;
}

typedef struct parsed_args
{
	const char *site;
	const char *login;
	const char *password;
	unsigned charset[2]; // inclusive, exclusive
	int length;
	int counter;
	unsigned changed;
} LPCLI_OPTS;

//option flags
enum
{
	OPTS_CSETINC   = (1 << 0), // inclusive
	OPTS_CSETEXC   = (1 << 1), // exclusive
	OPTS_LENGTH    = (1 << 2),
	OPTS_COUNTER   = (1 << 3),
	OPTS_PASSWORD  = (1 << 4),
	OPTS_CLIPBOARD = (1 << 5)
};

static int is_option_set(LPCLI_OPTS *opts, int flag)
{
	return (opts->changed & flag) ? 1 : 0;
}

static void set_option(LPCLI_OPTS *opts, int flag)
{
	if(opts->changed & flag)
		return;
	opts->changed |= flag;
}

static int read_args(int argc, const char **argv, LPCLI_OPTS *opts)
{
	if(argc < 3)
		return LPCLI_FAIL;
	int i = 0;
	const char *ptr;
	char *ptrEnd;
	ptr = argv[++i];
	opts->site = ptr;
	ptr = argv[++i];
	opts->login = ptr;
	
	ptr = argv[++i];
	
	if(ptr && *ptr != '-')
	{
		opts->password = ptr;
		set_option(opts, OPTS_PASSWORD);
		ptr = argv[++i];
	}
	
	int opt_open = 0;

	while(argv[i] != NULL)
	{
		if(!opt_open)
		{
			if(*ptr != '-')
				return LPCLI_FAIL;
			ptr++;
		}
		
		switch(*ptr)
		{
			case '\0': // -
				if(!opt_open)
				{
					return LPCLI_FAIL;
				}
				opt_open = 0;
				ptr = argv[++i];
				break;
			case '-': // --
				if(opt_open)
					return LPCLI_FAIL;
				ptr++;
				if(strcmp(ptr, "no-lowercase") == 0)
				{
					opts->charset[1] |= LP_CSF_LOWERCASE;
					set_option(opts, OPTS_CSETEXC);
				}
				else if(strcmp(ptr, "no-uppercase") == 0)
				{
					opts->charset[1] |= LP_CSF_UPPERCASE;
					set_option(opts, OPTS_CSETEXC);
				}
				else if(strcmp(ptr, "no-digits") == 0)
				{
					opts->charset[1] |= LP_CSF_DIGITS;
					set_option(opts, OPTS_CSETEXC);
				}
				else if(strcmp(ptr, "no-symbols") == 0)
				{
					opts->charset[1] |= LP_CSF_SYMBOLS;
					set_option(opts, OPTS_CSETEXC);
				}
				else if(strcmp(ptr, "clipboard") == 0)
				{
					set_option(opts, OPTS_CLIPBOARD);
				}
				else if(strcmp(ptr, "length") == 0)
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return LPCLI_FAIL;
					opts->length = strtol(ptr, &ptrEnd, 10);
					if(*ptrEnd != '\0')
						return LPCLI_FAIL;
					set_option(opts, OPTS_LENGTH);
				}
				else if(strcmp(ptr, "counter") == 0)
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return LPCLI_FAIL;
					opts->counter = strtol(ptr, &ptrEnd, 10);
					if(*ptrEnd != '\0')
						return LPCLI_FAIL;
					set_option(opts, OPTS_COUNTER);
				}
				else
				{
					return LPCLI_FAIL;
				}
				ptr = argv[++i];
				break;
			case 'L':
				ptr++;
				if(*ptr == '\0')
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return LPCLI_FAIL;
				}
				opts->length = strtol(ptr, &ptrEnd, 10);
				//if(*ptrEnd != '\0')
				//	return 1;
				set_option(opts, OPTS_LENGTH);
				ptr = (const char*) ptrEnd;  opt_open = 1;
				//ptr = argv[++i];
				//opt_open = 0;
				break;
			case 'c':
				ptr++;
				if(*ptr == '\0')
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return LPCLI_FAIL;
				}
				opts->counter = strtol(ptr, &ptrEnd, 10);
				//if(*ptrEnd != '\0')
				//	return 1;
				set_option(opts, OPTS_COUNTER);
				ptr = (const char*) ptrEnd; opt_open = 1;
				//ptr = argv[++i];
				//opt_open = 0;
				break;
			case 'l':
				opts->charset[0] |= LP_CSF_LOWERCASE;
				set_option(opts, OPTS_CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 'u':
				opts->charset[0] |= LP_CSF_UPPERCASE;
				set_option(opts, OPTS_CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 'd':
				opts->charset[0] |= LP_CSF_DIGITS;
				set_option(opts, OPTS_CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 's':
				opts->charset[0] |= LP_CSF_SYMBOLS;
				set_option(opts, OPTS_CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 'C':
				set_option(opts, OPTS_CLIPBOARD);
				ptr++;
				opt_open = 1;
				break;
			default:
				return LPCLI_FAIL;
		}
	}
	return LPCLI_OK;
}

void print_options(LPCLI_OPTS *t)
{
	printf("Options: -");
	if(t->charset[0] & LP_CSF_LOWERCASE)
		printf("l");
	if(t->charset[0] & LP_CSF_UPPERCASE)
		printf("u");
	if(t->charset[0] & LP_CSF_DIGITS)
		printf("d");
	if(t->charset[0] & LP_CSF_SYMBOLS)
		printf("s");
	printf("c%u", t->counter);
	printf("L%u", t->length);
	printf("\n");
}

int lpcli_main(int argc, const char **argv)
{
	if(argc == 1 || (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)))
	{
		return print_usage();
	}
	
	LPCLI_OPTS options = {0};
	if(read_args(argc, argv, &options) != LPCLI_OK)
	{
		return print_error(errstr[ERR_unrecognized_options]);
	}
	
	unsigned temp;
	if(is_option_set(&options, OPTS_CSETINC) && is_option_set(&options, OPTS_CSETEXC))
	{
		return print_error(errstr[ERR_inc_exc]);
	}

	LP_CTX *ctx = LP_CTX_new();
	
	if(is_option_set(&options, OPTS_CSETINC)) // this should never happen
	{
		temp = LP_set_charsets(ctx, options.charset[0]);
		if(temp != options.charset[0])
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_cannot_set_to], "inclusive charset flags", options.charset[0]);
		}
		options.charset[0] = temp;
	}
	else if(is_option_set(&options, OPTS_CSETEXC))
	{
		options.charset[1] = LP_CSF_ALL & ~options.charset[1];
		temp = LP_set_charsets(ctx, options.charset[1]);
		if(temp != options.charset[1])
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_cannot_set_to], "exclusive charset flags", options.charset[1]);
		}
		options.charset[0] = temp;
	}
	else
	{
		options.charset[0] = LP_set_charsets(ctx, 0);
	}
	
	if(is_option_set(&options, OPTS_LENGTH))
	{
		temp = LP_set_length(ctx, options.length);
		if(temp != (unsigned) options.length)
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_cannot_set_to], "length", options.length);
		}
	}
	else
	{
		options.length = LP_set_length(ctx, 0);
	}
	
	if(is_option_set(&options, OPTS_COUNTER))
	{
		temp = LP_set_counter(ctx, options.counter);
		if(temp != (unsigned) options.counter)
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_cannot_set_to], "counter", options.counter);
		}
	}
	else
	{
		options.counter = LP_set_counter(ctx, 0);
	}
	
	char genpass[options.length + 1];
	genpass[options.length] = 0;
	
	//print_options(&options);
	
	if(!is_option_set(&options, OPTS_PASSWORD))
	{

		char passwd_in[LPMAXSTRLEN];
		if(lpcli_readpassword("Enter Password: ", passwd_in, sizeof passwd_in) != LPCLI_OK)
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_read_password]);
		}
		LP_generate(ctx, options.site, options.login, (const char *) passwd_in, genpass, sizeof genpass);
		lpcli_zeromemory(passwd_in, sizeof passwd_in); // clean password read
	}
	else
	{
		LP_generate(ctx, options.site, options.login, options.password, genpass, sizeof genpass);
	}
	
	lpcli_zeromemory(&options, sizeof options); // clean options
	
	LP_CTX_free(ctx);
	
	if(is_option_set(&options, OPTS_CLIPBOARD))
	{
		if(lpcli_clipboardcopy(genpass) != LPCLI_OK)
			return print_error(errstr[ERR_clipboard]);
	}
	else
	{
		printf("%s\n", genpass);
	}
	
	lpcli_zeromemory(&genpass, sizeof genpass); // clean generated password
	return LPCLI_OK;
}
