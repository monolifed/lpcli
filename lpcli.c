#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
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
		"Usage: lpcli <site> [login] [options]" "\n"
		"Options:" "\n"
		"  --lowercase, -l     include lowercase characters" "\n"
		"  --uppercase, -u     include uppercase characters" "\n"
		"  --digits, -d        include digits" "\n"
		"  --symbols, -s       include symbols" "\n"
		"\n"
		"  --length, -n        number of characters (16)" "\n"
		"  --counter, -c       number to add to salt (1)" "\n"
		"\n"
		"  --print, -p         print instead of copying to clipboard." "\n"
		"                      xclip is required to copy to clipboard on linux." "\n"
	);
	fflush(stderr);
	return LPCLI_FAIL;
}

int print_error(const char *format, ...)
{
	fputs("Error: ", stderr);
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fflush(stderr);
	
	return LPCLI_FAIL;
}

typedef struct parsed_args
{
	const char *site;
	const char *login;
	const char *password;
	int length;
	int counter;
	unsigned flags;
} LPCLI_OPTS;

//option flags
enum
{
	OPTS_CSF_LOWERCASE = LP_CSF_LOWERCASE,
	OPTS_CSF_UPPERCASE = LP_CSF_UPPERCASE,
	OPTS_CSF_DIGITS    = LP_CSF_DIGITS,
	OPTS_CSF_SYMBOLS   = LP_CSF_SYMBOLS,
	OPTS_LENGTH    = (1 << (LP_NUM_CHARSETS + 0)),
	OPTS_COUNTER   = (1 << (LP_NUM_CHARSETS + 1)),
	OPTS_PRINT     = (1 << (LP_NUM_CHARSETS + 2)),
	//OPTS_PASSWORD  = (1 << (LP_NUM_CHARSETS + 3))
};

static bool is_option_set(LPCLI_OPTS *opts, int flag)
{
	return (opts->flags & flag) ? true : false;
}

static void set_option(LPCLI_OPTS *opts, int flag)
{
	if (opts->flags & flag)
		return;
	opts->flags |= flag;
}

static int read_args(int argc, char **argv, LPCLI_OPTS *opts)
{
	if (argc < 2)
		return LPCLI_FAIL;
	int i = 0;
	char *ptr;
	char *ptrEnd;
	ptr = argv[++i];
	opts->site = ptr;
	ptr = argv[++i]; // next
	
	opts->login = "";
	if (ptr && *ptr != '-')
	{
		opts->login = ptr;
		ptr = argv[++i]; // next
	}
	
	//if (ptr && *ptr != '-')
	//{
	//	opts->password = ptr;
	//	set_option(opts, OPTS_PASSWORD);
	//	ptr = argv[++i]; // next
	//}
	
	bool opt_open = false;
	
	while (argv[i] != NULL)
	{
		if (!opt_open)
		{
			if (*ptr != '-')
				return LPCLI_FAIL;
			ptr++;
		}
		
		switch (*ptr)
		{
		case '\0': // -
			if (!opt_open)
			{
				return LPCLI_FAIL;
			}
			opt_open = true;
			ptr = argv[++i];
			break;
		case '-': // --
			if (opt_open)
				return LPCLI_FAIL;
			ptr++;
			if (strcmp(ptr, "lowercase") == 0)
			{
				set_option(opts, OPTS_CSF_LOWERCASE);
			}
			else if (strcmp(ptr, "uppercase") == 0)
			{
				set_option(opts, OPTS_CSF_UPPERCASE);
			}
			else if (strcmp(ptr, "digits") == 0)
			{
				set_option(opts, OPTS_CSF_DIGITS);
			}
			else if (strcmp(ptr, "symbols") == 0)
			{
				set_option(opts, OPTS_CSF_SYMBOLS);
			}
			else if (strcmp(ptr, "print") == 0)
			{
				set_option(opts, OPTS_PRINT);
			}
			else if (strcmp(ptr, "length") == 0)
			{
				ptr = argv[++i];
				if (ptr == NULL)
					return LPCLI_FAIL;
				opts->length = strtol(ptr, &ptrEnd, 10);
				if (*ptrEnd != '\0')
					return LPCLI_FAIL;
				set_option(opts, OPTS_LENGTH);
			}
			else if (strcmp(ptr, "counter") == 0)
			{
				ptr = argv[++i];
				if (ptr == NULL)
					return LPCLI_FAIL;
				opts->counter = strtol(ptr, &ptrEnd, 10);
				if (*ptrEnd != '\0')
					return LPCLI_FAIL;
				set_option(opts, OPTS_COUNTER);
			}
			else
			{
				return LPCLI_FAIL;
			}
			ptr = argv[++i];
			break;
		case 'n':
			ptr++;
			if (*ptr == '\0')
			{
				ptr = argv[++i];
				if (ptr == NULL)
					return LPCLI_FAIL;
			}
			opts->length = strtol(ptr, &ptrEnd, 10);
			//if(*ptrEnd != '\0')
			//	return 1;
			set_option(opts, OPTS_LENGTH);
			ptr = ptrEnd;
			opt_open = true;
			//ptr = argv[++i];
			//opt_open = 0;
			break;
		case 'c':
			ptr++;
			if (*ptr == '\0')
			{
				ptr = argv[++i];
				if (ptr == NULL)
					return LPCLI_FAIL;
			}
			opts->counter = strtol(ptr, &ptrEnd, 10);
			//if(*ptrEnd != '\0')
			//	return 1;
			set_option(opts, OPTS_COUNTER);
			ptr = ptrEnd;
			opt_open = true;
			//ptr = argv[++i];
			//opt_open = 0;
			break;
		case 'l':
			set_option(opts, OPTS_CSF_LOWERCASE);
			ptr++;
			opt_open = true;
			break;
		case 'u':
			set_option(opts, OPTS_CSF_UPPERCASE);
			ptr++;
			opt_open = true;
			break;
		case 'd':
			set_option(opts, OPTS_CSF_DIGITS);
			ptr++;
			opt_open = true;
			break;
		case 's':
			set_option(opts, OPTS_CSF_SYMBOLS);
			ptr++;
			opt_open = true;
			break;
		case 'p':
			set_option(opts, OPTS_PRINT);
			ptr++;
			opt_open = true;
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
	if (t->flags & OPTS_CSF_LOWERCASE)
		printf("l");
	if (t->flags & OPTS_CSF_UPPERCASE)
		printf("u");
	if (t->flags & OPTS_CSF_DIGITS)
		printf("d");
	if (t->flags & OPTS_CSF_SYMBOLS)
		printf("s");
	printf("c%u", t->counter);
	printf("n%u", t->length);
	printf("\n");
}

void zeromem(void *, size_t);

int lpcli_main(int argc, char **argv)
{
	if (argc == 1 || (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)))
	{
		return print_usage();
	}
	
	LPCLI_OPTS options = {0};
	if (read_args(argc, argv, &options) != LPCLI_OK)
	{
		return print_error(errstr[ERR_unrecognized_options]);
	}
	
	LP_CTX *ctx = LP_CTX_new();
	
	unsigned temp;
	unsigned charset = options.flags & LP_CSF_ALL;
	if (charset)
	{
		temp = LP_set_charset(ctx, charset);
		if (temp != charset)
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_cannot_set_to], "charset flags", charset);
		}
	}
	else
	{
		charset = LP_set_charset(ctx, 0);
		options.flags |= charset;
	}
	
	if (is_option_set(&options, OPTS_LENGTH))
	{
		temp = LP_set_length(ctx, options.length);
		if (temp != (unsigned) options.length)
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_cannot_set_to], "length", options.length);
		}
	}
	else
	{
		options.length = LP_set_length(ctx, 0);
	}
	
	if (is_option_set(&options, OPTS_COUNTER))
	{
		temp = LP_set_counter(ctx, options.counter);
		if (temp != (unsigned) options.counter)
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
	
	print_options(&options);
	
	//if (!is_option_set(&options, OPTS_PASSWORD))
	{
	
		char passwd_in[LPMAXSTRLEN];
		if (lpcli_readpassword("Enter Password: ", passwd_in, sizeof passwd_in) != LPCLI_OK)
		{
			LP_CTX_free(ctx);
			return print_error(errstr[ERR_read_password]);
		}
		LP_generate(ctx, options.site, options.login, (const char *) passwd_in, genpass, sizeof genpass);
		zeromem(passwd_in, sizeof passwd_in); // clean password read
	}
	//else
	//{
	//	LP_generate(ctx, options.site, options.login, options.password, genpass, sizeof genpass);
	//}
	
	bool clipboardcopy = is_option_set(&options, OPTS_PRINT) ? false : true;
	zeromem(&options, sizeof options); // clean options
	
	LP_CTX_free(ctx);
	
	if (clipboardcopy)
	{
		if (lpcli_clipboardcopy(genpass) != LPCLI_OK)
			return print_error(errstr[ERR_clipboard]);
	}
	else
	{
		printf("%s\n", genpass);
	}
	
	zeromem(&genpass, sizeof genpass); // clean generated password
	return LPCLI_OK;
}
