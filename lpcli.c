/* HGvqQQSDvF7YlA2S */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lp.h"

void print_usage(void)
{
	fprintf(stderr,
	"Usage: lesspass <site> <login> [options] \n"
	"Options: \n"
	"  -l                  add lowercase in password \n"
	"  -u                  add uppercase in password \n"
	"  -d                  add digits in password \n"
	"  -s                  add symbols in password \n"
	"\n"
	"  --no-lowercase      remove lowercase from password \n"
	"  --no-uppercase      remove uppercase from password \n"
	"  --no-digits         remove digits from password \n"
	"  --no-symbols        remove symbols from password \n"
	"\n"
	"  --length, -L        int (default 16) \n"
	"  --counter, -c       int (default 1) \n"
	"\n"
	"  --clipboard, -C     copy to clipboard instead of displaying it. \n"
	"                      xclip (Linux) or clip (Windows) is required.\n"
	);
	fflush(stderr);
}

const char *site, *login, *password;
unsigned charset_in = 0, charset_ex = LP_CSF_ALL;
unsigned length = 0, counter = 0;

enum
{
	CMDLINE_CSETINC   = 0x01, // inclusive
	CMDLINE_CSETEXC   = 0x02, // exclusive
	CMDLINE_LENGTH    = 0x04,
	CMDLINE_COUNTER   = 0x08,
	CMDLINE_PASSWORD  = 0x10,
	CMDLINE_CLIPBOARD = 0x20
};

unsigned changes = 0;
#define OPTSET(X) (changes |= CMDLINE_##X)

int read_args(int argc, const char **argv)
{
	if(argc < 3)
		return 0;
	int i = 0;
	const char *ptr;
	char *ptrEnd;
	ptr = argv[++i];
	site = ptr;
	ptr = argv[++i];
	login = ptr;
	
	ptr = argv[++i];
	
	if(ptr && *ptr != '-')
	{
		password = ptr;
		OPTSET(PASSWORD);
		ptr = argv[++i];
	}
	
	int opt_open = 0;

	while(argv[i] != NULL)
	{
		if(!opt_open)
		{
			if(*ptr != '-')
				return 0;
			ptr++;
		}
		
		switch(*ptr)
		{
			case '\0': // -
				if(!opt_open)
				{
					return 0;
				}
				opt_open = 0;
				ptr = argv[++i];
				break;
			case '-': // --
				if(opt_open)
					return 0;
				ptr++;
				if(strcmp(ptr, "no-lowercase") == 0)
				{
					charset_ex &= ~ LP_CSF_LOWERCASE;
					OPTSET(CSETEXC);
				}
				else if(strcmp(ptr, "no-uppercase") == 0)
				{
					charset_ex &= ~ LP_CSF_UPPERCASE;
					OPTSET(CSETEXC);
				}
				else if(strcmp(ptr, "no-digits") == 0)
				{
					charset_ex &= ~ LP_CSF_DIGITS;
					OPTSET(CSETEXC);
				}
				else if(strcmp(ptr, "no-symbols") == 0)
				{
					charset_ex &= ~ LP_CSF_SYMBOLS;
					OPTSET(CSETEXC);
				}
				else if(strcmp(ptr, "clipboard") == 0)
				{
					OPTSET(CLIPBOARD);
				}
				else if(strcmp(ptr, "length") == 0)
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return 0;
					length = strtol(ptr, &ptrEnd, 10);
					if(*ptrEnd != '\0')
						return 0;
					OPTSET(LENGTH);
				}
				else if(strcmp(ptr, "counter") == 0)
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return 0;
					counter = strtol(ptr, &ptrEnd, 10);
					if(*ptrEnd != '\0')
						return 0;
					OPTSET(COUNTER);
				}
				else
				{
					return 0;
				}
				ptr = argv[++i];
				break;
			case 'L':
				ptr++;
				if(*ptr == '\0')
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return 0;
				}
				length = strtol(ptr, &ptrEnd, 10);
				//if(*ptrEnd != '\0')
				//	return 0;
				OPTSET(LENGTH);
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
						return 0;
				}
				counter = strtol(ptr, &ptrEnd, 10);
				//if(*ptrEnd != '\0')
				//	return 0;
				OPTSET(COUNTER);
				ptr = (const char*) ptrEnd; opt_open = 1;
				//ptr = argv[++i];
				//opt_open = 0;
				break;
			case 'l':
				charset_in |= LP_CSF_LOWERCASE;
				OPTSET(CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 'u':
				charset_in |= LP_CSF_UPPERCASE;
				OPTSET(CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 'd':
				charset_in |= LP_CSF_DIGITS;
				OPTSET(CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 's':
				charset_in |= LP_CSF_SYMBOLS;
				OPTSET(CSETINC);
				ptr++;
				opt_open = 1;
				break;
			case 'C':
				OPTSET(CLIPBOARD);
				ptr++;
				opt_open = 1;
				break;
			default:
				return 0;
		}
	}
	return 1;
}
#undef TOUCH

#define ISOPTSET(X) (changes & CMDLINE_##X)


int main(int argc, const char **argv)
{
	int ret = read_args(argc, argv);
	if(!ret)
	{
		fprintf(stderr, "Unknown options specified\n");
		fflush(stderr);
		return 1;
	}
	
	LP_CTX *ctx = LP_CTX_new();
	unsigned temp;
	if(ISOPTSET(CSETINC) && ISOPTSET(CSETEXC))
	{
		fprintf(stderr, "Exclusion options cannot be used with inclusion options\n");
		fflush(stderr);
		return 1;
	}
	
	unsigned charset;
	if(ISOPTSET(CSETINC))
	{
		temp = LP_set_charsets(ctx, charset_in);
		if(temp != charset_in)
		{
			fprintf(stderr, "Cannot set invalid charset value\n");
			fflush(stderr);
			return 1;
		}
		charset = charset_in;
		//fprintf(stderr, "char set to %u in options\n", charset_in);
		//fflush(stderr);
	}
	else if(ISOPTSET(CSETEXC))
	{
		temp = LP_set_charsets(ctx, charset_ex);
		if(temp != charset_ex)
		{
			fprintf(stderr, "Cannot set invalid charset value\n");
			fflush(stderr);
			return 1;
		}
		charset = charset_ex;
		//fprintf(stderr, "nchar set to %u in options\n", charset_ex);
		//fflush(stderr);
	}
	else
	{
		charset = LP_set_charsets(ctx, 0);
	}
	
	if(ISOPTSET(LENGTH))
	{
		temp = LP_set_length(ctx, length);
		if(temp != length)
		{
			fprintf(stderr, "Cannot set invalid length value\n");
			fflush(stderr);
			return 1;
		}
		//fprintf(stderr, "length set to %u in options\n", length);
		//fflush(stderr);
		//length = temp;
	}
	else
	{
		length = LP_set_length(ctx, 0);
	}
	
	if(ISOPTSET(COUNTER))
	{
		temp = LP_set_counter(ctx, counter);
		if(temp != counter)
		{
			fprintf(stderr, "Cannot set invalid counter value\n");
			fflush(stderr);
			return 1;
		}
		//fprintf(stderr, "counter set to %u in options\n", counter);
		//fflush(stderr);
		//counter = temp;
	}
	else
	{
		counter = LP_set_counter(ctx, 0);
	}
	
	if(!ISOPTSET(PASSWORD))
	{
		fprintf(stderr, "Currently password must be specified in the commandline\n");
		fflush(stderr);
		return 1;
	}
	if(ISOPTSET(CLIPBOARD))
	{
		fprintf(stderr, "Currently clipboard is not supported\n");
		fflush(stderr);
	}
	
	
	char genpass[length + 1];
	genpass[length] = 0;
	LP_get_pass(ctx, site, login, password, genpass, sizeof genpass);
	printf("%s\n", genpass);
	LP_CTX_free(ctx);
	return 0;
}
