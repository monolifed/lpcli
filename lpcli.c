#ifndef _WIN32
	#ifndef _XOPEN_SOURCE
	#define _XOPEN_SOURCE
	#endif
	#include <termios.h>
#endif
#include <stdio.h>
#include <stdarg.h>
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

int print_error(const char * format, ...)
{
	fputs("Error: ", stderr);
	va_list args;
	va_start (args, format);
	vfprintf (stderr, format, args);
	va_end (args);
	fflush(stderr);
	
	return 1;
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
		return 1;
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
				return 1;
			ptr++;
		}
		
		switch(*ptr)
		{
			case '\0': // -
				if(!opt_open)
				{
					return 1;
				}
				opt_open = 0;
				ptr = argv[++i];
				break;
			case '-': // --
				if(opt_open)
					return 1;
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
						return 1;
					length = strtol(ptr, &ptrEnd, 10);
					if(*ptrEnd != '\0')
						return 1;
					OPTSET(LENGTH);
				}
				else if(strcmp(ptr, "counter") == 0)
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return 1;
					counter = strtol(ptr, &ptrEnd, 10);
					if(*ptrEnd != '\0')
						return 1;
					OPTSET(COUNTER);
				}
				else
				{
					return 1;
				}
				ptr = argv[++i];
				break;
			case 'L':
				ptr++;
				if(*ptr == '\0')
				{
					ptr = argv[++i];
					if(ptr == NULL)
						return 1;
				}
				length = strtol(ptr, &ptrEnd, 10);
				//if(*ptrEnd != '\0')
				//	return 1;
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
						return 1;
				}
				counter = strtol(ptr, &ptrEnd, 10);
				//if(*ptrEnd != '\0')
				//	return 1;
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
				return 1;
		}
	}
	return 0;
}
#undef TOUCH


//FILE *popen(const char *command, const char *type);
//int pclose(FILE *stream);
void copy_to_clipboard(const char *text)
{
	FILE *pout = popen("xclip -selection clipboard -quiet -loop 1", "w");
	if(!pout)
	{
		fprintf(stderr, "Cannot copy to clipboard\n");
		fflush(stderr);
		return;
	}
	fprintf(pout, text);
	fflush(pout);
	pclose(pout);
}

int read_password(const char *prompt, char *out, size_t outl)
{
	printf(prompt);
	static struct termios told, tnew;
	tcgetattr(0, &told);
	tnew = told;
	tnew.c_lflag &= ~ICANON;
	tnew.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &tnew);
	
	out = fgets(out, outl, stdin);
	tcsetattr(0, TCSANOW, &told);
	
	if(out)
	{
		out[strcspn(out, "\r\n")] = 0;
		return 0;
	}
	return 1;
}

#define ISOPTSET(X) (changes & CMDLINE_##X)

void print_options(unsigned cs, unsigned ct, unsigned l)
{
	printf("Options: -");
	if(cs & LP_CSF_LOWERCASE)
		printf("u");
	if(cs & LP_CSF_UPPERCASE)
		printf("l");
	if(cs & LP_CSF_DIGITS)
		printf("d");
	if(cs & LP_CSF_SYMBOLS)
		printf("s");
	printf("c%u", ct);
	printf("L%u", l);
	printf("\n");
}

int main(int argc, const char **argv)
{
	int ret = read_args(argc, argv);
	if(ret)
	{
		return print_error("Unknown options specified\n");
	}
	
	unsigned temp;
	if(ISOPTSET(CSETINC) && ISOPTSET(CSETEXC))
	{
		return print_error("Exclusion options cannot be used with inclusion options\n");
	}

	LP_CTX *ctx = LP_CTX_new();
	
	unsigned charset;
	if(ISOPTSET(CSETINC))
	{
		temp = LP_set_charsets(ctx, charset_in);
		if(temp != charset_in)
		{
			LP_CTX_free(ctx);
			return print_error("Cannot set invalid charset value %u\n", charset_in);
		}
		charset = charset_in;
	}
	else if(ISOPTSET(CSETEXC))
	{
		temp = LP_set_charsets(ctx, charset_ex);
		if(temp != charset_ex)
		{
			LP_CTX_free(ctx);
			return print_error("Cannot set invalid charset value %u\n", charset_ex);
		}
		charset = charset_ex;
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
			LP_CTX_free(ctx);
			return print_error("Cannot set invalid length value %u\n", length);
		}
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
			LP_CTX_free(ctx);
			return print_error("Cannot set invalid counter value %u\n", counter);
		}
	}
	else
	{
		counter = LP_set_counter(ctx, 0);
	}
	
	char genpass[length + 1];
	genpass[length] = 0;
	
	print_options(charset, counter, length);
	
	if(!ISOPTSET(PASSWORD))
	{

		char passwd_in[1024];
		if(read_password("Password: ", passwd_in, sizeof passwd_in))
		{
			LP_CTX_free(ctx);
			return print_error("Cannot read password\n");
		}
		LP_get_pass(ctx, site, login, (const char *) passwd_in, genpass, sizeof genpass);
	}
	else
	{
		LP_get_pass(ctx, site, login, password, genpass, sizeof genpass);
	}
	
	LP_CTX_free(ctx);
	
	if(ISOPTSET(CLIPBOARD))
	{
		copy_to_clipboard(genpass);
	}
	else
	{
		printf("%s\n", genpass);
	}
	
	
	return 0;
}