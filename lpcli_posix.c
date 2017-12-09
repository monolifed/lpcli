#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#include <termios.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

#include "lpcli.h"

typedef void *(*lpcli_memset_f)(void *, int, size_t);
static volatile lpcli_memset_f lpcli_memset = memset;
void *lpcli_zeromemory(void *dst, size_t dstlen)
{
	return lpcli_memset(dst, 0, dstlen);
}

int lpcli_clipboardcopy(const char *text)
{
	FILE *pout = popen("xclip -selection clipboard -quiet -loop 1", "w");
	if (!pout)
	{
		return LPCLI_FAIL;
	}
	fprintf(pout, "%s", text);
	fflush(pout);
	pclose(pout);
	
	return LPCLI_OK;
}

#if __WCHAR_MAX__ <= 0xFFFF && __WCHAR_MAX__ >=0x0100
#define UTF16_MODE
#endif

#ifdef UTF16_MODE
#define SP_HI_START 0xD800
#define SP_HI_END   0xDBFF
#define SP_LO_START 0xDC00
#define SP_LO_END   0xDFFF
unsigned long sp_to_uni(wchar_t hi, wchar_t lo)
{
	if (hi < SP_HI_START || hi > SP_HI_END)
		return 0;
	if (lo < SP_LO_START || hi > SP_LO_END)
		return 0;
	return ((hi - SP_HI_START) << 10) + (lo - SP_LO_START) + 0x10000;
}
#endif //UTF16_MODE

#define UTF8_1 0x007FUL
#define UTF8_2 0x07FFUL
#define UTF8_3 0xFFFFUL
#define UTF8_4 0x10FFFFUL
static int uni_to_utf8(unsigned long uc, unsigned char *utf8)
{
	if (uc <= UTF8_1)
	{
		utf8[0] = uc;
		return 1;
	}
	if (uc <= UTF8_2)
	{
		utf8[0] = 0xC0 | ((uc >> 6) & 0x1F);
		utf8[1] = 0x80 | ((uc >> 0) & 0x3F);
		return 2;
	}
	if (uc <= UTF8_3)
	{
#ifdef UTF16_MODE
		if (uc >= SP_HI_START && uc <= SP_LO_END)
		{
			return -1;
		}
#endif //UTF16_MODE
		utf8[0] = 0xE0 | ((uc >> 12) & 0x0F);
		utf8[1] = 0x80 | ((uc >>  6) & 0x3F);
		utf8[2] = 0x80 | ((uc >>  0) & 0x3F);
		return 3;
	}
	if (uc <= UTF8_4)
	{
		utf8[0] = 0xF0 | ((uc >> 18) & 0x07);
		utf8[1] = 0x80 | ((uc >> 12) & 0x3F);
		utf8[2] = 0x80 | ((uc >>  6) & 0x3F);
		utf8[3] = 0x80 | ((uc >>  0) & 0x3F);
		return 4;
	}
	return 0;
}

static int uni_utf8_len(unsigned long uc)
{
	if (uc <= UTF8_1)
	{
		return 1;
	}
	if (uc <= UTF8_2)
	{
		return 2;
	}
	if (uc <= UTF8_3)
	{
#ifdef UTF16_MODE
		if (uc >= SP_HI_START && uc <= SP_LO_END)
		{
			return -1;
		}
#endif //UTF16_MODE
		return 3;
	}
	if (uc <= UTF8_4)
	{
		return 4;
	}
	return 0;
}

static size_t wcs_utf8_len(const wchar_t *wcs, size_t wlen)
{
	unsigned i;
	int len;
	size_t tlen = 0;
	for (i = 0; i < wlen; i++)
	{
		len = uni_utf8_len(wcs[i]);
		if (len == 0)
			return 0;
#ifdef UTF16_MODE
		if (len == -1)
		{
			i++;
			if (i >= wlen)
				return 0;
			unsigned long uc = sp_to_uni(wcs[i - 1], wcs[i]);
			if (uc == 0)
				return 0;
			len = uni_utf8_len(uc);
		}
#endif //UTF16_MODE
		tlen += len;
	}
	return tlen;
}

static int wcs_to_utf8(const wchar_t *wcs, size_t wlen, unsigned char *u8, size_t u8len)
{
	if (wlen == 0)
		return 0;
	size_t tlen = wcs_utf8_len(wcs, wlen);
	if (tlen == 0 || u8len < tlen)
		return -1;
	//unsigned char buffer[tlen];
	//unsigned char *p = buffer;
	unsigned char *p = u8;
	unsigned i;
	int len;
	for (i = 0; i < wlen; i++)
	{
		len = uni_to_utf8(wcs[i], p);
		//if(len == 0) // redundant
		//	return 0;
#ifdef UTF16_MODE
		if (len == -1)
		{
			i++;
			//if(i >= wlen) // redundant
			//	return 0;
			unsigned long uc = sp_to_uni(wcs[i - 1], wcs[i]);
			//if(uc == 0) // redundant
			//	return 0;
			len = uni_to_utf8(uc, p);
		}
#endif //UTF16_MODE
		p += len;
	}
	//memcpy(u8, buffer, tlen);
	return tlen;
}

// read as wchar convert to utf8
int lpcli_readpassword_u8(char *out, size_t outl)
{
	wchar_t input[MAX_INPUTWCS];
	wchar_t *wp = fgetws(input, MAX_INPUTWCS, stdin);
	if (wp == NULL)
		return LPCLI_FAIL;
	int len = wcscspn(input, L"\r\n");
	if (len == 0)
		return LPCLI_FAIL;
	len = wcs_to_utf8(input, len, (unsigned char *) out, outl - 1);
	lpcli_zeromemory(input, sizeof input);
	if (len <= 0)
	{
		return LPCLI_FAIL;
	}
	out[len] = 0;
	return LPCLI_OK;
}

// read directly, no conversion
int lpcli_readpassword_nc(char *out, size_t outl)
{
	out = fgets(out, outl, stdin);
	if (out == NULL)
		return LPCLI_FAIL;
	int len = strcspn(out, "\r\n");
	if (len == 0)
		return LPCLI_FAIL;
	out[len] = 0;
	return LPCLI_OK;
}

#include <langinfo.h>
int lpcli_readpassword(const char *prompt, char *out, size_t outl)
{
	printf("%s", prompt);
	static struct termios told, tnew;
	tcgetattr(0, &told);
	tnew = told;
	tnew.c_lflag &= ~ICANON;
	tnew.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &tnew);
	
	int ret;
	char *codeset = nl_langinfo(CODESET);
	if (strcmp(codeset, "UTF-8") == 0)
	{
		ret = lpcli_readpassword_nc(out, outl);
	}
	else
	{
		ret = lpcli_readpassword_u8(out, outl);
	}
	
	tcsetattr(0, TCSANOW, &told);
	printf("\n");
	return ret;
}

int main(int argc, char **argv)
{
	setlocale(LC_ALL, "");
	int ret = lpcli_main(argc, argv);
	return ret;
}
