#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 // for popen/pclose & usleep
#endif

#include <stdio.h>
#include <string.h>

#include "lpcli.h"

// Fixme: there should be a more standard secure zero function?
void *lpcli_zeromemory(void *dst, size_t dstlen)
{
	void *ret;
#if defined(__GNUC__) || defined(__clang__)
	ret = memset(dst, '\0', dstlen);
	__asm__ volatile("" : : "g"(dst) : "memory");
#else
	volatile char *volatile p;
	p = (volatile char *volatile) dst;
	size_t i = 0;
	while (i < dstlen)
	{
		p[i++] = 0;
	}
	ret = dst;
#endif
	return ret;
}

#ifndef USE_XCLIP
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <unistd.h>
#include <time.h>
#endif

#define PASTE_WAIT 10

int lpcli_clipboardcopy(const char *text)
{
#ifdef USE_XCLIP
	FILE *pout = popen("xclip -selection clipboard", "w");
	if (!pout)
		return LPCLI_FAIL;
	fprintf(pout, "%s", text);
	fflush(pout);
	pclose(pout);
#else
	// https://github.com/ccxvii/snippets/blob/master/x11clipboard.c
	Display *display = XOpenDisplay(NULL);
	
	Atom clipboard = XInternAtom(display, "CLIPBOARD", False);
	Atom targets = XInternAtom(display, "TARGETS", False);
	Atom textatoms[] =
	{
		//targets,
		XInternAtom(display, "text/plain;charset=utf-8", False),
		XInternAtom(display, "UTF8_STRING", False),
		//XInternAtom(display, "COMPOUND_TEXT", False),
		XA_STRING,
		//XInternAtom(display, "text/plain", False),
		XInternAtom(display, "TEXT", False),
	};
	
	int textatoms_len = sizeof(textatoms) / sizeof(Atom);
	
	printf("You have %i seconds to paste\n", PASTE_WAIT);
	
	Window window = XCreateSimpleWindow(display, DefaultRootWindow(display),
	        0, 0, 1, 1, 0, CopyFromParent, CopyFromParent);
	XSetSelectionOwner(display, clipboard, window, CurrentTime);
	Window owner = XGetSelectionOwner(display, clipboard);
	if (window != owner)
		return LPCLI_FAIL;
	
	XEvent event;
	time_t end_time = time(0) + PASTE_WAIT;
	time_t cur_time;
	while ((cur_time = time(0)) && end_time > cur_time)
	{
		if (XPending(display) == 0)
		{
			usleep(5000);
			continue;
		}
		
		XNextEvent(display, &event);
		switch (event.type)
		{
		case SelectionClear:
			return LPCLI_OK;
	
		case SelectionRequest:
		{
			XSelectionRequestEvent *sre = &event.xselectionrequest;
			// For obsolete clients
			if (sre->property == None)
			{
				sre->property = sre->target;
			}

			XSelectionEvent se =
			{
				.type = SelectionNotify, .serial = 0, .send_event = False, .display = display,
				.requestor = sre->requestor, .selection = sre->selection, .target = sre->target,
				.property = sre->property, .time = CurrentTime
			};


			int canpaste = 0;
			if (sre->target == targets)
			{
				XChangeProperty(display, sre->requestor, sre->property, XA_ATOM,
				    32, PropModeReplace, (unsigned char *) textatoms, textatoms_len);
			}
			else
			{
				for (int i = 0; i < textatoms_len; i++)
				{
					if (sre->target == textatoms[i])
					{
						canpaste = 1;
						break;
					}
				}

				if (canpaste)
				{
					XChangeProperty(display, sre->requestor, sre->property, sre->target,
					    8, PropModeReplace, (unsigned char *) text, strlen(text));
				}
				else
				{
					se.property = None;
				}
			}

			XSendEvent(display, sre->requestor, False, 0, (XEvent *) &se);
			XFlush(display);
		}
		break;
		}
	}

	{
		XSetSelectionOwner(display, clipboard, None, CurrentTime);
	}
#endif
	return LPCLI_OK;
}


#include <termios.h>
#include <wchar.h>

#if __WCHAR_MAX__ < 0x10FFFF
// Fixme: Because then fgetws will use some non-standard wchar encoding.
//        However if the terminal encoding is already utf-8,
//        there is no (need for any) conversion anyway.
#pragma message "Unsupported wchar_t type"
#define NOCONVERSION
#endif

#ifndef NOCONVERSION

#include <locale.h>
#include <langinfo.h>

#define UTF8_1 0x007FUL
#define UTF8_2 0x07FFUL
#define UTF8_3 0xFFFFUL
#define UTF8_4 0x10FFFFUL
static int uc_toutf8(unsigned long uc, unsigned char *utf8)
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

static int uc_utf8len(unsigned long uc)
{
	if (uc <= UTF8_1) { return 1; }
	if (uc <= UTF8_2) { return 2; }
	if (uc <= UTF8_3) { return 3; }
	if (uc <= UTF8_4) { return 4; }
	return 0;
}

static size_t wcs_utf8len(const wchar_t *wcs, size_t wcslen)
{
	int len;
	size_t tlen = 0;
	for (unsigned i = 0; i < wcslen; i++)
	{
		len = uc_utf8len(wcs[i]);
		if (len == 0)
			return 0;
		tlen += len;
	}
	return tlen;
}

static int wcs_toutf8(const wchar_t *wcs, size_t wlen, unsigned char *out, size_t outlen)
{
	if (wlen == 0)
		return 0;
		
	size_t tlen = wcs_utf8len(wcs, wlen);
	if (tlen == 0 || outlen < tlen)
		return -1;
		
	unsigned char *p = out;
	for (unsigned i = 0; i < wlen; i++)
	{
		p += uc_toutf8(wcs[i], p);
	}
	return tlen;
}

// read as wchar convert to utf8
static int lpcli_readpassword_utf8(char *out, size_t outlen)
{
	wchar_t input[MAX_INPUTWCS];
	wchar_t *wp = fgetws(input, MAX_INPUTWCS, stdin);
	if (wp == NULL)
		return LPCLI_FAIL;
		
	int len = wcscspn(input, L"\r\n");
	if (len == 0)
		return LPCLI_FAIL;
		
	len = wcs_toutf8(input, len, (unsigned char *) out, outlen - 1);
	lpcli_zeromemory(input, sizeof input);
	if (len <= 0)
		return LPCLI_FAIL;
		
	out[len] = 0;
	return LPCLI_OK;
}
#endif // NOCONVERSION

// read directly, no conversion
static int lpcli_readpassword_nc(char *out, size_t outlen)
{
	out = fgets(out, outlen, stdin);
	if (out == NULL)
		return LPCLI_FAIL;
		
	int len = strcspn(out, "\r\n");
	if (len == 0)
		return LPCLI_FAIL;
		
	out[len] = 0;
	return LPCLI_OK;
}

int lpcli_readpassword(const char *prompt, char *out, size_t outlen)
{
	printf("%s", prompt);
	static struct termios told, tnew;
	tcgetattr(0, &told);
	tnew = told;
	tnew.c_lflag &= ~ICANON;
	tnew.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &tnew);
	
	int ret;
#ifndef NOCONVERSION
	if (strcmp(nl_langinfo(CODESET), "UTF-8") != 0)
	{
		ret = lpcli_readpassword_utf8(out, outlen);
	}
	else
#endif // NOCONVERSION
	{
		ret = lpcli_readpassword_nc(out, outlen);
	}
	
	tcsetattr(0, TCSANOW, &told);
	printf("\n");
	return ret;
}

int main(int argc, char **argv)
{
#ifndef NOCONVERSION
	setlocale(LC_ALL, "");
#endif
	int ret = lpcli_main(argc, argv);
	return ret;
}
