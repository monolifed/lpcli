#include <windows.h>
#include <conio.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

int lpcli_clipboardcopy(const char *text)
{
	const size_t len = strlen(text) + 1;
	HGLOBAL hMem =  GlobalAlloc(GMEM_MOVEABLE, len);
	memcpy(GlobalLock(hMem), text, len);
	GlobalUnlock(hMem);
	OpenClipboard(0);
	EmptyClipboard();
	if(!SetClipboardData(CF_TEXT, hMem))
	{
		return 1;
	}
	CloseClipboard();
	return 0;
}

#define READPASS_MAX 512
// Todo: calculate the encoded length as characters entered
int lpcli_readpassword(const char *prompt, char *out, int outl)
{
	printf(prompt);
	wchar_t outbuff[READPASS_MAX];
	wint_t c;
	int i;
	for(i=0; i < READPASS_MAX; i++)
	{
		c = _getwch();
		if(c == L'\r')
		{
			//outbuff[i++] = 0;
			break;
		}
		outbuff[i] = c;
	}
	printf("\n");
	if(i >= READPASS_MAX)
	{
		SecureZeroMemory(outbuff, sizeof outbuff);
		fprintf(stderr, "Reached max password limit %i\n", READPASS_MAX);
		return 1;
	}
	int err = 0;
	int len = WideCharToMultiByte(CP_UTF8, 0, outbuff, i, out, outl - 1, NULL, NULL);
	if(len == 0 || len == 0xFFFD)
	{
		err = GetLastError();
	}
	out[len] = 0;
	SecureZeroMemory(outbuff, sizeof outbuff);
	if(err != 0)
	{
		fprintf(stderr, "WideCharToMultiByte got error code %i\n", err);
		return 1;
	}
	return 0;
}

static char** getargs_utf8(int *argc)
{
	wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), argc);
	int i;
	int tlen = 0;
	int utf8len[*argc];
	int wlen[*argc];
	for(i = 0; i < *argc; i++)
	{
		wlen[i] = wcslen(wargv[i]) + 1;
		utf8len[i] = WideCharToMultiByte(CP_UTF8, 0, wargv[i], wlen[i], NULL, 0, NULL, NULL);
		tlen += utf8len[i];
	}
	int argvsize = (*argc + 1) * sizeof(char*);
	char *argvp = malloc(argvsize + tlen * sizeof(char));
	char **argv = (void *) argvp;
	argvp += argvsize;
	for(i = 0; i < *argc; i++)
	{
		WideCharToMultiByte(CP_UTF8, 0, wargv[i], wlen[i], argvp, utf8len[i], NULL, NULL);
		SecureZeroMemory(wargv[i], wlen[i]);
		argv[i] = argvp;
		argvp += utf8len[i];
	}
	argv[*argc] = NULL;
	LocalFree(wargv);
	return argv;
}

void* lpcli_zeromemory(void *dst, size_t dstlen)
{
	return SecureZeroMemory(dst, dstlen);
}

int lpcli_main(int argc, const char **argv);

int main()
{
	setlocale(LC_ALL, "");
	int argc;
	char **_argv = getargs_utf8(&argc);
	const char **argv = (const char **) _argv;
	int ret = lpcli_main(argc, argv);
	free(_argv);
	return ret;
}
