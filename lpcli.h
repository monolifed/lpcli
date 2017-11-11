#ifndef LPCLI_H
#define LPCLI_H

#define LPCLI_FAIL    1
#define LPCLI_OK 0

int lpcli_clipboardcopy(const char *text);
int lpcli_readpassword(const char *prompt, char *out, size_t outl);
void *lpcli_zeromemory(void *dst, size_t dstlen);

int lpcli_main(int argc, char **argv);

#define MAX_INPUTWCS 512

#endif //LPCLI_H
