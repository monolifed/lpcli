#if defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif
#include <stddef.h>
#include <string.h>

void zeromem(void *dst, size_t dstlen)
{
#if defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64)
	SecureZeroMemory(dst, dstlen);
#elif defined(__GNUC__) || defined(__clang__)
	memset(dst, '\0', dstlen);
	__asm__ volatile("" : : "g"(dst) : "memory");
#else
	volatile char *volatile p;
	p = (volatile char *volatile) dst;
	size_t i = 0;
	while (i < dstlen)
	{
		p[i++] = 0;
	}
#endif
}