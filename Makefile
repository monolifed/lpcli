CFLAGS = -Wall -Wextra -pedantic -std=c99
LPCLI := lpcli
# Whether it should use ossl dev library or not
USE_OSSL_DEV := 0
CRYPTO_LIB := crypto

# Used on posix if USE_OSSL_DEV is 0
CRYPTO_SO := libcrypto.so.1.1

# Used on windows if USE_OSSL_DEV is 0
WIN_OSSL_DLL_PATH := .
WIN_OSSL_DLL := libeay32.dll
# Used on windows if USE_OSSL_DEV is 1
WIN_OSSL_DEV_PATH := D:/OpenSSL-Win64
WIN_OSSL_DEV_DLL := libcrypto-1_1-x64.dll

ifeq ($(USE_OSSL_DEV),0)
	CFLAGS += -DNO_OSSL_DEV
	CRYPTO_LIB := :$(CRYPTO_SO)
endif

ifeq ($(OS),Windows_NT)
	RM := del /Q
	LPCLI := $(LPCLI).exe
	CC := gcc
	ifeq ($(USE_OSSL_DEV),1)
		CFLAGS += -I$(WIN_OSSL_DEV_PATH)/include -L$(WIN_OSSL_DEV_PATH)/bin
		CRYPTO_LIB := :$(WIN_OSSL_DEV_DLL)
	else
		CFLAGS += -L$(WIN_OSSL_DLL_PATH)
		CRYPTO_LIB := :$(WIN_OSSL_DLL)
	endif
endif

$(LPCLI) : lpcli.c lp.c lp_crypto.h lp.h 
	$(CC) $(CFLAGS) -o $@ $^ -l$(CRYPTO_LIB)
clean :
	$(RM) $(LPCLI)
