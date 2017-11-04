COMMON_FLAGS := -Wall -Wextra -pedantic -std=c99
LPCLI := lpcli
SETGEN := setgen
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


CFLAGS = $(COMMON_FLAGS)
ifeq ($(USE_OSSL_DEV),0)
	CFLAGS += -DNO_OSSL_DEV
	CRYPTO_LIB := :$(CRYPTO_SO)
endif

ifeq ($(OS),Windows_NT)
	PLATFORM := win
	RM := del /Q
	EXT := .exe
	CC := gcc
	ifeq ($(USE_OSSL_DEV),1)
		CFLAGS += -I$(WIN_OSSL_DEV_PATH)/include -L$(WIN_OSSL_DEV_PATH)/bin
		CRYPTO_LIB := :$(WIN_OSSL_DEV_DLL)
	else
		CFLAGS += -L$(WIN_OSSL_DLL_PATH)
		CRYPTO_LIB := :$(WIN_OSSL_DLL)
	endif
else
	PLATFORM := posix
endif

$(LPCLI)$(EXT) : lpcli_$(PLATFORM).c lpcli.c lp.c lp_crypto.h lp.h 
	$(CC) $(CFLAGS) -o $@ $^ -l$(CRYPTO_LIB)
$(SETGEN)$(EXT) : lp_gencharsets.c
	$(CC) $(COMMON_FLAGS) -o $@ $^
clean :
	$(RM) $(LPCLI)$(EXT) $(SETGEN)$(EXT)
