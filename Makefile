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

LPCLI_DEPS := lpcli.h lp.h lp_crypto.h
LPCLI_CODE := lpcli_$(PLATFORM).c lpcli.c lp.c
$(LPCLI)$(EXT) : $(LPCLI_CODE) $(LPCLI_DEPS)
	$(CC) $(CFLAGS) -o $@ $(LPCLI_CODE) -l$(CRYPTO_LIB)

$(SETGEN)$(EXT) : lp_gencharsets.c lp.h
	$(CC) $(COMMON_FLAGS) -o $@ $<
clean :
	$(RM) $(LPCLI)$(EXT) $(SETGEN)$(EXT)
