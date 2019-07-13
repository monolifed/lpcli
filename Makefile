COMMON_FLAGS := -Wall -Wextra -pedantic -std=c99
LPCLI := lpcli
SETGEN := setgen
CFLAGS = $(COMMON_FLAGS)

ifeq ($(OS),Windows_NT)
	PLATFORM := win
	RM := del /Q
	EXT := .exe
	CC := gcc
else
	PLATFORM := posix
	ifeq ($(HAS_XCLIP), 1)
		CFLAGS = $(COMMON_FLAGS) -DUSE_XCLIP
	else
		CFLAGS = $(COMMON_FLAGS) -lX11
	endif
endif

LPCLI_DEPS := lpcli.h lp.c pbkdf2_sha256.h
LPCLI_CODE := lpcli_$(PLATFORM).c lpcli.c
$(LPCLI)$(EXT) : $(LPCLI_DEPS)
$(LPCLI)$(EXT) : $(LPCLI_CODE)
	$(CC) $(CFLAGS) -o $@ $(LPCLI_CODE)

clean :
	$(RM) $(LPCLI)$(EXT)
