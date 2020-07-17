CFLAGS := -Wall -Wextra -Wvla -Wsign-conversion -pedantic -std=c99
APPNAME := lpcli

ifeq ($(OS),Windows_NT)
	PLATFORM := win
	RM := del /Q
	CC := gcc
	APPNAME := $(APPNAME).exe
else
	PLATFORM := posix
	ifeq ($(HAS_XCLIP), 1)
		CFLAGS := $(CFLAGS) -DUSE_XCLIP
	else
		CFLAGS := $(CFLAGS) -lX11
	endif
endif

DEPS := lpcli.h lp.h pbkdf2_sha256.h
CODE := lpcli_$(PLATFORM).c lpcli.c
$(APPNAME): $(DEPS)
$(APPNAME): $(CODE)
	$(CC) $(CFLAGS) -o $@ $(CODE)

clean:
	$(RM) $(APPNAME)
