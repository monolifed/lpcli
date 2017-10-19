FLAGS = -Wall -Wextra -pedantic -std=c99
LPCLI := lpcli
CRYPTO_LIB := crypto

ifeq ($(OS),Windows_NT)
	RM = del /Q
	LPCLI := $(LPCLI).exe
	CC = gcc
	OPENSSL_DIR := D:/OpenSSL-Win64
	CRYPTO_LIB := crypto-1_1-x64
	FLAGS += -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/bin
endif

$(LPCLI) : lpcli.c lp.c lp.h 
	$(CC) $(FLAGS) -o $@ $^ -l$(CRYPTO_LIB)
clean :
	$(RM) $(LPCLI)
