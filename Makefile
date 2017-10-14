FLAGS = -Wall -Wextra -pedantic -std=c99
GCC = gcc
DEL = rm

lpcli : lpcli.c lp.c lp.h 
	@$(GCC) $(FLAGS) -o $@ $^ -lcrypto
	@echo "--Building $@"
clean :
	$(DEL) lpcli

