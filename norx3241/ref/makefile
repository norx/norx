CFLAGS=-O3 -march=native -std=c89 -Wall -Wextra -pedantic -Wno-long-long

all: check bench

debug:
	@$(CC) $(CFLAGS) -DNORX_DEBUG -I. -o debug ../../utils/debug.c norx.c
	@./debug
	@rm debug

bench:
	@$(CC) $(CFLAGS) -o bench ../../utils/bench.c norx.c caesar.c
	@./bench
	@rm bench

check:
	@$(CC) $(CFLAGS) -I../ -o check ../../utils/check.c norx.c caesar.c
	@./check
	@rm check

genkat:
	$(CC) $(CFLAGS) -o genkat ../../utils/genkat.c norx.c caesar.c
	./genkat > ../kat.h
	rm genkat
