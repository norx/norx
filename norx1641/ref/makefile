CFLAGS=-O3 -march=native -std=c89 -Wall -Wextra -pedantic -Wno-long-long

all: check bench

bench:
	@$(CC) $(CFLAGS) -o bench ../../bench/bench.c norx.c caesar.c
	@./bench
	@rm bench

check:
	@$(CC) $(CFLAGS) -I. -o check ../../check/check.c norx.c caesar.c
	@./check
	@rm check

genkat:
	$(CC) $(CFLAGS) -o genkat ../../check/genkat.c norx.c caesar.c
	./genkat > kat.h
	rm genkat

testvector:
	@$(CC) $(CFLAGS) -DNORX_DEBUG -I. -o testvector ../../check/testvector64.c caesar.c norx.c
	@./testvector
	@rm testvector
