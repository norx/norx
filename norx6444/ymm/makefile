CFLAGS=-O3 -mavx2 -march=native -std=c89 -Wall -pedantic -Wno-long-long

all: check bench

debug:
	@$(CC) $(CFLAGS) -DNORX_DEBUG -I. -o debug ../../utils/debug.c norx.c
	@./debug
	@rm debug

bench: ../../utils/bench.c norx.c caesar.c
	$(CC) $(CFLAGS) -o bench ../../utils/bench.c norx.c caesar.c
	sde64 -- ./bench
	rm bench

check: ../../utils/check.c norx.c caesar.c
	$(CC) $(CFLAGS) -I../ -o check ../../utils/check.c norx.c caesar.c
	sde64 -- ./check
	rm check
