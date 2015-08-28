CFLAGS=-O3 -mavx2 -march=native -std=c89 -Wall -pedantic -Wno-long-long

all: check bench

bench:
	@$(CC) $(CFLAGS) -o bench ../../utils/bench.c norx.c
	@./bench
	@rm bench

check:
	@$(CC) $(CFLAGS) -I.. -o check ../../utils/check.c norx.c
	@./check
	@rm check
