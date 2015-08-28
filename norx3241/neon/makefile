CFLAGS=-O3 -mcpu=cortex-a8 -mfpu=neon -std=c99 -Wall -pedantic -Wno-long-long

all: check bench

bench:
	@$(CC) $(CFLAGS) -o bench ../../utils/bench.c norx.c
	@./bench
	@rm bench

check:
	@$(CC) $(CFLAGS) -I.. -o check ../../utils/check.c norx.c
	@./check
	@rm check

