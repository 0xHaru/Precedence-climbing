CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -std=c11 -g
# CFLAGS=-Wall -Wextra -Wpedantic -std=c11 -O2

.PHONY: all clean

all: calc

calc: calc.c
	$(CC) calc.c -o $@ $(CFLAGS)

debug: calc.c
	$(CC) calc.c -o $@ $(CFLAGS) -DDEBUG

fuzz: calc.c
	clang calc.c -o $@ -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -O1 -DFUZZ

clean:
	rm -f calc debug fuzz crash-*
