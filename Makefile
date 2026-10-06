CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong
LDFLAGS ?=

all: jail t/try

jail: jail.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# -static so the probe needs nothing but its own inode: the sandbox under test
# then has to allow only the paths the test is actually about.
t/try: t/try.c
	$(CC) $(CFLAGS) -static -o $@ $<

test: all
	@t/run.sh

clean:
	rm -f jail t/try

.PHONY: all test clean
