CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong
LDFLAGS ?=

all: jail

jail: jail.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f jail

.PHONY: all clean
