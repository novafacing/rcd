CC=gcc
CFLAGS=
LDFLAGS=

all: rcd

rcd: rcd.c save.s
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)
