CC=gcc

CFLAGS=-w

all: sniff

sniff: main.c
		$(CC) $(CFLAGS) main.c -o bin/sniff -lpcap

