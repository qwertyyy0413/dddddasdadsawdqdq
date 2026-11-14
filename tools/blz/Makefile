CC ?= gcc
CFLAGS ?= -O3 -fvisibility=hidden -fno-ident

all: blz.o

blz.o: blz.c blz.h blz_config.h
	$(CC) $(CFLAGS) -c blz.c -o blz.o

clean:
	rm -f *.o blz_config.h
