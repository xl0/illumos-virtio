

CFLAGS= -D_KERNEL -DDEBUG -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -I../virtio -Wall -g
LDFLAGS=-r -dy -N misc/mac -N misc/virtio

CC=gcc
LD=/usr/ccs/bin/ld

all: vioif

vioif: vioif.c ../virtio/virtiovar.h
	$(CC) $(CFLAGS) -c vioif.c -o vioif.o
	$(LD) $(LDFLAGS) vioif.o -o vioif

clean:
	rm -f vioif vioif.o
