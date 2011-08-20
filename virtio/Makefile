
#CFLAGS=-D_KERNEL -DDEBUG -m64 -xarch=sse2a -xmodel=kernel -g
CFLAGS= -D_KERNEL -DDEBUG -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -Wall -g


LDFLAGS=-r

#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld

all: virtio

virtio: virtio.c virtiovar.h virtioreg.h
	$(CC) $(CFLAGS) -c virtio.c -o virtio.o
	$(CC) $(CFLAGS) -c util.c -o util.o
	$(LD) $(LDFLAGS) virtio.o util.o -o virtio

clean:
	rm -f virtio virtio.o util.o
