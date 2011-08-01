
#CFLAGS= -D_KERNEL -DDEBUG -m64 -xarch=sse2a -xmodel=kernel -I ../virtio -g
CFLAGS= -DDEBUG -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -I../virtio -Wall -g
LDFLAGS=-r -dy -N misc/mac -N misc/virtio -N drv/blkdev

#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld
all: vioblk

vioblk: vioblk.c ../virtio/virtiovar.h
	$(CC) $(CFLAGS) -c vioblk.c -o vioblk.o
	$(LD) $(LDFLAGS) vioblk.o -o vioblk

clean:
	rm -f vioblk vioblk.o
