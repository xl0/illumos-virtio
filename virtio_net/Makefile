

#CFLAGS=-D_KERNEL -m64 -xarch=sse2a -xmodel=kernel -I ../virtio -g
CFLAGS= -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -I../virtio -Wall -g
LDFLAGS=-r -dy -N misc/mac -N drv/virtio

#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld
all: vioif

vioif: vioif.c ../virtio/virtiovar.h
	$(CC) $(CFLAGS) -c vioif.c -o vioif.o
	$(LD) $(LDFLAGS) vioif.o -o vioif

clean:
	rm -f vioif vioif.o
