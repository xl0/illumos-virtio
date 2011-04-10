

#CFLAGS=-D_KERNEL -m64 -xarch=sse2a -xmodel=kernel -I ../virtio -g
CFLAGS= -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -I../virtio -Wall -g
LDFLAGS=-r -dy -N misc/mac -N drv/virtio

#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld
all: virtio_net

virtio_net: virtio_net.c ../virtio/virtiovar.h
	$(CC) $(CFLAGS) -c virtio_net.c -o virtio_net.o
	$(LD) $(LDFLAGS) virtio_net.o -o virtio_net

clean:
	rm -f virtio_net virtio_net.o
