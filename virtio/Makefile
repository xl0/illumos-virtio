
CFLAGS=-D_KERNEL -m64 -xarch=sse2a -xmodel=kernel -g
LDFLAGS=-r

CC=/opt/SUNWspro/bin/cc
LD=/usr/ccs/bin/ld

all: virtio

virtio: virtio.c virtiovar.h virtioreg.h
	$(CC) $(CFLAGS) -c virtio.c -o virtio.o
	$(LD) $(LDFLAGS) virtio.o -o virtio

clean:
	rm -f virtio virtio.o
