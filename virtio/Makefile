
#CFLAGS=-D_KERNEL -DDEBUG -m64 -xarch=sse2a -xmodel=kernel -g
CFLAGS= -D_KERNEL -DDEBUG -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -Wall -g

LDFLAGS=-r

ONDIR=/opt/onbld/bin/i386
CTFMERGE=$(ONDIR)/ctfmerge
CTFCONVERT=$(ONDIR)/ctfconvert


#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld

all: virtio

virtio: virtio.c virtiovar.h virtioreg.h
	$(CC) $(CFLAGS) -c virtio.c -o virtio.o
	$(CTFCONVERT) -i -L VERSION virtio.o
	$(LD) $(LDFLAGS) virtio.o -o virtio
	$(CTFMERGE) -L VERSION -o virtio virtio.o

clean:
	rm -f virtio virtio.o
