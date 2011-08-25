
#CFLAGS= -D_KERNEL -DDEBUG -m64 -xarch=sse2a -xmodel=kernel -I ../virtio -g
CFLAGS= -DDEBUG -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -I../virtio -Wall -g
LDFLAGS=-r -dy -N misc/mac -N misc/virtio -N drv/blkdev

ONDIR=/opt/onbld/bin/i386
CTFMERGE=$(ONDIR)/ctfmerge
CTFCONVERT=$(ONDIR)/ctfconvert
#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld
all: vioblk

vioblk: vioblk.c ../virtio/virtiovar.h
	$(CC) $(CFLAGS) -c vioblk.c -o vioblk.o
	$(CTFCONVERT) -i -L VERSION vioblk.o
	$(LD) $(LDFLAGS) vioblk.o -o vioblk
	$(CTFMERGE) -L VERSION -o vioblk vioblk.o

clean:
	rm -f vioblk vioblk.o
