
#CFLAGS=-D_KERNEL -m64 -xarch=sse2a -xmodel=kernel -g
CFLAGS= -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -Wall

LDFLAGS=-r

#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld

all: virtiox

virtiox: virtio.c virtiovar.h virtioreg.h
	$(CC) $(CFLAGS) -c virtiox.c -o virtiox.o
	$(CC) $(CFLAGS) -c util.c -o util.o
	$(LD) $(LDFLAGS) virtiox.o util.o -o virtiox

clean:
	rm -f virtiox virtiox.o util.o
