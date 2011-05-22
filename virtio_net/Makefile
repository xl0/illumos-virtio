

#CFLAGS=-D_KERNEL -m64 -xarch=sse2a -xmodel=kernel -I ../virtio -g
CFLAGS= -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -I../virtiox -Wall -g
LDFLAGS=-r -dy -N misc/mac -N drv/virtiox

#CC=/opt/SUNWspro/bin/cc
CC=gcc
LD=/usr/ccs/bin/ld
all: vioifx

vioifx: vioif.c ../virtiox/virtiovar.h
	$(CC) $(CFLAGS) -c vioif.c -o vioif.o
	$(LD) $(LDFLAGS) vioif.o -o vioifx

clean:
	rm -f vioifx vioif.o
