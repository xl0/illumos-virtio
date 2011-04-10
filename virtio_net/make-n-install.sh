#!/bin/sh


export PATH=$PATH:/sbin:/usr/sbin

./rem.sh
make clean && make && sudo modload virtio_net


