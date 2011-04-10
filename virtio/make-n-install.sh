#!/bin/sh

export PATH=$PATH:/sbin:/usr/sbin

./rem.sh

make clean && make && sudo modload virtio
sudo cp virtio /kernel/drv/amd64

#make clean && make && sudo cp virtio /kernel/drv/amd64/ &&  sudo update_drv virtio
