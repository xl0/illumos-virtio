#!/bin/sh

export PATH=$PATH:/sbin:/usr/sbin

sudo ifconfig vioif0 down
sudo ifconfig vioif0 unplumb
sudo modunload -i `modinfo | grep vioif | grep -v vioifx | cut -d " " -f 1`
sudo modunload -i `modinfo | grep virtio | grep -v virtiox | cut -d " " -f 1`

#sudo rem_drv virtio
#sudo rm /kernel/drv/amd64/virtio

