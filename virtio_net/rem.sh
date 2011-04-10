#!/bin/sh

export PATH=$PATH:/sbin:/usr/sbin

sudo ifconfig virtio_net0 unplumb
sudo modunload -i `modinfo | grep virtio_net | cut -d " " -f 1`

#sudo rem_drv virtio_net
# sudo rm /kernel/drv/amd64/virtio_net

