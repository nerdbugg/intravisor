#! /bin/bash

set -e

set -x

cd src

make clean

#make MMAP_COMBINE=1
make
#make TFORK=1

sync-vmshare.sh

