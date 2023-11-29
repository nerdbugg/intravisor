#! /bin/bash

set -e

set -x

cd src

make clean

make TFORK=1 DEBUG=1

sync-vmshare.sh

