#! /bin/bash

set -x
set -e

CHERI_SDK=/home/$USER/cheri/output/sdk
CHERI_OUT_PATH=/home/chu/cheri/output
CHERI_BIN=/home/chu/cheri/output/sdk/bin

PATH=$CHERI_SDK/bin:$PATH

cd libonnx/src

make clean
bear make -j16

cd ../../

