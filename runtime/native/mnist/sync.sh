#! /bin/bash

set -e
set -x

SSHFS=$HOME/cherry

SHARED=$SSHFS/vmshare


cp ./scripts/** $SHARED/intravisor/native/mnist/
cp ./mnist/libmnist.so $SHARED/intravisor/native/mnist/

