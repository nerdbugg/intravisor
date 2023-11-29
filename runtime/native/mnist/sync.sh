#! /bin/bash

set -e
set -x

SSHFS=$HOME/cherry

SHARED=$SSHFS/vmshare


cp ./mnist/libmnist.so $SHARED/intravisor/native/mnist/

