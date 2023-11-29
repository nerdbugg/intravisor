#! /bin/bash

set -e
set -x

SSHFS=$HOME/cherry

SHARED=$SSHFS/vmshare


cp ./libfile.so $SHARED/intravisor/native/file/

