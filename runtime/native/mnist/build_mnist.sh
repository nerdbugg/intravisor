#! /bin/bash

set -e
set -x

cd ./mnist/

make clean
bear make

