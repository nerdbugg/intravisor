#! /bin/bash

set -x
set -e

cd src

make clean
bear make CONFIG=1 TFORK=1 DEBUG=1 --ignore-errors
## bear make CONFIG=1 DEBUG=1 --ignore-errors

cp compile_commands.json ../

