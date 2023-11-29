#! /bin/bash

set -e
set -x

./build_libonnx.sh

./build_mnist.sh

./sync.sh
