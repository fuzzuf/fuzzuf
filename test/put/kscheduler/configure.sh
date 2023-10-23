#!/bin/bash

echo $@

export CC=${1}
export CXX=${2}
export CFLAGS=${3}
export CXXFLAGS=${4}

${@:5}
