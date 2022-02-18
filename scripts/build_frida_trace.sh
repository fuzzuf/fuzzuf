#!/bin/bash

set -eux

AFLPP_DIR=$1
CMAKE_BINARY_DIR=$2
BUILD_TARGET="afl-frida-trace.so"

if [ -f "$CMAKE_BINARY_DIR/$BUILD_TARGET" ]; then
    echo "$BUILD_TARGET already exists."
else
    if [ ! -d "$AFLPP_DIR/frida_mode" ]; then
        echo "[!] Cloning a submodule first..."
        git submodule init
        git submodule update
        if [ ! -d "$AFLPP_DIR" ]; then 
            echo "[-] Could not clone a submodule, exiting..."
            exit 1
        fi
    fi
    echo "[*] Building $BUILD_TARGET"
    make -C $AFLPP_DIR/frida_mode >/dev/null
    echo "[*] Copying $BUILD_TARGET"
    cp $AFLPP_DIR/$BUILD_TARGET $CMAKE_BINARY_DIR
fi

