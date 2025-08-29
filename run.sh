#!/bin/bash

cd $(dirname $0)

LIBZPHOOK=./target/debug/libndfuseshim.so LD_PRELOAD=./zpoline/libzpoline.so ls -l /mnt
LIBZPHOOK=./target/debug/libndfuseshim.so LD_PRELOAD=./zpoline/libzpoline.so cat /mnt/Cargo.toml
