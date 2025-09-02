#!/bin/bash

echo 0 | sudo tee /proc/sys/vm/mmap_min_addr

set -eux -o pipefail

cd $(dirname $0)


function run_cmd_and_compare_diff() {
    CMD=$1
    CMD_PREFIX="LIBZPHOOK=../target/debug/libndfuseshim.so LD_PRELOAD=../zpoline/libzpoline.so"
    diff <(/bin/bash -c "$CMD_PREFIX $CMD") <(/bin/bash -c "$CMD")
}

../target/debug/ndfuse-proxy ../go-fuse-loopback/go-fuse-loopback /dev/fd/ndfuse ./ &
PROXY_PID=$!
sleep 1

run_cmd_and_compare_diff "ls -l -R"
run_cmd_and_compare_diff "cat testdir/FILE1.txt"

kill $PROXY_PID
