#!/bin/bash

echo 0 | sudo tee /proc/sys/vm/mmap_min_addr

set -eux -o pipefail

cd $(dirname $0)


LIBNDFUSESHIM=$(realpath ../target/debug/libndfuseshim.so)
LIBZPOLINE=$(realpath ../zpoline/libzpoline.so)

function run_cmd_and_compare_diff() {
    CMD=$1
    CMD_PREFIX="LIBZPHOOK=$LIBNDFUSESHIM LD_PRELOAD=$LIBZPOLINE"
    diff <(cd /mnt && /bin/bash -c "$CMD_PREFIX $CMD") <(/bin/bash -c "$CMD")
}

../target/debug/ndfuse-proxy ../go-fuse-loopback/go-fuse-loopback /dev/fd/ndfuse ./ &
PROXY_PID=$!

trap 'kill $PROXY_PID' EXIT
sleep 1

run_cmd_and_compare_diff "ls -l -R ./"
run_cmd_and_compare_diff "cat testdir/FILE1.txt"
run_cmd_and_compare_diff "sha256sum testdir/FILE1.txt"

BINS=("16KiB" "64KiB" "128KiB" "256KiB") # TODO: 1MiB 10MiB
for size in "${BINS[@]}"; do
    run_cmd_and_compare_diff "cat testdir/$size.bin"
    run_cmd_and_compare_diff "sha256sum testdir/$size.bin"
done
