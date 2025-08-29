#!/bin/bash

set -eux

cd $(dirname $0)

cd linux/tools/lkl

make $(pwd)/../../.config

cd ../../

# enable FUSE support
./scripts/config -e CONFIG_FUSE_FS
./scripts/config -d CONFIG_CUSE
./scripts/config -d CONFIG_VIRTIO_FS

make -C tools/lkl -j $(nproc)
cp tools/lkl/liblkl.a ../.
