#!/bin/bash

cd $(dirname $0)

./target/debug/ndfuse-proxy ./go-fuse-loopback/go-fuse-loopback /dev/fd/ndfuse ./
