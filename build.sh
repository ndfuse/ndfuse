#!/bin/bash

set -eux

cd $(dirname $0)

BUILD_DIR="go-fuse-loopback"
mkdir $BUILD_DIR
pushd $BUILD_DIR

wget https://raw.githubusercontent.com/hanwen/go-fuse/refs/tags/v2.8.0/example/loopback/main.go -O main.go
go mod init github.com/ndfuse/go-fuse-loopback
go mod tidy
go build

popd

pushd zpoline
make
popd
