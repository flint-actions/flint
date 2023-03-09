#!/bin/bash

KERNEL_DIR=../build/kernel
CONTAINER_IMAGE="ubuntu:20.04"

mkdir -p $KERNEL_DIR
cp kernel/kernel.config $KERNEL_DIR/kernel.config

docker run --platform=linux/amd64 --env --privileged --name kernel -i --rm -v "$(pwd)/$KERNEL_DIR:/build" $CONTAINER_IMAGE bash -s <<'EOF'
apt-get update -y && apt-get upgrade -y
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential libssl-dev git ca-certificates flex bison libelf-dev bc

if [[ ! -d /build/linux ]]; then
	git clone --branch v5.10 --depth 1 https://github.com/torvalds/linux.git /build/linux
fi
cp /build/kernel.config /build/linux/.config
cd /build/linux
make vmlinux -j16
EOF
