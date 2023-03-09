#!/bin/bash

ROOTFS_DIR=../build/rootfs
CONTAINER_IMAGE="ubuntu:20.04"
RUNNER_VERSION="2.302.1"

mkdir -p $ROOTFS_DIR
dd if=/dev/zero of=$ROOTFS_DIR/rootfs.ext4 bs=1M count=4096
mkfs.ext4 $ROOTFS_DIR/rootfs.ext4

docker run --platform=linux/amd64 --env --env --env RUNNER_VERSION="$RUNNER_VERSION" --privileged --name filesystem -i --rm -v "$(pwd)/$ROOTFS_DIR:/rootfs" -v "$(pwd)/filesystem:/filesystem" "$CONTAINER_IMAGE" bash -s <<'EOF'
/filesystem/prepare.sh

img_file="/rootfs/rootfs.ext4"
mnt_dir="/rootfs/mnt"
dirs="bin etc home lib lib64 opt root sbin usr var"
mkdir -p $mnt_dir
echo "Mounting $img_file on $mnt_dir ..."
mount $img_file $mnt_dir
for d in $dirs; do tar c "/$d" | tar x -C $mnt_dir; done
mkdir -p $mnt_dir/overlay
mkdir -p $mnt_dir/dev
mkdir -p $mnt_dir/mnt
mkdir -p $mnt_dir/rom
umount $mnt_dir

EOF
