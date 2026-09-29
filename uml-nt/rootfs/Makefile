# SPDX-License-Identifier: GPL-2.0
# uml-nt rootfs — minimal ext4 image for the M3.5 boot gate.
#
#   make          → staging/sbin/init (static, freestanding) + rootfs.ext4
#
# The image is populated with mke2fs -d (no root, no loop device):
# staging/ becomes the fs root, so the kernel finds /sbin/init — the
# first of the default init paths it tries for a block-device root.
# busybox + a real userspace arrive at M3.8.

CC = clang   # command-line override wins (CC ?= loses to make's builtin)
LD = ld.lld
IMG_BLOCKS ?= 2048   # 8 MiB at 4K blocks

all: rootfs.ext4

staging/sbin/init: init.c
	@mkdir -p staging/sbin
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-Wall -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "init must be a static ELF" >&2; exit 1; }

# /dev must exist for devtmpfs_mount (M3.5 saw error -2 without it);
# devtmpfs then provides /dev/console for console_on_rootfs (init's
# fds 0/1/2) and the device nodes busybox needs (M3.8 S4).
staging/dev:
	@mkdir -p staging/dev

# S4: the script /sbin/init reads back through the REAL VFS
# (openat/read, M3.8 S4b gate) — and that busybox sh runs in S4c.
staging/hi.sh:
	@mkdir -p staging
	printf 'echo hi\n' > $@

rootfs.ext4: staging/sbin/init staging/dev staging/hi.sh
	rm -f $@
	mke2fs -q -t ext4 -d staging -b 4096 $@ $(IMG_BLOCKS)

clean:
	rm -rf staging rootfs.ext4

.PHONY: all clean
