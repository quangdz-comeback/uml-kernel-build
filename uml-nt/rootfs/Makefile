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
# Guest window link base: the loader shifts ET_EXECs linked below the
# window, which breaks baked absolute pointers (init's argv array in
# .data.rel.ro held link-VA pointers — the execve argv walk faulted,
# EXEC-FAIL native). Link INSIDE the window: the image loads where its
# pointers say. All guest binaries share it — execs replace each other
# sequentially and never share the address space.
IMAGE_BASE := 0x62000000
IMG_BLOCKS ?= 2048   # 8 MiB at 4K blocks

all: rootfs.ext4

staging/sbin/init: init.c
	@mkdir -p staging/sbin
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
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

# S4c: the exec-chain proof binary — /sbin/init execve()s it through
# the guest syscall path (the STEP2-OK native gate).
staging/bin/step2: ../guest/step2.elf
	@mkdir -p staging/bin
	cp $< $@

rootfs.ext4: staging/sbin/init staging/dev staging/hi.sh staging/bin/step2
	rm -f $@
	mke2fs -q -t ext4 -d staging -b 4096 $@ $(IMG_BLOCKS)

clean:
	rm -rf staging rootfs.ext4

.PHONY: all clean
