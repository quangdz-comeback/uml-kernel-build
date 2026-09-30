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

# S4c2: busybox FROM SOURCE, not the Alpine prebuilt — the prebuilt
# links at 0x400000 and the load shift would break every baked pointer
# (the exact S4c EXEC-FAIL bug). allnoconfig + ash keeps musl off the
# raw linux/ headers it doesn't ship (console tools need linux/kd.h).
# musl's crt1.o carries a .interp section, so the binary has a
# PT_INTERP — our loader only walks PT_LOADs and ignores it; guests
# never look at it either. Build needs musl-tools (musl-gcc) + lld.
BUSYBOX_VER := 1.36.1
BUSYBOX_SHA := b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314

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
# The second line is the unique acceptance marker: the file CONTENT
# rides the OPENAT-READ-OK line, so the gate greps a line that has
# BUSYBOX-SHELL-OK but NOT the read marker (only busybox's own echo
# produces one).
staging/hi.sh:
	@mkdir -p staging
	printf 'echo hi\necho BUSYBOX-SHELL-OK\n' > $@

# S4c: the exec-chain proof binary — /sbin/init execve()s it through
# the guest syscall path (the STEP2-OK native gate). It then probes
# TLS/mmap (S4c2a gates) and execve()s busybox (below).
staging/bin/step2: ../guest/step2.elf
	@mkdir -p staging/bin
	cp $< $@

# M4.1: the RTT bench guest — PID 1 of the bench gate's own launcher
# run (init=/bin/bench), a tight getpid loop between kernel-recognized
# window markers (guest/bench.c). Lives in the same image so both
# gates share one rootfs artifact.
staging/bin/bench: ../guest/bench.elf
	@mkdir -p staging/bin
	cp $< $@

# M4.2: the block-wait proof — PID 1 (init=/bin/forkwait): fork makes
# a REAL child kernel task; the parent's wait4 blocks via schedule()
# until the child's do_exit wakes it.
staging/bin/forkwait: ../guest/forkwait.elf
	@mkdir -p staging/bin
	cp $< $@

# M4/S4d: the signal-fidelity proof — PID 1 (init=/bin/sigtest): a
# NULL store with magic XMM state becomes a REAL guest SIGSEGV; the
# handler verifies the frame's fpstate + skips the insn, and the
# restorer's rt_sigreturn restores GP+FP (originals back in XMM).
staging/bin/sigtest: ../guest/sigtest.elf
	@mkdir -p staging/bin
	cp $< $@

# M4 slice 4: the multi-run heap growth proof — PID 1
# (init=/bin/heaptest): brk walks 24 runs past the exec reservation;
# content must survive every re-home (fresh span + memcpy + stub view
# swap), fresh areas read zero, shrink/regrow keeps everything.
staging/bin/heaptest: ../guest/heaptest.elf
	@mkdir -p staging/bin
	cp $< $@

# M4 slice 5: the guard tripwire proof — PID 1 (init=/bin/guardtest):
# a sub-run PROT_NONE MAP_FIXED (the musl mallocng shape) materializes
# NOACCESS for real; a store faults SIGSEGV ACCERR; the handler
# unprotects via sub-run mprotect and the store replays.
staging/bin/guardtest: ../guest/guardtest.elf
	@mkdir -p staging/bin
	cp $< $@

build/busybox-$(BUSYBOX_VER)/busybox:
	@mkdir -p build
	curl -sSL -o build/$(BUSYBOX_VER).tar.bz2 \
		https://busybox.net/downloads/busybox-$(BUSYBOX_VER).tar.bz2
	echo "$(BUSYBOX_SHA)  build/$(BUSYBOX_VER).tar.bz2" | sha256sum -c
	tar -xjf build/$(BUSYBOX_VER).tar.bz2 -C build
	make -C build/busybox-$(BUSYBOX_VER) allnoconfig >/dev/null
	sed -i -e 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' \
	       -e 's/^# CONFIG_ASH is not set/CONFIG_ASH=y/' \
	       -e 's/^# CONFIG_ASH_ECHO is not set/CONFIG_ASH_ECHO=y/' \
	       -e 's/^# CONFIG_ECHO is not set/CONFIG_ECHO=y/' \
	       -e 's/^CONFIG_EXTRA_LDFLAGS=.*/CONFIG_EXTRA_LDFLAGS="-fuse-ld=lld -static -Wl,--image-base=$(IMAGE_BASE)"/' \
	       build/busybox-$(BUSYBOX_VER)/.config
	make -C build/busybox-$(BUSYBOX_VER) -j$(shell nproc) \
		CC=musl-gcc >/dev/null

# busybox sh runs /hi.sh (the acceptance POC): argv[1] = applet name,
# the script comes back through openat/read (S4b), "hi" goes out
# through write(2) → the console hand-path.
staging/bin/busybox: build/busybox-$(BUSYBOX_VER)/busybox
	@mkdir -p staging/bin
	cp $< $@
	@file -b $@ | grep -q "statically linked" || \
		{ echo "busybox must be a static ELF" >&2; exit 1; }

rootfs.ext4: staging/sbin/init staging/dev staging/hi.sh \
	     staging/bin/step2 staging/bin/bench staging/bin/forkwait \
	     staging/bin/sigtest staging/bin/heaptest \
	     staging/bin/guardtest staging/bin/busybox
	rm -f $@
	mke2fs -q -t ext4 -d staging -b 4096 $@ $(IMG_BLOCKS)

clean:
	rm -rf staging build rootfs.ext4

.PHONY: all clean
