# SPDX-License-Identifier: GPL-2.0
# guest-init.elf — the M3.4 probe guest (a real static ELF64 the
# kernel-side loader loads). Built on the Linux CI kernel job (clang
# + ld.lld, same toolchain as the kernel itself), uploaded as an
# artifact, consumed by the native Windows launcher job via
# uml_nt_exec=<file>.
#
# --image-base=0x62000000: inside the guest VA span (RAM base
# 0x60000000 + 32 MiB — the stub's VEH filter only treats traps with
# rip inside [ram_base, ram_base+ram_size) as guest traps, so the
# image MUST link there) and 64K-aligned (the loader expands regions
# to run boundaries anyway). max-page-size=0x10000 keeps every
# PT_LOAD 64K-aligned so segments load as separate VMAs (the loader
# merges when a linker overlaps them).
CC     ?= clang
LD     ?= ld.lld
IMAGE_BASE := 0x62000000

all: guest-init.elf

guest-init.elf: init.S
	$(CC) --target=x86_64-linux-gnu -c init.S -o init.o
	$(LD) -static -nostdlib -e _start -z max-page-size=0x10000 \
		--image-base=$(IMAGE_BASE) -o $@ init.o

clean:
	rm -f init.o guest-init.elf
.PHONY: all clean
