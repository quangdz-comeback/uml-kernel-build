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

all: guest-init.elf step2.elf bench.elf forkwait.elf sigtest.elf \
	heaptest.elf guardtest.elf sysbench.elf netsetup.elf

guest-init.elf: init.S
	$(CC) --target=x86_64-linux-gnu -c init.S -o init.o
	$(LD) -static -nostdlib -e _start -z max-page-size=0x10000 \
		--image-base=$(IMAGE_BASE) -o $@ init.o

# S4c: the exec-chain proof binary — /sbin/init execve()s it through
# the guest syscall path (freestanding static, no TLS: musl's
# arch_prctl(ARCH_SET_FS) is the S4c2 slice).
#
# --image-base=$(IMAGE_BASE) matters for correctness, not just
# convenience: the loader shifts ET_EXECs linked below the guest
# window up to UML_NT_GUEST_VA_BASE (elf.c S3 note), which BREAKS
# baked absolute pointers — init's argv array lived in
# .data.rel.ro as link-VA pointers and the execve argv walk faulted
# (EXEC-FAIL, native CI). Linked inside the window the image loads
# exactly where its pointers say. Every guest binary we build gets
# the same base: execs replace each other sequentially, so they
# never share the address space.
step2.elf: step2.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "step2 must be a static ELF" >&2; exit 1; }

# M4.1: the RTT bench guest — runs as PID 1 (init=/bin/bench), a
# tight getpid loop between kernel-recognized window markers
# (bench.c); the kernel prints the ns summary, this binary the rdtsc
# cross-check. Same link recipe as step2 (in-window base).
bench.elf: bench.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "bench must be a static ELF" >&2; exit 1; }

# M4.2: the block-wait proof — PID 1 (init=/bin/forkwait) forks; the
# child is a REAL kernel task (copy_process + fork_handler + its own
# conn) and the parent's wait4 must BLOCK via schedule() until the
# child's do_exit wakes it (the POC -EAGAIN retry cannot produce the
# marker order this binary asserts).
forkwait.elf: forkwait.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "forkwait must be a static ELF" >&2; exit 1; }

# M4/S4d: the signal-fidelity proof — PID 1 (init=/bin/sigtest) faults
# a NULL store with magic XMM state, the kernel delivers a REAL guest
# SIGSEGV (force_sig_fault → do_signal → sigframe with fpstate), the
# handler verifies the frame's FP + skips the faulting insn via
# uc_mcontext.rip, the restorer's rt_sigreturn restores GP+FP — the
# guest continues with the ORIGINAL XMM values. Same link recipe.
sigtest.elf: sigtest.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "sigtest must be a static ELF" >&2; exit 1; }

# M4 slice 4: the multi-run heap growth proof — PID 1
# (init=/bin/heaptest) walks brk(2) 24 runs past the exec
# reservation's ONE run; every growth re-homes the heap in a fresh
# contiguous span (contents memcpy'd kernel-side), so the proof is
# content survival across growths + fresh-zero growth areas.
heaptest.elf: heaptest.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "heaptest must be a static ELF" >&2; exit 1; }

# M4 slice 5: the guard tripwire proof — PID 1 (init=/bin/guardtest):
# mmap(4K, PROT_NONE, MAP_FIXED) inside the heap VMA (the musl
# mallocng call shape) arms a REAL NOACCESS region; a store into it
# faults SIGSEGV ACCERR (kernel guard state, never auto-repaired);
# the handler unprotects via SUB-RUN mprotect (guard killed + view
# op) and the store replays through sigreturn.
guardtest.elf: guardtest.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "guardtest must be a static ELF" >&2; exit 1; }

# M4 final: the REAL sysbench cpu workload — sb_cpu.c's
# cpu_execute_event 1:1 (double-sqrt prime sweep to 10000), one event
# per sweep, a 10s monotonic window, eps = the M4-done metric.
# clock_gettime rides the new kernel syscall (QPC).
sysbench.elf: sysbench.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O2 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "sysbench must be a static ELF" >&2; exit 1; }

# M5.1c: the net gate guest — PID 1 (init=/bin/netsetup): execve()s
# busybox sh onto /net.sh, which brings eth0 (the vector device —
# spawned netstack helper + dialed D8 TCP channel) up, runs udhcpc
# (lease through the vector TX ring + the D19 reader) and pings the
# NAT gateway (10.0.2.2 — the slirp-parity uplink).
netsetup.elf: netsetup.c
	$(CC) --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-fuse-ld=lld \
		-Wall -Wl,--image-base=$(IMAGE_BASE) -o $@ $<
	@file -b $@ | grep -q "statically linked" || \
		{ echo "netsetup must be a static ELF" >&2; exit 1; }

clean:
	rm -f init.o guest-init.elf step2.elf bench.elf forkwait.elf \
		sigtest.elf heaptest.elf guardtest.elf sysbench.elf \
		netsetup.elf
.PHONY: all clean
