/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub_nt.h — uml-nt stub protocol (kernel ↔ stub.exe shared memory).
 *
 * Upstream 6.18 seccomp stub (arch/um/include/shared/skas/stub-data.h)
 * synchronizes via a futex inside stub_data plus a unix socket for FD
 * passing; both are same-host-clone tricks that do not exist across
 * real processes (D3: stub.exe is a separate PE process, and
 * WaitOnAddress/NtAlertThreadByThreadId are same-process only —
 * verified M0/S2). The NT protocol replaces them with:
 *
 *   - two auto-reset event handles, inherited by the stub and passed
 *     by VALUE on its command line (S5 bootstrap pattern);
 *   - a monotonic request sequence (Interlocked64 on the shared
 *     section — cross-process coherent, S2) so a command can never be
 *     executed twice (M0 pitfall 4.4: dedupe by monotonic id).
 *
 * One instance of `struct uml_nt_stub_data` lives in its own 64 KiB
 * pagefile section per stub (the stub_data analogue). The kernel owns
 * the section + events; it writes the bootstrap block before
 * ResumeThread.
 *
 * This header is included by BOTH the kernel ELF (freestanding, no
 * host headers) and stub.exe (mingw PE, windows.h available) — same
 * dual-mode pattern as ntabi.h. Layout drift between the two sides
 * fails loudly at handshake (magic/version check).
 */
#ifndef __UML_STUB_NT_H
#define __UML_STUB_NT_H

#ifdef _WIN64
#include <windows.h>
#define UML_STUB_CC /* ms ABI is the default under mingw/PE */
typedef unsigned int u32_nt;
typedef unsigned long long u64_nt;
typedef long long s64_nt;
#else
#define UML_STUB_CC __attribute__((ms_abi))
typedef unsigned int u32_nt;
typedef unsigned long long u64_nt;
typedef long long s64_nt;
#endif

/* "USTB". */
#define UML_STUB_MAGIC   0x42545355u
#define UML_STUB_VERSION 1u
/* Section size (also the map granularity guard). */
#define UML_STUB_SECTION_SIZE 0x10000u

/* Bootstrap block offset: the first cache line of the section. The
 * kernel fills it before ResumeThread; the stub maps the section and
 * validates it before doing anything else. */
#define UML_STUB_BOOT_OFFSET 0

/* Commands (stub → kernel request in slot.cmd). */
#define UML_STUB_CMD_WRITE 1u /* write(fd, buf, len) — guest syscall 1 */
#define UML_STUB_CMD_EXIT  2u /* exit(code)        — guest syscall 60 */

/* Guest virtual address space, M2 edition: the stub maps the whole
 * physmem section at ram_base and the static init runs in that view,
 * so guest VA == ram_base + guest physical offset. M3's VMA manager
 * replaces this with per-VMA views at real guest VAs. */
#define UML_STUB_RAM_BASE 0x60000000ULL /* == launcher GUEST_RAM_VA */

/*
 * GP register snapshot at the trap (stub → kernel), explicit-field —
 * no layout tricks: both sides write every member by name.
 */
struct uml_nt_gp_regs {
	unsigned long long rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
			   r8, r9, r10, r11, r12, r13, r14, r15,
			   rip, rflags;
};

/*
 * One command slot. M2 has a single outstanding request at a time
 * (the whole stub blocks until the kernel answers); the seq makes the
 * slot safe to reuse in order and leaves room for batching later.
 */
struct uml_nt_stub_data {
	/* -- cache line 0: handshake + protocol state ---------------- */
	u32_nt magic;   /* UML_STUB_MAGIC, written by kernel */
	u32_nt version; /* UML_STUB_VERSION */
	/* Monotonic request id, bumped (Interlocked) by the stub when
	 * it publishes a command. Kernel waits for seq > done_seq,
	 * answers, then bumps done_seq. 0 = nothing yet. */
	volatile u64_nt req_seq;
	volatile u64_nt done_seq;
	u32_nt cmd;      /* UML_STUB_CMD_* */
	u32_nt err;      /* kernel → stub: 0 = ok, else -errno-style */
	unsigned long long args[6]; /* syscall args (guest VA space) */
	unsigned long long retval;  /* kernel → stub: syscall return */
	u32_nt halt;                /* kernel → stub: 1 = ExitProcess now */
	struct uml_nt_gp_regs regs; /* full GP snapshot at the trap */

	/* -- bootstrap (written by kernel pre-ResumeThread) ---------- */
	unsigned long long ram_base;  /* stub VA of the physmem view */
	unsigned long long ram_size;  /* physmem section bytes */
	unsigned long long entry_off; /* guest entry, phys offset */
	unsigned long long stack_off; /* guest stack top, phys offset */
	unsigned long long image_len; /* init image bytes at entry_off */

	/* -- bookkeeping (kernel-only use, kept here for parity) ----- */
	u32_nt exit_code; /* observed via GetExitCodeProcess */
	u32_nt pid;       /* stub process id (kernel-side record) */
};

#endif /* __UML_STUB_NT_H */
