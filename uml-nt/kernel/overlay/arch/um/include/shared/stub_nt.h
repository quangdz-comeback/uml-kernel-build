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
#define UML_STUB_VERSION 4u /* v4: per-VMA views + INIT plan + fork (M3.3) */
/* Section size (also the map granularity guard). */
#define UML_STUB_SECTION_SIZE 0x10000u

/* Bootstrap block offset: the first cache line of the section. The
 * kernel fills it before ResumeThread; the stub maps the section and
 * validates it before doing anything else. */
#define UML_STUB_BOOT_OFFSET 0

/* Requests (stub → kernel, slot.cmd). The kernel dispatches syscalls
 * on regs.rax (upstream parity — the cmd only classifies the trap);
 * faults carry their own fault_addr/fault_type fields. */
#define UML_STUB_CMD_SYSCALL   1u /* ud2 trap: guest syscall (v1 name
				   * was WRITE — misleading, the kernel
				   * never dispatched on it) */
#define UML_STUB_CMD_EXIT      2u /* reserved numbering; the halt flag
				   * is the real transport (M2.2) */
#define UML_STUB_CMD_FAULT     3u /* AV in guest code → fault round-trip */
#define UML_STUB_CMD_PROT_DONE 4u /* result of the last ACTION_* (retval) */
#define UML_STUB_CMD_INIT      5u /* first request: stream the initial
				   * per-VMA map plan before guest entry */

/* Answers (kernel → stub, slot.action). */
#define UML_STUB_ACTION_NONE 0u /* handled — resume the guest */
#define UML_STUB_ACTION_PROT 1u /* stub: VirtualProtect(page, prot) */
#define UML_STUB_ACTION_KILL 2u /* fatal: park, kernel terminates us */
#define UML_STUB_ACTION_MAP  3u /* stub: map section view [map_va,
				 * map_len) from offset map_off with
				 * map_prot (per-VMA view, M3 model) */
#define UML_STUB_ACTION_UNMAP 4u /* stub: unmap [map_va, map_len) */

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
	/* M3 model: the stub has NO flat physmem view — its address
	 * space is built by per-VMA views streamed over CMD_INIT
	 * before entry. entry_va/stack_va are real guest VAs (the
	 * probe uses RAM_BASE + phys offset, identity by convention).
	 * init_regs are applied before the jump — fork hands the
	 * child the parent's register snapshot with rax = 0. The
	 * stub_data section itself maps at the FIXED va 0x10000000
	 * (below the guest span) so the NT allocator never lands
	 * inside [ram_base, ram_base+ram_size). */
	unsigned long long ram_base;  /* guest VA span base (fault filter) */
	unsigned long long ram_size;  /* guest VA span bytes */
	unsigned long long entry_va;  /* guest entry VA */
	unsigned long long stack_va;  /* guest stack top VA */
	struct uml_nt_gp_regs init_regs; /* applied pre-jump */

	/* -- bookkeeping (kernel-only use, kept here for parity) ----- */
	u32_nt exit_code; /* observed via GetExitCodeProcess */
	u32_nt pid;       /* stub process id (kernel-side record) */

	/* -- v2: page-fault round-trip (M3.1) ------------------------ */
	/* Filled by the stub for CMD_FAULT: ExceptionInformation[0] is
	 * the access class (0=read, 1=write, 8=DEP execute),
	 * [1] the faulting guest VA. The kernel answers with an
	 * action; the stub executes it and reports via CMD_PROT_DONE
	 * (retval = 1 ok / 0 failed), then resumes on ACTION_NONE. */
	unsigned long long fault_addr;
	u32_nt fault_type;
	u32_nt action; /* UML_STUB_ACTION_* */
	u32_nt prot;   /* ACTION_PROT: NT PAGE_* constant */
	u32_nt _pad_fault;

	/* -- v3: ACTION_MAP/UNMAP/PROT operands ---------------------- */
	/* One op per round-trip (the slot is single-outstanding by
	 * design — M3.2). MAP: [map_va, map_va+map_len) is a fresh
	 * view of the physmem section from offset map_off (64K
	 * aligned) with map_prot; UNMAP releases that range; PROT
	 * protects [map_va, map_va+map_len) to prot (fault fix-ups
	 * and INIT-plan guard pages alike — not only fault_addr). */
	u32_nt map_prot;
	u32_nt _pad_map;
	unsigned long long map_va;
	unsigned long long map_len;
	unsigned long long map_off;
};

#endif /* __UML_STUB_NT_H */
