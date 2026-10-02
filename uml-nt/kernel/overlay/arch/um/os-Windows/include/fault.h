/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fault.h — guest page-fault decision (M3.2), uml-nt.
 *
 * Upstream analogue: arch/um/kernel/tlb.c fault handling + the VMA
 * walk in handle_mm_fault() — on Linux the host MMU delivers a
 * SIGSEGV/SIGTRAP and the kernel consults its VMA tree. On NT the
 * stub's VEH delivers STATUS_ACCESS_VIOLATION with the access class +
 * faulting VA; uml_nt_mm_fault() consults the per-mm VMA manager
 * (vma.h) and produces a PLAN: the stub ops (unmap/map/protect) that
 * fix the guest view, plus a kernel-side copy directive for COW.
 *
 * Geometry contract (vma.h): VMAs are 64K-run multiples — the guest
 * kernel 64K-aligns every mapping (upstream UML constrains guest VA
 * layout for host-side reasons the same way). That keeps every
 * MapViewOfFile offset 64K-aligned through any COW split.
 *
 * Pure logic, no kernel includes: the unit test compiles fault.c
 * standalone on Linux CI (same pattern as scan_patch.c).
 */
#ifndef __UM_OS_WINDOWS_FAULT_H
#define __UM_OS_WINDOWS_FAULT_H

#include <vma.h>

#ifndef UML_NT_FAULT_PAGE_SIZE /* owned by vma.h since M4 slice 5 */
#define UML_NT_FAULT_PAGE_SIZE 0x1000ull /* guest page granularity */
#endif

/* ExceptionInformation[0] access classes for STATUS_ACCESS_VIOLATION
 * (NT exception record contract; 8 = DEP — execute on non-exec page). */
#define UML_NT_FAULT_READ  0u
#define UML_NT_FAULT_WRITE 1u
#define UML_NT_FAULT_EXEC  8u

/* Stub ops in a plan — the codes ARE the stub actions (1:1 with
 * UML_STUB_ACTION_*; test_mm asserts the mirroring). */
#define UML_NT_FOP_PROTECT 1u
#define UML_NT_FOP_MAP     3u
#define UML_NT_FOP_UNMAP   4u

/* COW-BREAK AUDIT (M5.6a): uml_nt_mm_init_plan counts the emitted
 * MAP ops that map a SHARED run (refs >= 2) WRITABLE — a write
 * through such a view skips the COW fault and eats the sharer's
 * memory (the heap-trasher class: cowwatch runs 37014552047 +
 * 37017936382 — the writer = the fork child's own malloc init at
 * nr=56/clone, rip = the glibc clone wrapper). Pure-file globals:
 * the caller logs them at the INIT round. */
extern int uml_nt_cowbreak_audit_count;
extern unsigned long long uml_nt_cowbreak_va, uml_nt_cowbreak_run;
extern int uml_nt_cowbreak_refs;

/* UNMAP + up to 3 MAP pieces (COW split), or an INIT plan: one MAP
 * per VMA + guard NOACCESS protects. The plan is kernel-side only
 * (the stub sees ONE op per round-trip), so the cap is memory, not
 * protocol: it lives embedded in the conn (kzalloc) — 256 ops * 32B
 * = 8KB, no kernel-stack copies.
 *
 * 64 was the hazard-3 slice number and it broke the fork re-protect
 * (run 36787150906): the fork answer re-protects the parent's
 * writable COW views read-only at 2 ops per view — 64 ops capped
 * that at EXACTLY 32 views ("fork: re-protected 32 parent view(s)"
 * on every fork), and the rest of the parent's ~40 writable views
 * kept their WRITABLE stub views over runs shared with the child.
 * The parent's post-fork writes then landed on the child's pages
 * without faulting — no COW machinery — and the child read torn
 * malloc metadata (wild list nodes 0x61432 / -1 in the executors,
 * SIGSEGV 'w'). 256 covers the systemd boot: ~50 VMAs (INIT plans),
 * ~40 writable views * 2 ops, plus the uaccess fixup bursts (4 per
 * COW run fixed mid-syscall). */
#define UML_NT_FAULT_MAX_OPS 256

/* The VEH dispatch window (c00000fd fix, archive 065 work order):
 * Windows builds the exception dispatch state (EXCEPTION_RECORD +
 * full CONTEXT + xstate, ~12KB) on the guest stack BELOW the trap
 * rsp at EVERY trap, and the stub's own VEH handler + do_action
 * frames push deeper still (ntdll MapViewOfFileEx/VirtualProtect run
 * mid-answer). When the committed (RW) extent below the trap rsp is
 * smaller than that, the dispatch machinery itself faults and NT
 * latches STATUS_STACK_OVERFLOW (c00000fd) — an exception class the
 * stub's VEH does not own ("UNOWNED exception c00000fd", 3/8 runs of
 * session R15/R16, byte-identical: RW region = [rsp-page, stack top),
 * everything below non-RW inside the very same mapped view). Only
 * kernel-queued OPS change stub views, so only op-carrying rounds
 * can break the window: the kernel re-asserts it at every
 * op-carrying answer (uml_nt_stack_window_plan, called from
 * serve_conn). Spawn needs nothing extra: the INIT plan maps whole
 * VMAs, so a fresh conn's stack run starts fully RW. */
#define UML_NT_STACK_GROW_AHEAD 0x4000ull /* 16KB below the trap rsp */

struct uml_nt_fault_op {
	unsigned op;   /* UML_NT_FOP_* */
	unsigned prot; /* MAP/PROTECT: NT PAGE_* */
	unsigned long long va;  /* guest VA (PROTECT: page base) */
	unsigned long long len; /* bytes (PROTECT: 4096) */
	unsigned long long off; /* section offset, 64K aligned (MAP) */
};

struct uml_nt_fault_plan {
	int kill;        /* 1 = fatal: stub parks, kernel terminates */
	char kill_why;   /* kill reason: 'w' wild VMA, 'b' page outside
			  * the VMA, 'p' RO write, 'r' unreadable read,
			  * 'x' DEP exec, 'o' plan full, 'a' alloc fail,
			  * 's' split fail, '?' unknown access class;
			  * 0 = not a kill decision */
	int n_ops;
	struct uml_nt_fault_op ops[UML_NT_FAULT_MAX_OPS];
	/* COW copy directive (integration: kernel memcpy through its
	 * own flat view, 64K run, BEFORE the ops reach the stub).
	 * copy_src_off == 0 && copy_dst_off == 0 = none. */
	unsigned long long copy_src_off;
	unsigned long long copy_dst_off;
};

/*
 * Decide one guest page fault against the mm's VMA tree.
 *
 * Returns 0 with a repair plan (ops for the stub) when the fault is
 * recoverable, -1 with plan->kill = 1 when it is fatal (wild pointer,
 * unknown access class, write to read-only VMA, physmem exhausted —
 * every fail path loud). `addr` is the raw faulting VA.
 */
int uml_nt_mm_fault(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
		    unsigned long long addr, unsigned type,
		    struct uml_nt_fault_plan *plan);

/*
 * Re-assert the VEH dispatch window below `rsp` as PROTECT ops
 * (grow-ahead — the c00000fd fix; see UML_NT_STACK_GROW_AHEAD).
 * Pure logic. The window is [rsp - GROW_AHEAD, rsp-page-end) clamped
 * into the WRITABLE VMA containing rsp-1 (M3.3: rsp = the first byte
 * PAST the stack); guard ranges keep their NOACCESS (prot semantics
 * are the fault truth — the segments split around them). Ops carry
 * the VMA's EFFECTIVE protection: a COW-shared run re-asserts
 * READ-ONLY (re-asserting RW there would break fork sharing — that
 * state is an invariant sighting for the log, not something to hide).
 * Fills up to max_ops ops; returns the op count, 0 when there is
 * nothing to assert (no writable VMA at rsp — e.g. a POC bootstrap
 * rsp), -1 when the window's run shows 0 refs (stolen — the map-049
 * contract; the caller logs once and skips), -2 when the segments
 * exceed max_ops.
 */
int uml_nt_stack_window_plan(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			     unsigned long long rsp,
			     struct uml_nt_fault_op *ops, int max_ops);

/*
 * Build the INIT plan for a (fresh or forked) stub: MAP every VMA
 * with its EFFECTIVE protection (COW-shared VMAs map read-only — the
 * first write faults into the private copy). The caller may append
 * extra ops (e.g. guard pages NOACCESS) — up to MAX_OPS total.
 * Returns 0, -1 when the mm does not fit the plan.
 */
int uml_nt_mm_init_plan(const struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			struct uml_nt_fault_plan *plan);

/* The protection a VMA is mapped with RIGHT NOW: COW-shared writable
 * VMAs map read-only (writes must fault to reach the COW logic). */
unsigned uml_nt_vma_effective_prot(const struct uml_nt_vma *vma,
				   struct uml_nt_phys *ph);

#endif /* __UM_OS_WINDOWS_FAULT_H */
