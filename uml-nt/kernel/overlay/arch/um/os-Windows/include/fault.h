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

/* UNMAP + up to 3 MAP pieces (COW split), or an INIT plan: one MAP
 * per VMA + guard NOACCESS protects. 64 (hazard-3 slice): the uaccess
 * write fixups QUEUE ops too — one COW run fixed up mid-syscall costs
 * 4 (unmap + up to 3 piece maps), a multi-run to_user bursts several;
 * the plan is kernel-side only (the stub sees ONE op per round-trip),
 * so the cap is memory, not protocol. 64 covers UML_NT_VMA_MAX for
 * INIT plans as well. */
#define UML_NT_FAULT_MAX_OPS 64

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
