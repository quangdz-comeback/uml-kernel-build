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
#define UML_NT_FAULT_WATCHPT 0x10u /* v13 DR watchpoint report (no
				    * repair; the store already
				    * landed — pure witness) */

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

/* The FAULT-side witness: a write fault on a non-COW VMA whose run is
 * SHARED (refs >= 2) = the restore-W remap stomps the sharer's memory
 * (the heap-trasher stomp itself). The caller (owning the round:
 * pid/nr/ret/rip) prints when uml_nt_cowbreak_faults increments. */
extern int uml_nt_cowbreak_faults;
extern unsigned int uml_nt_cowbreak_prot, uml_nt_cowbreak_flags;

/* 098 δ: kernel-direct write census. Called by every bulk-write site
 * (fork seed/eager copies, the brk re-home, the sweep patcher, the
 * zero fills) with the physmem offset + length it is about to write;
 * prints when the range touches a cowwatch-armed run. stub_ctl.c
 * owns the ring. */
void uml_nt_cowwatch_touch(unsigned long long off, unsigned long long len,
			   const char *what);

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

/* ---- M5.6a root-cause fix: the table<->view swap window airtight --
 * Pure protocol core, host-tested in test_mm.c. See the block comment
 * at the helpers' definitions in fault.c (dl18 37512134759, [tcekey]
 * verdict MATCH: run-granular lost-update at the swap window). */

/*
 * All-or-nothing capacity: 0 when plan can hold `need` MORE ops
 * (n_ops + need <= MAX_OPS), -1 when not. A table mutation that
 * queues view ops reserves FIRST and refuses (Linux failure
 * semantics) when this fails — a view op silently dropped by a full
 * plan strands the stub's view on a run the table no longer owns
 * (the K3 uaccess-fixup precedent, referee 37137513174).
 */
int uml_nt_fault_plan_reserve(const struct uml_nt_fault_plan *plan,
			      int need);

/*
 * The apply-time guard for a MAP op: 1 when the CURRENT VMA table
 * still backs the op's exact range with the op's own run (both
 * endpoints translate to op->off), 0 when the table moved under the
 * op (re-home/munmap/fixup after queueing) or the op claims a range
 * the table does not own. PROTECT/UNMAP carry no backing claim and
 * always pass. The conn layer REFUSES (kills) a MAP op that fails
 * this — applying it would hand the guest a wrong-backed view.
 */
int uml_nt_fault_op_backed(const struct uml_nt_fault_op *op,
			   const struct uml_nt_mm *mm);

/*
 * A MAP op whose view the plan itself tears down before it
 * completes: 1 when a LATER op in the SAME plan is an UNMAP at
 * the op's own base va (UnmapViewOfFile releases the view AT its
 * base — the stub's do_action — so a same-base UNMAP queued
 * behind the MAP is exactly "this view gets released in-plan").
 * The chained multi-run COW writeback queues this shape: a
 * writeback crossing the run boundary of a multi-run shared VMA
 * runs two cow fixups into ONE plan, and the first fixup's
 * re-map of the still-shared tail is superseded by the second
 * fixup's corrective UNMAP/MAP pair. Intermediate views are
 * invisible to the guest: it stays parked in the stub's
 * action_chain until the plan drains (ACTION_NONE). 0 when the
 * op is NULL, not a MAP, outside the plan, or nothing behind it
 * releases its view.
 */
int uml_nt_fault_op_superseded(const struct uml_nt_fault_op *op,
			       const struct uml_nt_fault_plan *plan);

/*
 * The apply-time MAP decision: 1 when the op may issue — its
 * view survives the plan AND the CURRENT VMA table backs its
 * exact range with its own run (uml_nt_fault_op_backed: the
 * final-backing invariant — no surviving view may map a backing
 * the table does not own), OR its view is superseded in-plan
 * (released before the plan completes; the corrective ops
 * queued behind it repair the view state the plan itself will
 * produce). 0 = refuse: applying it would strand a wrong-backed
 * view with no in-plan repair.
 */
int uml_nt_fault_op_allowed(const struct uml_nt_fault_op *op,
			    const struct uml_nt_fault_plan *plan,
			    const struct uml_nt_mm *mm);

/*
 * The COMPLETE view-release set for a whole-VMA munmap of [s, e):
 * one UNMAP op per VMA fully inside the range, into ops[0..max).
 * Returns the op count, 0 when the range intersects nothing,
 * -1 when there are more views than max, -2 when a VMA straddles
 * the range edges (whole views only — the munmap contract).
 * UnmapViewOfFile releases the WHOLE view at map_va: one op for a
 * multi-VMA range released only the first view and stranded the
 * rest over dropped, recycled runs (the split-brain class).
 */
int uml_nt_fault_munmap_views(const struct uml_nt_mm *mm,
			      unsigned long long s, unsigned long long e,
			      struct uml_nt_fault_op *ops, int max);

/* ---- K6 (M5.6a, feature cowcopy-race-class-fix, dl26 37539992560):
 * the per-view release-set completeness — the view ledger ----
 *
 * The dl26 verdict (cowcopy-race-witness, af7aa78): pid 7484's own
 * tcache_put pair (e->next, e->key) landed in the ABANDONED source
 * run 0x4090000 AFTER the fault-path COW copy moved the table to
 * 0x11b0000 (running=0 at all 129 arms — the vector is the SAME
 * stub, not a concurrent sharer). UnmapViewOfFile releases the ONE
 * view at the given base, so a re-homing plan's UNMAP-at-range-
 * start releases only the view whose base equals that start — any
 * other issued view covering the re-homed range (a chained COW
 * split's piece view, a stale survivor) stays mapped, writable,
 * over the abandoned backing, and every later guest store through
 * it lands in a run the table no longer owns (the D22/D25
 * invariant broken silently). This is the same class that
 * uml_nt_fault_munmap_views closed for munmap in 6d3c932,
 * generalized: the conn keeps a LEDGER of every view its op
 * stream issues (stub_ctl.c issue_plan_op records MAPs, retires
 * at UNMAP bases, updates prots on PROTECTs), and every re-homing
 * plan — fault-path COW split/copy, uaccess COW fixup, brk
 * re-home, mmap MAP_FIXED replace, fork re-protect — is AUGMENTED
 * at prime time with the COMPLETE per-view release set for the
 * ranges it releases, each release at the view's OWN base.
 *
 * The helpers are pure logic, host-tested in test_mm.c
 * (test_release_set): the chained-split-over-multiple-bases
 * regression the fix mandates. */

/* One issued stub view (the ledger entry). va IS the view's BASE —
 * the only address UnmapViewOfFile accepts; len/off/prot are the
 * census's bookkeeping (what the view maps, and how). */
struct uml_nt_view {
	unsigned long long va;  /* the view's BASE */
	unsigned long long len; /* byte length of the view */
	unsigned long long off; /* section offset the view maps */
	unsigned prot;          /* the NT prot the view last carried */
};

/* The ledger cap: views are 1:1 with table VMAs (every MAP op
 * pairs with the VMA it materializes), so the VMA table's own cap
 * bounds it — an overflow is a broken protocol state, killed
 * loud at issue time, never silently dropped. */
#define UML_NT_VIEW_MAX UML_NT_VMA_MAX

/*
 * Record/refresh one view in the ledger (base-exact upsert: a
 * re-MAP at an occupied base replaces the entry — the stub would
 * refuse the mapping outright otherwise). Returns 0, -1 when the
 * ledger is full (the caller refuses loud) or the args are bad.
 * Pure logic.
 */
int uml_nt_view_track(struct uml_nt_view *vs, int *n, int max,
		      unsigned long long va, unsigned long long len,
		      unsigned long long off, unsigned prot);

/*
 * Union containment — the drain-side census's core test: 1 when
 * every byte of [base, base+len) lies inside SOME ledger view.
 * Adjacent same-prot section views can read as ONE VirtualQueryEx
 * region, so coverage must be by UNION, never by a single view
 * (a single-view test false-refuses exactly the healthy fork
 * re-protect drains). 0 when any part is uncovered. Pure logic.
 */
int uml_nt_view_region_covered(const struct uml_nt_view *vs, int n,
			       unsigned long long base,
			       unsigned long long len);

/*
 * THE release-set completeness: walk `plan`'s UNMAP ops and, for
 * every ledger view that INTERSECTS a released range but is NOT
 * already released at its own base by the plan's own UNMAPs,
 * insert an UNMAP at that view's base directly after the
 * triggering op — BEFORE any later re-MAP can collide with the
 * still-occupied range. Inserted ops are releases themselves and
 * never re-trigger. Returns the number inserted, -1 when the plan
 * cannot hold the complete set (the caller refuses LOUD — a
 * dropped release is the stranding class itself). Pure logic,
 * host-tested (test_mm.c test_release_set).
 */
int uml_nt_fault_augment_release_set(struct uml_nt_fault_plan *plan,
				     const struct uml_nt_view *vs, int n);

#endif /* __UM_OS_WINDOWS_FAULT_H */
