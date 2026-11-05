/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stackreserve_model.h — how many runs the answer-time reserve asks for.
 *
 * The proactive reserve used to be the whole experiment or nothing: 128 runs
 * (8 MiB) per answer starved the plan slots the boot needed, so it was switched
 * off entirely, and the third link of the stack trio went missing — a fork
 * child with correct bounds and a reservation no mapping may enter still had
 * nothing committed below its stack, so a large frame met a free page and
 * faulted.
 *
 * The helper that does the work is no longer the one that caused that storm:
 * it only ever ADDS a run-backed VMA, refuses a target any VMA already covers,
 * and preflights the plan, so an answer can ask for a small reserve safely. The
 * policy lives here so it can be tested without the kernel.
 */
#ifndef UML_NT_STACKRESERVE_MODEL_H
#define UML_NT_STACKRESERVE_MODEL_H

/* One answer commits at most this many runs (256 KiB) below the committed
 * bottom; anything deeper is the deliberate FULLCOMMIT experiment. */
#define UML_NT_CA_DEFAULT_RUNS	4
/* S34: the margin committed at conn birth. The PAM dip needs ~0x51000 (dip
 * 0x41000 + wrapper ~0x10000); six runs = 384 KiB covers it with slack, and the
 * budget at mem=120M (free 7-8 MiB, nine conns live, chain conns a handful)
 * pays 384 KiB for the handful without touching the rest. */
#define UML_NT_CA_MARGIN_RUNS	6
#define UML_NT_RUN_BYTES	0x10000ull

/*
 * `fullcommit` = the UML_NT_STACK_FULLCOMMIT experiment, `has_regs` = the answer
 * actually carries the guest's registers (without them there is no rsp to
 * anchor a reserve on, and the kernel helper would refuse anyway).
 */
static inline int uml_nt_ca_runs(int fullcommit, int has_regs)
{
	if (fullcommit)
		return 128;
	return has_regs ? UML_NT_CA_DEFAULT_RUNS : 0;
}

/*
 * S24: which rounds may reserve at all.
 *
 * A fork round is a SYSCALL round — the guest's clone(2) — so the command
 * number cannot tell it apart from an ordinary syscall, and the reserve booked
 * its run into the plan the child's spawn consumes. The parent kept the VMA and
 * never sent the MAP, and the teardown's UNMAP for that address had no view to
 * remove (487, "Attempted to kill init"). The round is identified by the fork
 * handoff that is armed for this conn while the clone is in flight, and a fork
 * round never reserves: the next ordinary answer does, and it is idempotent.
 */
static inline int uml_nt_ca_round_ok(unsigned int cmd, int fork_round)
{
	if (fork_round)
		return 0;
	return cmd == 1u /* SYSCALL */ || cmd == 3u /* FAULT */;
}

/*
 * S25: and never into a plan that is mid-drain.
 *
 * The plan is streamed a few ops per answer; when a fault arrives with ops
 * still unsent the repair RESETS the plan and the unissued tail is dropped
 * ("the repair supersedes the unissued tail"). A reserve that had queued its
 * MAP into that tail kept its VMA and lost its op — the orphan the teardown
 * later UNMAPs and the stub answers 487. Reserve only into a quiescent plan:
 * plan_left counts ops not yet sent, plan_next the drain cursor, and both must
 * be zero. Deferring costs nothing because the reserve is idempotent.
 */
static inline int uml_nt_ca_plan_ok(unsigned long long plan_left,
				    unsigned long long plan_next)
{
	return plan_left == 0 && plan_next == 0;
}

/*
 * S31: the release side has a contract too — only release a view that exists.
 *
 * The fork's COW re-protect walks every writable shared VMA and queues
 * UNMAP+MAP: drop the writable view, put a read-only one back. For a VMA whose
 * view the stub never received (a reserve whose MAP was still owed) the UNMAP
 * names an address the stub has no view for — 487, a KILL, and init dead. When
 * the ledger has no view, the pair is wrong in both halves: there is nothing to
 * release, and the MAP that was owed is exactly what materializes it.
 */
static inline int uml_nt_reprotect_release_first(int has_view)
{
	return has_view ? 1 : 0;
}

/* One view of the conn, as the predicate needs it. */
struct uml_nt_ca_view {
	unsigned long long va, len;
};

/*
 * May this answer reserve a run, and which one?
 *
 * The reserve exists for the guest's own stack, so it must land inside the
 * conn's reservation and must not collide with anything the conn has already
 * mapped — a probe mapping of the caller's own lives in exactly such a place,
 * and committing over it made the caller's UnmapViewOfFile fail (487) and the
 * stub was killed. Returns 1 and sets `target` when a reserve is wanted.
 */
static inline int uml_nt_ca_target(unsigned long long rsp, unsigned long long lo,
				   unsigned long long hi, int has_regs,
				   int fullcommit,
				   const struct uml_nt_ca_view *views, int nviews,
				   int login_chain,
				   unsigned long long *target)
{
	unsigned long long t;
	int i;

	if (uml_nt_ca_runs(fullcommit, has_regs) == 0)
		return 0;
	/* S23: scoped to the conn this milestone is about. The reserve exists
	 * to keep one particular stack alive — the login chain's — and enabling
	 * it for every conn made an unrelated gate fail: a canary conn's own
	 * probe mapping was in the way of an UNMAP. Until that is understood,
	 * only the login chain reserves. */
	if (!login_chain)
		return 0;
	if (lo == 0 || hi == 0 || lo >= hi)
		return 0;
	if (rsp < lo || rsp > hi)
		return 0;
	if (rsp < UML_NT_RUN_BYTES)
		return 0;
	/* the run just below the one rsp sits in, like the kernel's
	 * committed_bottom - run */
	t = (rsp & ~(UML_NT_RUN_BYTES - 1)) - UML_NT_RUN_BYTES;
	if (t < lo)
		return 0;
	if (views != 0)
		for (i = 0; i < nviews; i++)
			if (t < views[i].va + views[i].len &&
			    t + UML_NT_RUN_BYTES > views[i].va)
				return 0;
	if (target != 0)
		*target = t;
	return 1;
}

#endif /* UML_NT_STACKRESERVE_MODEL_H */
