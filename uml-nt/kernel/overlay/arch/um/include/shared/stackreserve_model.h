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
				   unsigned long long *target)
{
	unsigned long long t;
	int i;

	if (uml_nt_ca_runs(fullcommit, has_regs) == 0)
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
