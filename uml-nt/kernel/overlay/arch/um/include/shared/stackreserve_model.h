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

#endif /* UML_NT_STACKRESERVE_MODEL_H */
