/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uml-nt: the replay single-step (TF) state machine — the pure half.
 *
 * The stub's VEH re-executes a fault-repaired store under EFLAGS.TF so
 * the post-store #DB can read the landing back (stub_nt.h v10). TF is
 * the STUB's one-shot instrument: the guest never owns it, the kernel
 * must never see it, and no resume may carry it except the replay
 * trampoline's own popfq. The 0x80000004 class (referees 39798056175,
 * 39809900440 — "died silently (STATUS_SINGLE_STEP) last cmd=4") was
 * exactly those invariants broken: a trap context captured inside the
 * window handed TF to the kernel (pt_regs, the sigframe, the verbatim
 * push), a later resume restored it with nothing armed, and the stray
 * #DB fell through to the VEH's unowned path — CONTINUE_SEARCH, the
 * process dies with the exception code (0x8 class: report_unowned's
 * 0xC filter kept it silent). Shared with tests/test_ss.c: no Windows
 * types here.
 */
#ifndef UML_NT_SS_MODEL_H
#define UML_NT_SS_MODEL_H

#define UML_NT_EFLAGS_TF 0x100ull

/* The longest x86 instruction: the post-store rip is at most this far
 * past the store's door. */
#define UML_NT_SS_INSN_MAX 15ull

/* A trap context's flags on their way to the kernel. */
static inline unsigned long long
uml_nt_ss_capture_flags(unsigned long long eflags)
{
	return eflags & ~UML_NT_EFLAGS_TF;
}

/* A register snapshot's flags on their way into a resume context. */
static inline unsigned long long
uml_nt_ss_resume_flags(unsigned long long eflags)
{
	return eflags & ~UML_NT_EFLAGS_TF;
}

enum uml_nt_ss_class {
	UML_NT_SS_DR_HIT = 1,	/* Dr6.B0-3: a hardware watchpoint fired
				 * — the DR filter decides, armed or not */
	UML_NT_SS_HOP,		/* TF step inside the replay trampoline or
				 * at the store's door: re-raise TF, go on */
	UML_NT_SS_POST_STORE,	/* TF step right past the armed store: the
				 * readback runs, TF off, the arm is spent */
	UML_NT_SS_STRAY,	/* a #DB the window does not admit: TF off,
				 * record it, continue — NEVER fatal */
};

static inline int
uml_nt_ss_classify(unsigned long long dr6, unsigned long long ss_page,
		   unsigned long long rip, unsigned long long target,
		   unsigned long long tf_lo, unsigned long long tf_hi)
{
	if (dr6 & 0xfull)
		return UML_NT_SS_DR_HIT;
	if (ss_page == 0)
		return UML_NT_SS_STRAY;
	if (rip == target || (rip >= tf_lo && rip < tf_hi))
		return UML_NT_SS_HOP;
	if (rip > target && rip - target <= UML_NT_SS_INSN_MAX)
		return UML_NT_SS_POST_STORE;
	return UML_NT_SS_STRAY;
}

/* The arm epoch: the page a fault round arms, or 0. Every round
 * decides its own — a fault the decoder refuses arms nothing (the
 * previous arm must not ride into this resume), and a spent verify
 * budget arms nothing (an instrument whose verdicts are exhausted
 * must not perturb the guest). */
static inline unsigned long long
uml_nt_ss_arm_page(int decodable, int verify_budget,
		   unsigned long long fault_addr)
{
	if (!decodable || verify_budget <= 0)
		return 0;
	return fault_addr & ~0xfffull;
}

#endif /* UML_NT_SS_MODEL_H */
