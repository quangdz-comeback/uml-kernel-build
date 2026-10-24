/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uml-nt: the trap → resume boundary contract — the pure half.
 *
 * M5.6a writer-hunt follow-up (to-shelley 148-UPDATE 3/4, Shelley's
 * ruling): the login-depth deaths are byte-shifted ENTRIES into
 * ld-linux `_dl_find_dso_for_object` (0xb57d = the last byte of the
 * `je` at 0xb578, 0xb582 = the `lea` at 0xb581 minus its REX, 0xb5b8/
 * 0xb5bb = inside the `jne` at 0xb5b6) — and systemd's zero-tail at
 * 0x1b57e. The VEH classified traps by exception code alone
 * (STATUS_ILLEGAL_INSTRUCTION ⇒ syscall), so a wild illegal
 * instruction was dispatched with rax-as-nr and resumed at rip+2
 * (ab boot: nr=0x6001b560 — a code address — then nr=-ENOSYS, then a
 * store to address -ENOSYS). Every resume MUST land on the boundary it
 * claims:
 *
 *  - the syscall path exists ONLY for the D20 sentinel (0f 0b) the
 *    sweep wrote over every real `syscall` (0f 05); anything else is
 *    REJECTED (report_unowned; never rip+2);
 *  - the syscall resume advances exactly the 2-byte ud2;
 *  - the signal-restart rewind is exactly those 2 bytes back onto the
 *    sentinel, so the re-executed trap carries the restored nr;
 *  - an access fault resumes at the faulting rip (verbatim);
 *  - a signal delivery/rt_sigreturn push is verbatim (the kernel's
 *    exact target — no arithmetic applies).
 *
 * Shared with tests/test_resume.c (and the stub): no Windows types.
 */
#ifndef UML_NT_RESUME_MODEL_H
#define UML_NT_RESUME_MODEL_H

#define UML_NT_RESUME_UD2_0 0x0fu
#define UML_NT_RESUME_UD2_1 0x0bu
#define UML_NT_RESUME_UD2_LEN 2ull

enum uml_nt_resume_class {
	UML_NT_RESUME_SYSCALL = 1, /* the sentinel: resume at rip+2 */
	UML_NT_RESUME_FAULT,	   /* access fault: resume at rip */
	UML_NT_RESUME_VERBATIM,	   /* kernel-supplied target (signal) */
	UML_NT_RESUME_REJECT,	   /* illegal instruction off the
				    * sentinel: no resume target — the
				    * task must die unowned, never be
				    * advanced past foreign bytes */
};

/* The trap bytes spell the patched syscall instruction. */
static inline int uml_nt_resume_is_ud2(const unsigned char *b)
{
	return b[0] == UML_NT_RESUME_UD2_0 &&
	       b[1] == UML_NT_RESUME_UD2_1;
}

/* The VEH's syscall gate: an illegal instruction is a syscall ONLY
 * when the trap site's TWO bytes (read through the stub's OWN view —
 * the table may diverge) are the sentinel. An unreadable site (region
 * edge) cannot be validated and is rejected. */
static inline int uml_nt_resume_illegal_is_syscall(int illegal,
						   int readable,
						   const unsigned char *b)
{
	return illegal && readable && uml_nt_resume_is_ud2(b);
}

static inline int uml_nt_resume_classify_illegal(int illegal, int readable,
						 const unsigned char *b)
{
	return uml_nt_resume_illegal_is_syscall(illegal, readable, b) ?
		UML_NT_RESUME_SYSCALL : UML_NT_RESUME_REJECT;
}

static inline int uml_nt_resume_classify_fault(void)
{
	return UML_NT_RESUME_FAULT;
}

static inline unsigned long long
uml_nt_resume_syscall_target(unsigned long long trap_rip)
{
	return trap_rip + UML_NT_RESUME_UD2_LEN;
}

/* do_signal's restart: UPT_IP -= 2 — back onto the syscall
 * instruction so the guest re-executes the trap with the nr the
 * generic code restored into ax (PT_REGS_ORIG_SYSCALL = AX for x86
 * UML, arch/um/kernel/signal.c). */
static inline unsigned long long
uml_nt_resume_restart_target(unsigned long long post_rip)
{
	return post_rip - UML_NT_RESUME_UD2_LEN;
}

/* A resume target is on the claimed boundary when it is the trap
 * itself (fault/restart/verbatim) or the far side of the 2-byte
 * syscall instruction. */
static inline int uml_nt_resume_is_boundary(unsigned long long insn_rip,
					    unsigned long long target)
{
	return target == insn_rip ||
	       target == insn_rip + UML_NT_RESUME_UD2_LEN;
}

/* The kernel-side expected resume for a round — what the stub's own
 * d->resume_rip must equal at the next trap. `verbatim` is set when
 * signal delivery (or rt_sigreturn) pushed the state; the pushed rip
 * then wins. */
static inline unsigned long long
uml_nt_resume_expected(int syscall_cmd, unsigned long long trap_rip,
		       int verbatim, unsigned long long verbatim_rip)
{
	if (verbatim)
		return verbatim_rip;
	if (syscall_cmd)
		return uml_nt_resume_syscall_target(trap_rip);
	return trap_rip;
}

#endif /* UML_NT_RESUME_MODEL_H */
