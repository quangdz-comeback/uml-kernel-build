/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/sigtest.c — S4d-b signal fidelity proof (runs as PID 1 via
 * init=/bin/sigtest).
 *
 * Asserts the FULL guest-signal path the M4 signals slice built:
 *
 *   1. rt_sigaction(SIGSEGV) through the REAL generic sys_rt_sigaction
 *      (SA_SIGINFO + SA_RESTORER — x86-64 always needs a restorer; the
 *      guest provides its own `mov $15,eax; syscall` trailer, which the
 *      kernel's patch scan turns into the ud2 the stub traps on).
 *   2. XMM0-3 loaded with magic values, then a NULL store faults.
 *   3. The fault becomes a REAL guest SIGSEGV: force_sig_fault →
 *      do_signal → the handler runs (SIGTEST-HANDLER).
 *   4. FIDELITY IN: the ucontext's fpstate (the FXSAVE block the
 *      kernel copied from the trap capture) still holds the magic
 *      XMM values (SIGTEST-FRAME-FP-OK) — the trap → kernel →
 *      sigframe direction.
 *   5. The handler clobbers XMM0-3 with ANTI-magic and edits
 *      uc_mcontext.rip += 6 (the faulting `movl $imm,(rax)` never
 *      replays), returns through the restorer → rt_sigreturn.
 *   6. FIDELITY OUT: sigreturn restores GP + FP from the frame —
 *      after it, XMM0-3 are the ORIGINAL magics again, not the
 *      anti values (SIGTEST-XMM-OK) — the sigframe → sigreturn →
 *      stub-resume direction. Then SIGTEST-OK, exit 0.
 *
 * Freestanding static, linked INSIDE the guest window (see Makefile).
 */
#include <stdint.h>

/* ---- x86_64 signal ABI (guest-side mirrors of the uapi layouts) -- */

struct sc64 {
	unsigned long long r8, r9, r10, r11, r12, r13, r14, r15;
	unsigned long long rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip;
	unsigned long long eflags;
	unsigned short cs, gs, fs, ss;
	unsigned long long err, trapno, oldmask, cr2, fpstate;
	unsigned long long reserved[8];
};

struct ucontext64 {
	unsigned long long uc_flags;
	struct ucontext64 *uc_link;
	unsigned long long uc_stack[3]; /* ss_sp, ss_flags(+pad), ss_size */
	struct sc64 uc_mcontext;
	unsigned long long uc_sigmask[16];
};

struct siginfo64 {
	int si_signo, si_errno, si_code;
	unsigned long long _addr; /* _sigfault._addr */
};

struct sa64 {
	void *handler;            /* ksa_handler / sa_handler */
	unsigned long long flags;
	void *restorer;           /* sa_restorer */
	unsigned long long mask;  /* sigset, 64 bits = sigsetsize 8 */
};

#define SA_SIGINFO  0x00000004ull
#define SA_RESTORER 0x04000000ull

#define SEGV_MAPERR 1
#define SEGV_ACCERR 2

/* FXSAVE layout: 32-byte header, 8 ST registers, then XMM0-15 —
 * XMM0 sits at byte 160 of the fpstate block. */
#define FXSAVE_XMM0_OFF 160u

/* ---- syscalls ------------------------------------------------------ */

static long sys_write(int fd, const void *buf, unsigned long len)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (1L), "D" ((long)fd), "S" (buf),
			    "d" (len)
			  : "rcx", "r11", "memory");
	return ret;
}

static void __attribute__((noreturn)) sys_exit(int code)
{
	__asm__ volatile ("syscall"
			  :
			  : "a" (60L), "D" ((long)code)
			  : "rcx", "r11");
	__builtin_unreachable();
}

static long sys_rt_sigaction(int sig, const struct sa64 *act,
			     struct sa64 *oact, unsigned long sigsetsize)
{
	long ret;
	register long r10 __asm__ ("r10") = (long)sigsetsize;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (13L), "D" ((long)sig), "S" (act),
			    "d" (oact), "r" (r10)
			  : "rcx", "r11", "memory");
	return ret;
}

/* ---- state --------------------------------------------------------- */

/* Distinct, byte-asymmetric (catches Low/High and index mixups). */
static const unsigned long long xmm_magic[4] = {
	0x5D4D534753530101ull,
	0x5D4D534753530202ull,
	0x5D4D534753530304ull,
	0x5D4D534753530408ull,
};
static const unsigned long long xmm_anti[4] = {
	0x1163116311631163ull,
	0x2263226322632263ull,
	0x3363336333633363ull,
	0x4464446444644464ull,
};

/* The faulting `movl $0x2a,(rax)` with rax = 0: C7 00 2A 00 00 00. */
#define FAULT_INSN_LEN 6u

/* ---- handler ------------------------------------------------------- */

static void sigsegv_handler(int sig, struct siginfo64 *si, void *uuc)
{
	struct ucontext64 *uc = uuc;
	struct sc64 *sc = &uc->uc_mcontext;
	const unsigned char *fp = (const unsigned char *)sc->fpstate;
	int i, fp_ok = 1;

	(void)sig;
	sys_write(1, "SIGTEST-HANDLER\n", 16);

	if (si->si_signo == 11 && (si->si_code == SEGV_MAPERR ||
				   si->si_code == SEGV_ACCERR))
		sys_write(1, "SIGTEST-SI-OK\n", 14);

	/* FIDELITY IN: the frame's fpstate = the trap capture. */
	for (i = 0; i < 4; i++)
		if (*(const unsigned long long *)(fp + FXSAVE_XMM0_OFF +
						  16u * (unsigned)i) !=
		    xmm_magic[i])
			fp_ok = 0;
	if (fp_ok)
		sys_write(1, "SIGTEST-FRAME-FP-OK\n", 20);
	else
		sys_write(1, "SIGTEST-FRAME-FP-BAD\n", 21);

	/* Clobber XMM with the ANTI values: the sigreturn restore must
	 * overwrite them with the frame's originals. */
	__asm__ volatile (
		"movdqu %[m0], %%xmm0\n\t"
		"movdqu %[m1], %%xmm1\n\t"
		"movdqu %[m2], %%xmm2\n\t"
		"movdqu %[m3], %%xmm3\n\t"
		:
		: [m0] "m" (xmm_anti[0]), [m1] "m" (xmm_anti[1]),
		  [m2] "m" (xmm_anti[2]), [m3] "m" (xmm_anti[3])
		: "xmm0", "xmm1", "xmm2", "xmm3", "memory");

	/* Skip the faulting instruction (a real handler would fix the
	 * pointer or siglongjmp — the edit exercises frame-driven rip
	 * control, which is the mechanism both of those rely on). */
	sc->rip += FAULT_INSN_LEN;
}

/* x86-64 must always use SA_RESTORER: the handler's ret lands here,
 * and the rt_sigreturn syscall (nr 15) undoes the frame. The kernel
 * patches this syscall to ud2 like every other. */
void sigtest_restorer(void)
{
	__asm__ volatile (
		"movq	$15, %rax\n\t"
		"syscall\n\t"
	);
	__builtin_unreachable();
}

/* ---- main ----------------------------------------------------------- */

/* Process entry (naked — no prologue may run before the realign).
 * The loader sets rsp 16-byte-aligned pointing at argc (the SysV
 * PROCESS-entry convention), but clang compiled _start as a NORMAL
 * callee (it assumes rsp+8 ≡ 0 mod 16 at entry, i.e. entered by
 * call) — the first wine run died on a movaps #AC IN THE PROLOGUE
 * (fault rip 0x62001336, misaligned by 8 after the two pushes).
 * Realign to the callee convention and jump: and $-16 then sub $8
 * simulates the return-address push a real call would have made.
 * forkwait/bench/init never tripped only because their prologues
 * emit no 16-aligned SSE before an adjustment — latent, not fixed
 * here (green gates stay untouched). */
void sigtest_main(void);
void _start(void) __attribute__((naked, noreturn));
void _start(void)
{
	__asm__ volatile (
		"andq	$-16, %rsp\n\t"
		"subq	$8, %rsp\n\t"
		"xorl	%ebp, %ebp\n\t"
		"jmp	sigtest_main\n\t"
	);
}

void sigtest_main(void)
{
	struct sa64 act;
	unsigned long long seen[4] = { 0, 0, 0, 0 };
	int i, xmm_ok = 1;

	sys_write(1, "SIGTEST-ARM\n", 12);

	act.handler = (void *)sigsegv_handler;
	act.flags = SA_SIGINFO | SA_RESTORER;
	act.restorer = (void *)sigtest_restorer;
	act.mask = 0;
	if (sys_rt_sigaction(11, &act, (struct sa64 *)0, 8) != 0) {
		sys_write(1, "SIGTEST-ACTION-BAD\n", 19);
		sys_exit(9);
	}

	/* Load the magics, then fault: NULL store. */
	__asm__ volatile (
		"movdqu %[m0], %%xmm0\n\t"
		"movdqu %[m1], %%xmm1\n\t"
		"movdqu %[m2], %%xmm2\n\t"
		"movdqu %[m3], %%xmm3\n\t"
		"xorl %%eax, %%eax\n\t"
		"movl $0x2a, (%%rax)\n\t"
		"movdqu %%xmm0, %[o0]\n\t"
		"movdqu %%xmm1, %[o1]\n\t"
		"movdqu %%xmm2, %[o2]\n\t"
		"movdqu %%xmm3, %[o3]\n\t"
		: [o0] "=m" (seen[0]), [o1] "=m" (seen[1]),
		  [o2] "=m" (seen[2]), [o3] "=m" (seen[3])
		: [m0] "m" (xmm_magic[0]), [m1] "m" (xmm_magic[1]),
		  [m2] "m" (xmm_magic[2]), [m3] "m" (xmm_magic[3])
		: "rax", "xmm0", "xmm1", "xmm2", "xmm3", "memory");

	/* FIDELITY OUT: the handler's ANTI values must be gone, the
	 * frame's originals restored by the sigreturn. */
	for (i = 0; i < 4; i++) {
		if (seen[i] != xmm_magic[i])
			xmm_ok = 0;
		if (seen[i] == xmm_anti[i])
			sys_write(1, "SIGTEST-XMM-ANTI-LEAK\n", 23);
	}
	if (xmm_ok)
		sys_write(1, "SIGTEST-XMM-OK\n", 15);

	sys_write(1, "SIGTEST-OK\n", 11);
	sys_exit(0);
}
