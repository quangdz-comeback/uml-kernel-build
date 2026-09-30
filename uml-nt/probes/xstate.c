/* SPDX-License-Identifier: GPL-2.0 */
/*
 * probes/xstate.c — can guest FP/XMM state survive the VEH round-trip
 * (and can the kernel drive a restore) on native Windows?
 *
 * S4d needs to know what the trap boundary actually does with FP state
 * before stub_data grows an xstate area (the S4c methodology: evidence
 * first, D-note after). The upstream UML contract: at EVERY trap the
 * kernel pulls the FP state out of the stub process and pushes it back
 * at every resume (get/put_fp_registers around the userspace loop) —
 * signals copy regs->fp into the sigframe and sigreturn copies it
 * back. The NT stub has no FP plumbing at all today; whether that is
 * silently lossy depends on Windows behavior this probe measures:
 *
 *   1. CAPTURE: does the exception CONTEXT carry the at-exception FP
 *      state (ContextFlags CONTEXT_FLOATING_POINT + FloatSave holding
 *      the live XMM magic)? This is the ONLY at-exception snapshot:
 *      by the time the VEH handler runs, RtlDispatchException has
 *      already executed user-mode code that may use SSE.
 *   2. DISPATCHER CLOBBER: are the LIVE XMM registers at handler
 *      entry still the magic (informational)?
 *   3. WRITEBACK: if the handler edits CONTEXT.FloatSave, does
 *      EXCEPTION_CONTINUE_EXECUTION restore the EDITED value (then a
 *      plain copy is the restore path), or the unmodified state (then
 *      the restore needs a post-restore trampoline, D18-style)?
 *   4. ROUNDTRIP: does an unmodified ud2 round-trip preserve XMM at
 *      all (is the current fault-replay path silently lossy for
 *      mid-instruction XMM state)?
 *
 * The handler is pure-integer on purpose: no printf, no SSE — nothing
 * of ours may perturb the state under test between the trap capture
 * and the globals. Evidence probe, not a gate: exit 0 with markers
 * printed either way; the CI native runner is the arbiter (wine's
 * exception path is ~2x slower and NOT representative — pitfall 8).
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Distinct magic patterns (not byte-symmetric: catches Low/High mixups
 * and register-index mixups). */
static const unsigned long long magic[4] = {
	0x5D4D534753530101ull, /* S4D-magic-0 */
	0x5D4D534753530202ull, /* S4D-magic-1 */
	0x5D4D534753530304ull, /* S4D-magic-2 */
	0x5D4D534753530408ull, /* S4D-magic-3 */
};
/* The writeback target: the handler plants this in FloatSave XMM0. */
#define WB_MAGIC 0x5D4D534753574242ull /* "S4D...WBB" */

/* --- what the handler observed (printed after the asm block) ------- */
static unsigned long long ctx_flags;
static unsigned long long fs_xmm[4];  /* FloatSave.XmmRegisters[0..3] */
static unsigned int fs_mxcsr;
static unsigned short fs_fcw;
static unsigned long long live_xmm0_at_handler;
static int float_flag_valid;
static int wrote_back;

static LONG CALLBACK ud2_veh(PEXCEPTION_POINTERS ep)
{
	CONTEXT *c = ep->ContextRecord;

	if (ep->ExceptionRecord->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION)
		return EXCEPTION_CONTINUE_SEARCH;

	ctx_flags = c->ContextFlags;
	float_flag_valid = (c->ContextFlags & CONTEXT_FLOATING_POINT) ? 1 : 0;
	/* Integer-only capture: plain memory reads of the CONTEXT. */
	fs_fcw = c->FloatSave.ControlWord;
	fs_mxcsr = c->FloatSave.MxCsr;
	fs_xmm[0] = c->FloatSave.XmmRegisters[0].Low;
	fs_xmm[1] = c->FloatSave.XmmRegisters[1].Low;
	fs_xmm[2] = c->FloatSave.XmmRegisters[2].Low;
	fs_xmm[3] = c->FloatSave.XmmRegisters[3].Low;

	/* The LIVE XMM at handler entry: the dispatcher ran user-mode
	 * code before us — this tells us how much of the state a
	 * CONTEXT-only design can still recover (informational). */
	__asm__ volatile ("movq %%xmm0, %0" : "=m" (live_xmm0_at_handler));

	/* Writeback test: plant the WB magic in the CONTEXT copy. If
	 * EXCEPTION_CONTINUE_EXECUTION restores FP from the CONTEXT,
	 * the resumed code reads it back — the plain-copy restore path
	 * exists. */
	c->FloatSave.XmmRegisters[0].Low = WB_MAGIC;
	wrote_back = 1;

	c->Rip += 2;
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void)
{
	unsigned long long out[4] = { 0, 0, 0, 0 };
	unsigned int xsave_size = 0, xsave_max = 0;
	unsigned int a, b, c2, d2;
	int i;

	__asm__ volatile ("cpuid"
			  : "=a" (a), "=b" (b), "=c" (c2), "=d" (d2)
			  : "a" (0xD), "c" (0));
	xsave_size = b;
	__asm__ volatile ("cpuid"
			  : "=a" (a), "=b" (b), "=c" (c2), "=d" (d2)
			  : "a" (0xD), "c" (1));
	xsave_max = c2;

	printf("XSTATE-CPUID-XSAVE-SIZE: enabled=%u max=%u\n",
	       xsave_size, xsave_max);

	if (!AddVectoredExceptionHandler(1, ud2_veh)) {
		printf("XSTATE-VEH-FAILED\n");
		return 0;
	}

	/* Set XMM0-3 to the magics, trap, read back what resumed. The
	 * whole sequence is ONE asm block: nothing of ours (and no
	 * compiler spill of the caller-saved XMMs) runs between the
	 * setup and the ud2, nor between the resume and the stores.
	 * movdqu on BOTH sides: the "m" operand for magic[1..3] is
	 * only 8-byte aligned (the array base is what GCC aligns) —
	 * a movdqa there is a #GP (found on the wine smoke run). */
	__asm__ volatile (
		"movdqu %[m0], %%xmm0\n\t"
		"movdqu %[m1], %%xmm1\n\t"
		"movdqu %[m2], %%xmm2\n\t"
		"movdqu %[m3], %%xmm3\n\t"
		"ud2\n\t"
		"movdqu %%xmm0, %[o0]\n\t"
		"movdqu %%xmm1, %[o1]\n\t"
		"movdqu %%xmm2, %[o2]\n\t"
		"movdqu %%xmm3, %[o3]\n\t"
		: [o0] "=m" (out[0]), [o1] "=m" (out[1]),
		  [o2] "=m" (out[2]), [o3] "=m" (out[3])
		: [m0] "m" (magic[0]), [m1] "m" (magic[1]),
		  [m2] "m" (magic[2]), [m3] "m" (magic[3])
		: "xmm0", "xmm1", "xmm2", "xmm3", "memory");

	printf("XSTATE-CTX-FLAGS: 0x%llx (FLOATING_POINT=%s)\n",
	       ctx_flags, float_flag_valid ? "set" : "CLEAR");
	printf("XSTATE-TRAP-FPW: fcw=0x%04x mxcsr=0x%08x\n",
	       fs_fcw, fs_mxcsr);
	for (i = 0; i < 4; i++)
		printf("XSTATE-TRAP-XMM%d: 0x%016llx%s\n", i, fs_xmm[i],
		       fs_xmm[i] == magic[i] ? " (magic ok)" : "");
	printf("XSTATE-HANDLER-LIVE-XMM0: 0x%016llx%s\n",
	       live_xmm0_at_handler,
	       live_xmm0_at_handler == magic[0] ? " (intact)" :
	       live_xmm0_at_handler == WB_MAGIC ? " (writeback visible?)" :
		       " (clobbered by dispatch)");
	printf("XSTATE-RESUME-XMM0: 0x%016llx%s\n", out[0],
	       out[0] == WB_MAGIC ? " (writeback STUCK — CONTEXT restore works)" :
	       out[0] == magic[0] ? " (writeback lost, original restored)" :
				    " (garbage — state not restored)");
	printf("XSTATE-RESUME-XMM1-3: %s\n",
	       (out[1] == magic[1] && out[2] == magic[2] &&
		out[3] == magic[3]) ?
	       "preserved (round-trip faithful)" :
	       "CLOBBERED (fault-replay path is lossy today)");
	printf("XSTATE-PROBE-DONE\n");
	(void)wrote_back;
	(void)xsave_max;
	return 0;
}
