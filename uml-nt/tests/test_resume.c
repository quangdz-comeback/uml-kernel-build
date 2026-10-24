/* The resume-boundary model — M5.6a writer-hunt follow-up (Shelley
 * 148-UPDATE 3/4 ruling).
 *
 * Red-first for the byte-shifted-entry class: exception RIPs at
 * ld-linux 0xb57d/0xb582/0xb5b8/0xb5bb (and systemd's zero-tail
 * 0x1b57e/0x1b582) are ENTRIES INTO the middle of an instruction.
 * The VEH's syscall gate was exception-code only
 * (STATUS_ILLEGAL_INSTRUCTION => syscall), so ANY wild illegal
 * instruction was dispatched with rax-as-nr and resumed at rip+2 —
 * observed in the ab boot: nr=1610724704 (0x6001b560), then
 * nr=-ENOSYS, then a store to address -ENOSYS. The model is the
 * pure contract: only the D20 sentinel (0f 0b) may take the syscall
 * path; every other resume arithmetic (restart -2, verbatim, fault)
 * must land on the instruction boundary it claims. */
#include <stdio.h>
#include <string.h>
#include "resume_model.h"

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
	} } while (0)

static unsigned long long
resume_target(int cls, unsigned long long rip, unsigned long long verbatim)
{
	switch (cls) {
	case UML_NT_RESUME_SYSCALL:
		return uml_nt_resume_syscall_target(rip);
	case UML_NT_RESUME_FAULT:
		return rip;
	case UML_NT_RESUME_VERBATIM:
		return verbatim;
	default:
		return ~0ull; /* REJECT: no resume target exists */
	}
}

int main(void)
{
	/* The bytes at the observed death sites (Debian bookworm
	 * ld-linux 2.36, extracted from the referee image):
	 *   0xb578: 0f 84 90 02 00 00   je
	 *   0xb57e: 48 89 cb            mov %rcx,%rbx
	 *   0xb581: 4c 8d 3d a0 84 02 00 lea
	 *   0xb5b6: 0f 85 ac 01 00 00   jne
	 * A trap at any of these addresses is NOT a patched syscall. */
	static const unsigned char je_bytes[8]    = {0x0f,0x84,0x90,0x02,0x00,0x00,0x00,0x00};
	static const unsigned char mid_bytes[8]   = {0x00,0x00,0x00,0x70,0x65,0x32,0xd3,0xfc};
	static const unsigned char jne_bytes[8]   = {0x0f,0x85,0xac,0x01,0x00,0x00,0x48,0x89};
	static const unsigned char ud2_bytes[8]   = {0x0f,0x0b,0x48,0x83,0xc4,0x08,0xc3,0x90};

	/* 1. The sentinel: only 0f 0b is a syscall site. */
	CHECK(uml_nt_resume_is_ud2(ud2_bytes));
	CHECK(!uml_nt_resume_is_ud2(je_bytes));
	CHECK(!uml_nt_resume_is_ud2(jne_bytes));
	CHECK(!uml_nt_resume_is_ud2(mid_bytes));

	/* 2. STATUS_ILLEGAL_INSTRUCTION off the sentinel is NOT a
	 *    syscall — the wild trap must never be resumed at rip+2.
	 *    The death sites: 0xb578 is the je START (a valid boundary
	 *    but not a syscall), 0xb57d/0xb5b8/0xb5bb are mid-insn. */
	CHECK(uml_nt_resume_illegal_is_syscall(1, 1, ud2_bytes));
	CHECK(!uml_nt_resume_illegal_is_syscall(1, 1, je_bytes));
	CHECK(!uml_nt_resume_illegal_is_syscall(1, 1, mid_bytes));
	CHECK(!uml_nt_resume_illegal_is_syscall(1, 1, jne_bytes));
	/* An unreadable trap site (region edge) cannot be validated. */
	CHECK(!uml_nt_resume_illegal_is_syscall(1, 0, ud2_bytes));
	/* A real access fault is never a syscall site. */
	CHECK(!uml_nt_resume_illegal_is_syscall(0, 1, ud2_bytes));

	/* 3. The pre-fix cascade, replayed: each wild trap took the
	 *    syscall path and advanced +2. Show every step produced a
	 *    target the new gate must refuse (the +2 of a 6-byte jne
	 *    or of foreign bytes is mid-instruction). */
	{
		unsigned long long rips[] = { 0x6001b57dull, 0x6001b582ull,
					      0x6001b5b8ull, 0x6001b5bbull };
		int i;

		for (i = 0; i < 4; i++) {
			int cls = uml_nt_resume_classify_illegal(
				1, 1, mid_bytes);

			CHECK(cls == UML_NT_RESUME_REJECT);
			CHECK(resume_target(cls, rips[i], 0) == ~0ull);
		}
	}

	/* 4. A legitimate syscall trap: the sentinel at the trap RIP,
	 *    resume exactly past the 2-byte ud2. */
	{
		unsigned long long trap = 0x601e800full; /* libc __open */
		int cls = uml_nt_resume_classify_illegal(1, 1, ud2_bytes);

		CHECK(cls == UML_NT_RESUME_SYSCALL);
		CHECK(resume_target(cls, trap, 0) == 0x601e8011ull);
		CHECK(uml_nt_resume_is_boundary(trap, trap + 2));
	}

	/* 5. The restart round trip: the kernel syncs a syscall trap to
	 *    trap+2, do_signal rewinds by 2 on -ERESTARTSYS, and the
	 *    guest must re-execute the sentinel itself — not a byte
	 *    before or after it. */
	{
		unsigned long long trap = 0x601e800full;
		unsigned long long post = uml_nt_resume_syscall_target(trap);

		CHECK(uml_nt_resume_restart_target(post) == trap);
		CHECK(uml_nt_resume_is_boundary(trap,
			uml_nt_resume_restart_target(post)));
	}

	/* 6. Fault resume: verbatim re-execution of the faulting
	 *    instruction (no arithmetic at all). */
	{
		unsigned long long rip = 0x6001b582ull;

		CHECK(uml_nt_resume_classify_fault() == UML_NT_RESUME_FAULT);
		CHECK(resume_target(UML_NT_RESUME_FAULT, rip, 0) == rip);
	}

	/* 7. The kernel's expected resume for each round — the value
	 *    the stub's actual resume_rip is checked against at the
	 *    next trap. A verbatim (signal) push overrides both. */
	CHECK(uml_nt_resume_expected(1, 0x601e800full, 0, 0) ==
	      0x601e8011ull);
	CHECK(uml_nt_resume_expected(0, 0x6001b582ull, 0, 0) ==
	      0x6001b582ull);
	CHECK(uml_nt_resume_expected(1, 0x601e800full, 1,
				     0x6000d000ull) == 0x6000d000ull);
	/* Restart: the delivered state's rip (post -2) wins. */
	CHECK(uml_nt_resume_expected(1, 0x601e800full, 1,
				     0x601e800full) == 0x601e800full);

	/* 8. The resume-RSP contract (Shelley 149 [resume-regs]). The
	 *    witness asks one question: when the login conn resumed
	 *    after round close(3) (trap rsp=0x6005d258, clean), did the
	 *    guest come back with that same rsp — or did the kernel/
	 *    stub answer carry a different (already wild) one?
	 *
	 *    A syscall or fault round changes NO stack pointer: every
	 *    round is the trap state verbatim plus a rip/rax fold. The
	 *    ONE legitimate rsp rewrite is a verbatim push (signal
	 *    frame placed below the trap rsp, or rt_sigreturn restoring
	 *    an arbitrary one). Anything else is the reg-restore bug
	 *    class and must classify as REWRITE, never as clean. */
	CHECK(uml_nt_resume_regs_class(0x6005d258ull, 0x6005d258ull, 0) ==
	      UML_NT_RRES_UNCHANGED);
	/* A wild resume on a plain round is the bug class — the value
	 * the rp1 fire would have shown had the kernel written it. */
	CHECK(uml_nt_resume_regs_class(0x6005d258ull, 0x6001c228ull, 0) ==
	      UML_NT_RRES_REWRITE);
	/* Upwards is just as illegal (a restore that pops). */
	CHECK(uml_nt_resume_regs_class(0x6005d258ull, 0x6005d2a8ull, 0) ==
	      UML_NT_RRES_REWRITE);
	/* A signal frame placed below the trap rsp: the verbatim class,
	 * with the shift measurable (frame length). */
	CHECK(uml_nt_resume_regs_class(0x6005d258ull, 0x6005cf00ull, 1) ==
	      UML_NT_RRES_VERBATIM);
	CHECK(uml_nt_resume_regs_below(0x6005d258ull, 0x6005cf00ull) ==
	      0x358ull);
	/* rt_sigreturn: the restored rsp is arbitrary, including ABOVE
	 * the trap rsp (the syscall ran on the frame). Legitimate — the
	 * verbatim flag is the only thing that separates it from the
	 * rewrite class. */
	CHECK(uml_nt_resume_regs_class(0x6005cf00ull, 0x6005d258ull, 1) ==
	      UML_NT_RRES_VERBATIM);
	CHECK(uml_nt_resume_regs_below(0x6005cf00ull, 0x6005d258ull) == 0);
	/* A verbatim round that did NOT move rsp is still the plain
	 * case (nothing to explain). */
	CHECK(uml_nt_resume_regs_class(0x6005d258ull, 0x6005d258ull, 1) ==
	      UML_NT_RRES_UNCHANGED);
	/* The fire's own interval, spelled out: trap rsp clean, the
	 * resume the kernel answered is what the stub restored, and the
	 * NEXT trap arrived with a text rsp. Only a guest-side pivot
	 * explains that chain — this is what the witness must prove
	 * from the log, not what the model may assume. */
	{
		unsigned long long trap = 0x6005d258ull; /* close(3) */
		unsigned long long resume = 0x6005d258ull; /* answered */
		unsigned long long next_trap = 0x6001c228ull; /* fstatat */

		CHECK(uml_nt_resume_regs_class(trap, resume, 0) ==
		      UML_NT_RRES_UNCHANGED);
		CHECK(resume == trap);
		/* The guest's own arithmetic between the two traps is
		 * NOT the kernel's business: the detector must not call
		 * the next trap's wild rsp a resume rewrite. */
		CHECK(next_trap != resume);
		CHECK(uml_nt_resume_regs_below(resume, next_trap) ==
		      0x6005d258ull - 0x6001c228ull);
	}

	/* 9. The TF single-step trace's ONE decision (Shelley 149's
	 *    verdict: the resume carried the trap's own rsp, so the
	 *    pivot is guest code). The witness arms TF on the round
	 *    after close(3); every guest instruction then traps once.
	 *    The loop must keep stepping over a wild-but-UNMOVED rsp
	 *    (a trace armed late), and stop exactly on the step whose
	 *    rsp moved into image text — that step's PREVIOUS 'instruction'
	 *    is the pivot. The budget end is a separate verdict.
	 *
	 *    Witnessed values: close(3) resume rsp=0x6005d258 [stack],
	 *    the trap after the pivot rsp=0x6001c228 [interp text]. */
	CHECK(uml_nt_tf_trace_next(400, 0, 1) == UML_NT_TF_STEP);
	CHECK(uml_nt_tf_trace_next(400, 1, 1) == UML_NT_TF_PIVOT);
	/* A wild rsp that did not move this step is the trace's own
	 * start state, never the pivot. */
	CHECK(uml_nt_tf_trace_next(400, 1, 0) == UML_NT_TF_STEP);
	/* A clean rsp that "moved" (a push/pop) is normal execution. */
	CHECK(uml_nt_tf_trace_next(400, 0, 1) == UML_NT_TF_STEP);
	/* Budget: the last allowed step still steps; then stop. */
	CHECK(uml_nt_tf_trace_next(1, 0, 1) == UML_NT_TF_STEP);
	CHECK(uml_nt_tf_trace_next(1, 1, 1) == UML_NT_TF_PIVOT);
	CHECK(uml_nt_tf_trace_next(0, 0, 1) == UML_NT_TF_EXHAUSTED);
	CHECK(uml_nt_tf_trace_next(0, 1, 1) == UML_NT_TF_EXHAUSTED);

	if (fails) {
		fprintf(stderr, "test_resume: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_resume: all checks passed\n");
	return 0;
}
