/* The replay single-step (TF) state machine model — M5.6a K7 slice D.
 *
 * Red-first for the 0x80000004 class (referees 39798056175 and
 * 39809900440: "stub died silently (STATUS_SINGLE_STEP) last cmd=4"):
 * a #DB that nothing armed reached the VEH's unowned path and killed
 * the stub, and a trap context captured inside the replay window
 * carried EFLAGS.TF into the kernel's pt_regs. The model is the pure
 * half of stub.c's VEH: flag sanitizers + the #DB classifier + the
 * arm epoch. Compiles on the host, no Windows types. */
#include <stdio.h>
#include "ss_model.h"

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
	} } while (0)

int main(void)
{
	const unsigned long long TF = UML_NT_EFLAGS_TF;
	const unsigned long long P = 0x67c02000ull;	/* an armed page */
	const unsigned long long target = 0x6040174dull;	/* the armed store */
	const unsigned long long tf_lo = 0x140001000ull;	/* fs_trampoline_fault_tf */
	const unsigned long long tf_hi = tf_lo + 56;	/* fs_tramp_tf_end */

	/* 1. capture: the guest never owns TF — a trap context that
	 *    carries it (a fault-class exception inside the window) must
	 *    not hand it to the kernel. */
	CHECK(uml_nt_ss_capture_flags(0x10346ull) == 0x10246ull);
	CHECK(uml_nt_ss_capture_flags(0x246ull) == 0x246ull);
	CHECK((uml_nt_ss_capture_flags(~0ull) & TF) == 0);

	/* 2. resume: no restored context carries TF — the replay
	 *    trampoline raises it itself, after the restore. */
	CHECK(uml_nt_ss_resume_flags(0x10346ull) == 0x10246ull);
	CHECK((uml_nt_ss_resume_flags(TF) & TF) == 0);

	/* 3. the leak transition end to end: AV inside the window (TF
	 *    live) -> capture -> kernel pt_regs -> sigframe/verbatim ->
	 *    resume with nothing armed. Before: TF=1 at the first
	 *    instruction -> #DB -> dead stub. After: TF=0 both ends. */
	{
		unsigned long long ctx = 0x346ull;	/* TF=1 at the AV */
		unsigned long long pt = uml_nt_ss_capture_flags(ctx);
		unsigned long long back = uml_nt_ss_resume_flags(pt);

		CHECK((pt & TF) == 0);
		CHECK((back & TF) == 0);
	}

	/* 4. the #DB classifier. */
	/* a DR watchpoint hit (Dr6.B0-3) is the DR filter's, armed or not */
	CHECK(uml_nt_ss_classify(0x4001ull, P, target + 7, target, tf_lo, tf_hi) ==
	      UML_NT_SS_DR_HIT);
	CHECK(uml_nt_ss_classify(0x0004ull, 0, 0x606665beull, target, tf_lo, tf_hi) ==
	      UML_NT_SS_DR_HIT);
	/* nothing armed: a stray — never the fatal verdict */
	CHECK(uml_nt_ss_classify(0x4000ull, 0, target, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);
	CHECK(uml_nt_ss_classify(0ull, 0, 0x140000f00ull, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);
	/* armed: the store's door and the trampoline body are hops */
	CHECK(uml_nt_ss_classify(0x4000ull, P, target, target, tf_lo, tf_hi) ==
	      UML_NT_SS_HOP);
	CHECK(uml_nt_ss_classify(0x4000ull, P, tf_lo + 7, target, tf_lo, tf_hi) ==
	      UML_NT_SS_HOP);
	CHECK(uml_nt_ss_classify(0x4000ull, P, tf_hi - 1, target, tf_lo, tf_hi) ==
	      UML_NT_SS_HOP);
	/* armed: right past the store (one instruction, <= 15 bytes) */
	CHECK(uml_nt_ss_classify(0x4000ull, P, target + 3, target, tf_lo, tf_hi) ==
	      UML_NT_SS_POST_STORE);
	CHECK(uml_nt_ss_classify(0x4000ull, P, target + 15, target, tf_lo, tf_hi) ==
	      UML_NT_SS_POST_STORE);
	/* armed but the rip is nowhere the window admits: the ntdll
	 * dispatcher (an AV inside the window), the plain trampoline, a
	 * far jump — a stray, not "the store just ran" */
	CHECK(uml_nt_ss_classify(0x4000ull, P, target + 16, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);
	CHECK(uml_nt_ss_classify(0x4000ull, P, target - 5, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);
	CHECK(uml_nt_ss_classify(0x4000ull, P, tf_lo - 7, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);
	CHECK(uml_nt_ss_classify(0x4000ull, P, tf_hi, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);
	CHECK(uml_nt_ss_classify(0x4000ull, P, 0x7ffd12345678ull, target, tf_lo, tf_hi) ==
	      UML_NT_SS_STRAY);

	/* 5. the arm epoch: every fault decides its own page — a fault
	 *    the decoder refuses arms NOTHING (the previous round's arm
	 *    must not ride into this resume), and a spent verify budget
	 *    arms nothing either. */
	CHECK(uml_nt_ss_arm_page(1, 16, 0x67c02ae0ull) == 0x67c02000ull);
	CHECK(uml_nt_ss_arm_page(0, 16, 0x67c02ae0ull) == 0);
	CHECK(uml_nt_ss_arm_page(1, 0, 0x67c02ae0ull) == 0);
	CHECK(uml_nt_ss_arm_page(1, -1, 0x67c02ae0ull) == 0);

	if (fails) {
		fprintf(stderr, "test_ss: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_ss: all ok\n");
	return 0;
}
