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
#include "veh_model.h"
#include "deathsit_model.h"
#include "d20sweep_model.h"
#include "fillrehome_model.h"
#include "dr7_model.h"
#include "drslot_model.h"
#include "prot_restore_model.h"
#include "stackgrow_model.h"

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
static void test_pwslot(void);

static void sec11_veh_stack(void);

/* section 12 — the DEATH-SITE discriminator (Shelley 159).
 *
 * Real numbers from the hunt, so the test is not a toy: the stub dies
 * at rip 0x601dce65 while the module that should hold it starts at
 * 0x601ec000 (one 64K above the hole) — i.e. the two live hypotheses
 * differ by a single bit (0x601dce65 ^ 0x601ece65 == 0x10000), which is
 * exactly the shape a copy-path bug takes and exactly the shape a
 * wildly-computed jump target does NOT (that one lands anywhere).
 */
static void section12(void)
{
	const unsigned long long dead = 0x601dce65ull;
	const unsigned long long text = 0x601ece65ull;

	/* a. block and kernel agree, table has it, stub has it => SANE */
	CHECK(uml_nt_deathsit_verdict(dead, dead, 1, 1) == UML_NT_DS_SANE);
	/* b. the table says hole but the process still maps it => STALE */
	CHECK(uml_nt_deathsit_verdict(dead, dead, 0, 1) == UML_NT_DS_STALE);
	/* c. both empty => the guest jumped into a hole */
	CHECK(uml_nt_deathsit_verdict(dead, dead, 0, 0) == UML_NT_DS_JUMP);
	/* d. the block no longer holds the answer => TRANSIT, and it WINS
	 *    over every geometric branch (a stale view cannot be diagnosed
	 *    on a value we never wrote) */
	CHECK(uml_nt_deathsit_verdict(text, dead, 1, 1) == UML_NT_DS_TRANSIT);
	CHECK(uml_nt_deathsit_verdict(text, dead, 0, 0) == UML_NT_DS_TRANSIT);
	/* e. the +64K relation, told exactly: as ARITHMETIC the two
	 *    addresses are 0x10000 apart (Shelley's observation), as a BIT
	 *    VECTOR they differ in TWO bits (0x30000) — a single-bit flip
	 *    is a different animal, and only the arithmetic difference
	 *    survives a page-shift story. Both facts, so nobody re-derives
	 *    the wrong one from the log. */
	CHECK(text - dead == 0x10000ull);
	CHECK((text ^ dead) == 0x30000ull);
	CHECK(uml_nt_deathsit_verdict(text, dead, 0, 1) == UML_NT_DS_TRANSIT);

	/* f. the jump-source test: a rip equal to the syscall return value
	 *    (or within 64K of it) names the producer of the target */
	CHECK(uml_nt_deathsit_near_retval(dead, dead, 0x10000) == 1);
	CHECK(uml_nt_deathsit_near_retval(dead, 0x601d0000ull, 0x10000) == 1);
	/* ... and the module base one 64K up is NOT "near": the distance
	 * is 0x1ce65, which is why the bit-flip observation is a TRANSIT
	 * signal and not a jump-source signal */
	CHECK(uml_nt_deathsit_near_retval(dead, 0x6085d000ull, 0x10000) == 0);
	/* symmetric: a retval BELOW the rip is measured too */
	CHECK(uml_nt_deathsit_near_retval(dead, dead + 0xfff, 0x10000) == 1);
	CHECK(uml_nt_deathsit_near_retval(dead, dead + 0x10001, 0x10000) == 0);

	printf("section 12 (death-site discriminator): all ok\n");
}

/* section 13 — when must the D20 sweep re-patch a run? (referee
 * 40197441363). The password death is libc+0xfce65, the `syscall` of
 * __close_nocancel, in a conn whose sweeps reported "0 patched" while
 * another conn's sweep of the same library patched 526. The physical
 * runs are shared and a later file fill restores the pristine bytes,
 * so a plain "already swept" bit lies forever.
 */
static void section13(void)
{
	/* a. never swept, executable => patch it */
	CHECK(uml_nt_sweep_needed(1, 0, 7) == 1);
	/* b. swept at the generation the content still has => skip */
	CHECK(uml_nt_sweep_needed(1, 7, 7) == 0);
	/* c. content was re-created (a file fill, a COW copy, a re-home)
	 *    => the patch went with the old bytes, patch again */
	CHECK(uml_nt_sweep_needed(1, 7, 8) == 1);
	CHECK(uml_nt_sweep_needed(1, 7, 0) == 1);
	/* d. data is never patched: the sweep is a code instrument */
	CHECK(uml_nt_sweep_needed(0, 0, 7) == 0);
	CHECK(uml_nt_sweep_needed(0, 7, 8) == 0);
	/* e. the exact death shape: run swept once, then rewritten by a
	 *    fill that forgot the mark — the model must say "patch" */
	CHECK(uml_nt_sweep_needed(1, 0 /* forgotten by the fill */, 7) == 1);

	printf("section 13 (D20 sweep re-arm): all ok\n");
}

/* section 14 — must a fill re-home before writing? (Shelley 161).
 *
 * A fill writes physmem directly, bypassing every stub view. On a run
 * with a second claimer that is the memory-safety bug; on an executable
 * one it is the silent-death bug (a 0f 05 restored under a guest that
 * is executing). The decision is the refcount.
 */
static void section14(void)
{
	/* a. the shared executable run: never written in place */
	CHECK(uml_nt_fill_needs_rehome(1, 2) == 1);
	CHECK(uml_nt_fill_needs_rehome(1, 7) == 1);
	/* b. a private executable run: the fill owns it */
	CHECK(uml_nt_fill_needs_rehome(1, 1) == 0);
	/* c. shared data is corruption too, same answer */
	CHECK(uml_nt_fill_needs_rehome(0, 2) == 1);
	/* d. private data: plain fill */
	CHECK(uml_nt_fill_needs_rehome(0, 1) == 0);
	CHECK(uml_nt_fill_needs_rehome(0, 0) == 0);

	printf("section 14 (fill re-home): all ok\n");
}

/* section 15 — the DR state rides EVERY resume (Shelley 163).
 *
 * The application of dr7 used to live on one resume branch, so the
 * verbatim branch (signal push, fault verbatim) dropped every kernel
 * watchpoint — and the one-shot execute probe, which is why it reported
 * "armed but never fired" while the conn demonstrably kept running. The
 * shape is pure: a slot with a VA gets Ln; only exec slots omit the
 * write fields.
 */
static void section15(void)
{
	/* a. nothing armed => no bits at all (a resume with no DR state) */
	CHECK(uml_nt_dr7_build(0, 0, 0, 0, 0) == 0);
	/* b. one EXECUTE slot: Ln only (bit 2), no RW/LEN fields */
	CHECK(uml_nt_dr7_build(1u << 2, 0, 0, 0x601dce67ull, 0) ==
	      (1ull << 4));
	/* c. one WRITE slot: Ln + RW=01 LEN=10 at 16 + 4*i */
	CHECK(uml_nt_dr7_build(0, 0x60a20000ull, 0, 0, 0) ==
	      (1ull | (0x9ull << 16)));
	CHECK(uml_nt_dr7_build(0, 0, 0, 0, 0x60a20000ull) ==
	      ((1ull << 6) | (0x9ull << 28)));
	/* d. mixed: the exec slot keeps its shape, the writes keep theirs */
	CHECK(uml_nt_dr7_build(1u << 2, 0x60a20000ull, 0, 0x601dce67ull, 0) ==
	      (1ull | (0x9ull << 16) | (1ull << 4)));
	/* e. an armed slot with a zero VA contributes nothing (the kernel
	 *    disarms a slot by zeroing it, not by clearing the mask) */
	CHECK(uml_nt_dr7_build(1u << 2, 0, 0, 0, 0) == 0);

	printf("section 15 (DR state on every resume): all ok\n");
}

/* section 16 — ONE owner per debug slot (Shelley 164).
 *
 * The three incidents that blinded a live measurement, as regressions:
 * (1) the write-slot instrument took all four slots and left the live
 *     probe nothing; (2) the arena instrument rewrote slots 2/3 under a
 *     live probe; (3) a retired owner kept re-arming forever.
 */
static void section16(void)
{
	struct uml_nt_drslots s;
	int got[UML_NT_DRS_SLOTS];

	uml_nt_drs_init(&s);
	/* a. a live EXEC reserve gets a slot even when a lower-priority
	 *    owner holds all four (incident 1) */
	CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_WSLOT, 4, got) == 4);
	CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_EXEC, 1, got) == 1);
	CHECK(uml_nt_drs_holds(&s, UML_NT_DRS_EXEC) == 1);
	CHECK(uml_nt_drs_holds(&s, UML_NT_DRS_WSLOT) == 3); /* evicted one */
	/* b. a lower-priority owner can never take the exec slot
	 *    (incident 2) */
	{
		int i, exec_slot = -1;

		for (i = 0; i < UML_NT_DRS_SLOTS; i++)
			if (s.owner[i] == UML_NT_DRS_EXEC)
				exec_slot = i;
		CHECK(exec_slot >= 0);
		CHECK(uml_nt_drs_holds(&s, UML_NT_DRS_ARENA) == 0);
		CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_ARENA, 2, got) == 0);
		CHECK(s.owner[exec_slot] == UML_NT_DRS_EXEC);
	}
	/* c. a retired owner never reserves again (incident 3) */
	uml_nt_drs_release(&s, UML_NT_DRS_WSLOT);
	CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_WSLOT, 1, got) == 1);
	uml_nt_drs_retire(&s, UML_NT_DRS_WSLOT);
	CHECK(uml_nt_drs_holds(&s, UML_NT_DRS_WSLOT) == 0); /* dropped */
	CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_WSLOT, 1, got) == 0);
	/* d. release frees exactly the owner's slots, nothing else */
	uml_nt_drs_init(&s);
	CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_TCACHE, 2, got) == 2);
	CHECK(uml_nt_drs_reserve(&s, UML_NT_DRS_EXEC, 1, got) == 1);
	uml_nt_drs_release(&s, UML_NT_DRS_EXEC);
	CHECK(uml_nt_drs_holds(&s, UML_NT_DRS_TCACHE) == 2);
	CHECK(uml_nt_drs_holds(&s, UML_NT_DRS_EXEC) == 0);

	printf("section 16 (one owner per DR slot): all ok\n");
}

/* section 17 — a page comes back with the protection its VMA asks for
 * (Shelley 166). The regression: a write-dance over TEXT restored
 * PAGE_READONLY, so the next fetch faulted — and a fetch fault is
 * delivered before the CPU checks DR execute breakpoints, which made it
 * look like a resume that never reached the guest.
 */
static void section17(void)
{
	/* a. text comes back executable */
	CHECK(uml_nt_prot_restore(0x20) == UML_NT_PROT_EXR);
	/* b. a writable-exec VMA keeps both rights (the VMA decides) */
	CHECK(uml_nt_prot_restore(0x40) == UML_NT_PROT_EXW);
	/* c. data keeps its shape: write stays write, read stays read */
	CHECK(uml_nt_prot_restore(0x04) == UML_NT_PROT_RW);
	CHECK(uml_nt_prot_restore(0x02) == UML_NT_PROT_RO);
	CHECK(uml_nt_prot_restore(0x00) == UML_NT_PROT_RO);
	/* d. an exec VMA with extra flag bits still yields execute */
	CHECK(uml_nt_prot_restore(0x80 | 0x20) == UML_NT_PROT_EXR);
	/* e. the predicate the ledger comparison uses */
	CHECK(uml_nt_prot_executable(UML_NT_PROT_EXR));
	CHECK(uml_nt_prot_executable(UML_NT_PROT_EXW));
	CHECK(!uml_nt_prot_executable(UML_NT_PROT_RO));
	CHECK(!uml_nt_prot_executable(UML_NT_PROT_RW));

	printf("section 17 (protection comes from the VMA): all ok\n");
}

/* section 18 — grow the stack BEFORE the exception that needs it
 * (Shelley 168). Measured: rsp with 264..3900 bytes of committed page
 * under it, reservation hole below, dispatcher builds its frame there,
 * second AV, no handler, silent death. The rule grows one run below the
 * committed bottom, inside the reservation, and never past the floor.
 */
static void section18(void)
{
	unsigned long long st = 0;
	unsigned long long top = 0x60860000ull;   /* stack_top */
	unsigned long long lim = 0x60060000ull;   /* 8 MiB reservation floor */
	unsigned long long bot = 0x60850000ull;   /* committed bottom */
	unsigned long long run = UML_NT_SG_RUN;

	/* a. 600 bytes of headroom => grow, and the run is right below */
	CHECK(uml_nt_sg_precommit(top, lim, 0x60850258ull, bot, run, &st) == 1);
	CHECK(st == bot - run);
	/* b. plenty of headroom => nothing to do */
	CHECK(uml_nt_sg_precommit(top, lim, 0x6085f000ull, bot, run, &st) == 0);
	/* c. one page left is NOT enough (the measured death had 264 bytes) */
	CHECK(uml_nt_sg_precommit(top, lim, bot + 0x1000ull, bot, run, &st) == 1);
	/* d. a run would cross the floor => not ours (clean SIGSEGV instead) */
	CHECK(uml_nt_sg_precommit(top, lim, lim + 0x100ull, lim + 0x10000ull,
				  run, &st) == -1);
	/* e. rsp outside the stack => no opinion */
	CHECK(uml_nt_sg_precommit(top, lim, 0x70000000ull, bot, run, &st) == 0);
	CHECK(uml_nt_sg_precommit(0, lim, 0x60850000ull, bot, run, &st) == 0);

	printf("section 18 (stack grown ahead of the exception): all ok\n");
}

int main(void)
{
	test_pwslot();
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

	sec11_veh_stack();
	section12();
	section13();
	section14();
	section15();
	section16();
	section17();
	section18();

	if (fails) {
		fprintf(stderr, "test_resume: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_resume: all checks passed\n");
	return 0;
}

/* ============================================================
 * Section 10 — [pivot-wslot] (to-shelley 151, Shelley's ruling):
 * the pivot's footprint in the interp's text is a stride-16
 * vfprintf arg array, and the four addresses it lands on are
 * deterministic. The kernel arms DR WRITE slots on them, so the
 * slot identity must be decided from the interp base alone —
 * no absolute address may be baked in (the interp is a DSO and
 * its load base is whatever the loader picked).
 * ============================================================ */
static void test_pwslot(void)
{
	unsigned long long b = 0x60010000ull;

	/* the four ruled slots, in arm order */
	CHECK(uml_nt_pwslot_index(b, b + 0xc5e0) == 0);
	CHECK(uml_nt_pwslot_index(b, b + 0xc5e8) == 1);
	CHECK(uml_nt_pwslot_index(b, b + 0xc5f0) == 2);
	CHECK(uml_nt_pwslot_index(b, b + 0xc5f8) == 3);
	/* everything else is NOT ours: a write elsewhere in text (or on
	 * the stack) must keep the v13/tcache meaning */
	CHECK(uml_nt_pwslot_index(b, b + 0xc5f9) == -1);
	CHECK(uml_nt_pwslot_index(b, b + 0xc4b8) == -1); /* mid-stack */
	CHECK(uml_nt_pwslot_index(b, b + 0xc2c8) == -1);
	CHECK(uml_nt_pwslot_index(b, b + 0xc228) == -1);
	CHECK(uml_nt_pwslot_index(b, 0x6005c6a0ull) == -1);
	/* an unknown base disarms the whole classifier */
	CHECK(uml_nt_pwslot_index(0, b + 0xc4b8) == -1);
	/* the same offsets must hold at a different load base: this is a
	 * DSO, and a fixed absolute address would silently watch the
	 * wrong page */
	CHECK(uml_nt_pwslot_index(0x70000000ull, 0x7000c5e0ull) == 0);
	CHECK(uml_nt_pwslot_index(0x70000000ull, 0x7000c5f8ull) == 3);
	CHECK(uml_nt_pwslot_index(0x70000000ull, 0x6001c5e0ull) == -1);
}

/* Section 11 — the VEH dispatch stack (Shelley 157 (a), v1).
 * RED FIRST: written before the model existed; every CHECK below is
 * the semantics the asm thunk will be held to. */
static void sec11_veh_stack(void)
{
	static unsigned char buf[64 * 1024] __attribute__((aligned(16)));
	struct uml_nt_veh_stack s;
	unsigned long long sp_out = 0;
	unsigned long long guest_sp = 0x6085c6a8ULL;

	memset(&s, 0, sizeof(s));
	s.buf = (unsigned long long)(unsigned long)buf;
	s.size = sizeof(buf);

	/* 1. the outermost entry switches somewhere INSIDE the buffer,
	 *    16-byte aligned, with real room left for a dispatch */
	CHECK(uml_nt_veh_enter(&s, guest_sp) == 0);
	CHECK(s.depth == 1);
	CHECK(s.sp >= s.buf && s.sp < s.buf + s.size);
	CHECK((s.sp & 15) == 0);
	CHECK(s.sp - s.buf >= UML_NT_VEH_MIN_SIZE);
	CHECK(s.guest_sp == guest_sp);

	/* 2. nested entries keep the private stack — never a second
	 *    switch, never a return to the guest stack mid-dispatch */
	{
		unsigned long long sp1 = s.sp;

		CHECK(uml_nt_veh_enter(&s, 0x6085a000ULL) == 1);
		CHECK(s.depth == 2);
		CHECK(s.sp == sp1);
		CHECK(uml_nt_veh_leave(&s, &sp_out) == 1);
		CHECK(sp_out == sp1);		/* nested leave: unchanged */
		CHECK(s.guest_sp == guest_sp);	/* and untouched */
	}

	/* 3. the outermost leave restores the guest sp BIT-EXACTLY — the
	 *    CONTINUE_EXECUTION path returns to the faulting instruction
	 *    with this rsp */
	CHECK(uml_nt_veh_leave(&s, &sp_out) == 0);
	CHECK(sp_out == guest_sp);
	CHECK(s.depth == 0);

	/* 4. a second outermost cycle works (handlers are re-entered for
	 *    each new exception) and records the NEW guest sp */
	CHECK(uml_nt_veh_enter(&s, 0x60001234ULL) == 0);
	CHECK(s.guest_sp == 0x60001234ULL);
	CHECK(uml_nt_veh_leave(&s, &sp_out) == 0);
	CHECK(sp_out == 0x60001234ULL);

	/* 5. a buffer too small to dispatch is refused rather than run
	 *    off the end of it */
	memset(&s, 0, sizeof(s));
	s.buf = (unsigned long long)(unsigned long)buf;
	s.size = 512;
	CHECK(uml_nt_veh_enter(&s, guest_sp) == -1);
	CHECK(s.depth == 0);
	/* no buffer at all is refused too */
	memset(&s, 0, sizeof(s));
	CHECK(uml_nt_veh_enter(&s, guest_sp) == -1);

	/* 5b. the alignment contract must hold for an UNALIGNED buffer
	 *     too — the real TLS buffer's top need not be 16-aligned */
	memset(&s, 0, sizeof(s));
	s.buf = (unsigned long long)(unsigned long)buf + 8;
	s.size = sizeof(buf) - 20;	/* top is now 4 mod 16 */
	CHECK(uml_nt_veh_enter(&s, guest_sp) == 0);
	CHECK((s.sp & 15) == 0);
	CHECK(uml_nt_veh_leave(&s, &sp_out) == 0 && sp_out == guest_sp);

	/* 6. unbalanced leaves are refused, not silently ignored */
	memset(&s, 0, sizeof(s));
	CHECK(uml_nt_veh_leave(&s, &sp_out) == -1);
	printf("section 11 (VEH dispatch stack): all ok\n");
}

