// SPDX-License-Identifier: GPL-2.0
/*
 * tests/test_hop_live_asm.c — the EXACT instruction sequence the production
 * trampolines add, executed on the host x86-64 with a real execution frame.
 *
 * What this harness does that the earlier one did not:
 *   - the hop runs inside a naked function with its own aligned frame, so no
 *     C inline-asm CALL is hidden from the compiler's stack accounting;
 *   - the red zone below the live RSP is filled with canaries and checked by
 *     the landing pad BEFORE the frame is torn down, so a stray write below
 *     RSP is a failure, not an invisible one;
 *   - arithmetic flags are set to a known value before the sequence and
 *     compared with the landing pad's value, so a flag-clobbering instruction
 *     fails;
 *   - the callee-saved registers are seeded and compared, and RAX/R11 are
 *     checked against what was delivered.
 *
 * It is still a SNIPPET CONTROL: it proves the sequence on this CPU, not that
 * Windows dispatched through the real trampoline.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <hop_live.h>
#include <hop_live_asm.h>

static int fails;

#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

/* the globals the production sequence refers to */
struct uml_nt_hop_live rec;
struct uml_nt_hop_live *volatile fs_live_ptr = &rec;
volatile unsigned long long fs_tramp_target;
volatile unsigned long long fs_save_r11;

/* what the landing pad observed */
static volatile unsigned long long seen_rax, seen_r11, seen_flags;
static volatile unsigned long long seen_rbx, seen_r12, seen_r13, seen_r14, seen_r15;
static volatile unsigned long long seen_rcx, seen_rdx, seen_rsi, seen_rdi, seen_rbp;
static volatile unsigned long long seen_r8, seen_r9, seen_r10;
static volatile unsigned long long rsp_before;
#define RZ_WORDS 16
static volatile unsigned long long seen_rz[RZ_WORDS];	/* -8 .. -128 */
static volatile unsigned long long seen_rsp;

#define KNOWN_FLAGS	0x246ull	/* IF | ZF | PF | bit1, CF=0, DF=0, TF=0 */
#define RZ0		0x1111222233334444ull
#define RZ1		0x5555666677778888ull
#define RZ2		0x9999aaaabbbbccccull
#define RZ3		0xddddeeeeffff0001ull

/*
 * The hop: a real frame (6 callee-saved pushes + 0x100), canaries in the red
 * zone below RSP, known flags, the production stamps, then the production
 * tail and the indirect jmp to the landing pad.
 */
__attribute__((naked)) void hop_run(void)
{
	__asm__ volatile (
		"pushq	%rbx\n\t"
		"pushq	%rbp\n\t"
		"pushq	%r12\n\t"
		"pushq	%r13\n\t"
		"pushq	%r14\n\t"
		"pushq	%r15\n\t"
		"subq	$0x100, %rsp\n\t"
		/* canaries in the red zone (below the live RSP): a 64-bit
		 * immediate cannot go straight to memory, so stage it in RAX
		 * before the delivered value is loaded. */
		"movabsq	$0x1111222233334444, %rax\n\t"
		"movq	%rax, -8(%rsp)\n\t"
		"movabsq	$0x5555666677778888, %rax\n\t"
		"movq	%rax, -16(%rsp)\n\t"
		"movabsq	$0x9999aaaabbbbcccc, %rax\n\t"
		"movq	%rax, -24(%rsp)\n\t"
		"movabsq	$0xddddeeeeffff0001, %rax\n\t"
		"movq	%rax, -32(%rsp)\n\t"
		/* seed EVERY guest-live GPR (fault replay leaves them all
		 * live) — the sequence must not disturb any of them */
		"movq	$0x1b1b1b1b, %rbx\n\t"
		"movq	$0x0c0c0c0c, %rcx\n\t"
		"movq	$0x0d0d0d0d, %rdx\n\t"
		"movq	$0x0e0e0e0e, %rsi\n\t"
		"movq	$0x0f0f0f0f, %rdi\n\t"
		"movq	$0x0b0b0b0b, %rbp\n\t"
		"movq	$0x08080808, %r8\n\t"
		"movq	$0x09090909, %r9\n\t"
		"movq	$0x0a0a0a0a, %r10\n\t"
		"movq	$0x12121212, %r12\n\t"
		"movq	$0x13131313, %r13\n\t"
		"movq	$0x14141414, %r14\n\t"
		"movq	$0x15151515, %r15\n\t"
		"movq	%rsp, rsp_before(%rip)\n\t"
		"movq	hop_in_rax(%rip), %rax\n\t"
		"movq	hop_in_r11(%rip), %r11\n\t"
		"pushq	$0x246\n\t"
		"popfq\n\t"
		/* the flags push/pop above wrote -8(%rsp): (re)write the canaries
		 * AFTER it so what remains is the canary, not the pushed value */
		"movabsq	$0x1111222233334444, %rax\n\t"
		"movq	%rax, -8(%rsp)\n\t"
		"movabsq	$0x5555666677778888, %rax\n\t"
		"movq	%rax, -16(%rsp)\n\t"
		"movabsq	$0x9999aaaabbbbcccc, %rax\n\t"
		"movq	%rax, -24(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0000, %rax\n\t"
		"movq\t%rax, -8(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0001, %rax\n\t"
		"movq\t%rax, -16(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0002, %rax\n\t"
		"movq\t%rax, -24(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0003, %rax\n\t"
		"movq\t%rax, -32(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0004, %rax\n\t"
		"movq\t%rax, -40(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0005, %rax\n\t"
		"movq\t%rax, -48(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0006, %rax\n\t"
		"movq\t%rax, -56(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0007, %rax\n\t"
		"movq\t%rax, -64(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0008, %rax\n\t"
		"movq\t%rax, -72(%rsp)\n\t"
		"movabsq\t$0x00000000c0de0009, %rax\n\t"
		"movq\t%rax, -80(%rsp)\n\t"
		"movabsq\t$0x00000000c0de000a, %rax\n\t"
		"movq\t%rax, -88(%rsp)\n\t"
		"movabsq\t$0x00000000c0de000b, %rax\n\t"
		"movq\t%rax, -96(%rsp)\n\t"
		"movabsq\t$0x00000000c0de000c, %rax\n\t"
		"movq\t%rax, -104(%rsp)\n\t"
		"movabsq\t$0x00000000c0de000d, %rax\n\t"
		"movq\t%rax, -112(%rsp)\n\t"
		"movabsq\t$0x00000000c0de000e, %rax\n\t"
		"movq\t%rax, -120(%rsp)\n\t"
		"movabsq\t$0x00000000c0de000f, %rax\n\t"
		"movq\t%rax, -128(%rsp)\n\t"
		"movq	hop_in_rax(%rip), %rax\n\t"	/* delivered value again */
		HOP_LIVE_STAMP_ENTER()
		HOP_LIVE_STAMP_COMMIT("1")
		"movq	fs_save_r11(%rip), %r11\n\t"
		"jmp	*fs_tramp_target(%rip)\n\t"
	);
}

/* the body changes RAX between the entry stamp and the commit stamp: the
 * record must carry the value that is actually delivered. */
__attribute__((naked)) void hop_run_body_sets_rax(void)
{
	__asm__ volatile (
		"pushq	%rbx\n\t"
		"subq	$0x40, %rsp\n\t"
		HOP_LIVE_STAMP_ENTER()
		"movq	$0x5151, %rax\n\t"
		HOP_LIVE_STAMP_COMMIT("1")
		"movq	fs_save_r11(%rip), %r11\n\t"
		"jmp	*fs_tramp_target(%rip)\n\t"
	);
}

__attribute__((naked, used)) static void hop_landing_short(void)
{
	__asm__ volatile (
		"movq	%rax, seen_rax(%rip)\n\t"
		"addq	$0x40, %rsp\n\t"
		"popq	%rbx\n\t"
		"ret\n\t"
	);
}

/* the FAULT kind: same production sequence, kind literal "2", nonzero live
 * RAX — the case the previous harness never executed. */
__attribute__((naked)) void hop_run_fault(void)
{
	__asm__ volatile (
		"pushq	%rbx\n\t"
		"pushq	%rbp\n\t"
		"pushq	%r12\n\t"
		"pushq	%r13\n\t"
		"pushq	%r14\n\t"
		"pushq	%r15\n\t"
		"subq	$0x100, %rsp\n\t"
		"movq	hop_in_rax(%rip), %rax\n\t"
		"movq	hop_in_r11(%rip), %r11\n\t"
		HOP_LIVE_STAMP_ENTER()
		HOP_LIVE_STAMP_COMMIT("2")
		"movq	fs_save_r11(%rip), %r11\n\t"
		"jmp	*fs_tramp_target(%rip)\n\t"
	);
}

__attribute__((naked)) void hop_landing(void)
{
	__asm__ volatile (
		"movq	%rax, seen_rax(%rip)\n\t"
		"movq	%r11, seen_r11(%rip)\n\t"
		"movq	%rsp, seen_rsp(%rip)\n\t"
		"movq	%rbx, seen_rbx(%rip)\n\t"
		"movq	%r12, seen_r12(%rip)\n\t"
		"movq	%r13, seen_r13(%rip)\n\t"
		"movq	%r14, seen_r14(%rip)\n\t"
		"movq	%r15, seen_r15(%rip)\n\t"
		"movq	%rcx, seen_rcx(%rip)\n\t"
		"movq	%rdx, seen_rdx(%rip)\n\t"
		"movq	%rsi, seen_rsi(%rip)\n\t"
		"movq	%rdi, seen_rdi(%rip)\n\t"
		"movq	%rbp, seen_rbp(%rip)\n\t"
		"movq	%r8, seen_r8(%rip)\n\t"
		"movq	%r9, seen_r9(%rip)\n\t"
		"movq	%r10, seen_r10(%rip)\n\t"
		/* the red zone, still live because this pad was jumped to */
		"movq\t-8(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+0(%rip)\n\t"
		"movq\t-16(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+8(%rip)\n\t"
		"movq\t-24(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+16(%rip)\n\t"
		"movq\t-32(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+24(%rip)\n\t"
		"movq\t-40(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+32(%rip)\n\t"
		"movq\t-48(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+40(%rip)\n\t"
		"movq\t-56(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+48(%rip)\n\t"
		"movq\t-64(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+56(%rip)\n\t"
		"movq\t-72(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+64(%rip)\n\t"
		"movq\t-80(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+72(%rip)\n\t"
		"movq\t-88(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+80(%rip)\n\t"
		"movq\t-96(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+88(%rip)\n\t"
		"movq\t-104(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+96(%rip)\n\t"
		"movq\t-112(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+104(%rip)\n\t"
		"movq\t-120(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+112(%rip)\n\t"
		"movq\t-128(%rsp), %rax\n\t"
		"movq\t%rax, seen_rz+120(%rip)\n\t"

		"pushfq\n\t"
		"popq	%rax\n\t"
		"movq	%rax, seen_flags(%rip)\n\t"
		"addq	$0x100, %rsp\n\t"
		"popq	%r15\n\t"
		"popq	%r14\n\t"
		"popq	%r13\n\t"
		"popq	%r12\n\t"
		"popq	%rbp\n\t"
		"popq	%rbx\n\t"
		"ret\n\t"
	);
}

/*
 * Inputs ride globals; the wrapper is a normal typed C call, so the compiler
 * emits and accounts for the CALL itself (stack alignment, red zone). A CALL
 * hidden in ordinary inline asm would not be visible to that accounting.
 */
static volatile unsigned long long hop_in_rax, hop_in_r11;

extern void hop_run(void);
extern void hop_run_body_sets_rax(void);
extern void hop_run_fault(void);

static void hop_once(unsigned long long delivered_rax, unsigned long long r11)
{
	fs_save_r11 = r11;
	fs_tramp_target = (unsigned long long)(uintptr_t)&hop_landing;
	hop_in_rax = delivered_rax;
	hop_in_r11 = r11;
	hop_run();			/* typed C call to a naked wrapper */
}

static void arm_sys(unsigned long long id, unsigned long long target,
		    unsigned long long rax, unsigned long long req,
		    unsigned long long done, unsigned long long entry)
{
	memset(&rec, 0, sizeof(rec));
	uml_nt_hop_live_arm(&rec, id, UML_NT_HOP_KIND_SYS, target, rax, req,
			    done, entry);
}

static void test_sys_hop_delivers_and_restores(void)
{
	struct uml_nt_hop_live_view v;

	arm_sys(101, (unsigned long long)(uintptr_t)&hop_landing, 0ull,
		7, 6, 0x55ull);
	hop_once(0ull, 0xDEADBEEFull);

	CHECK(seen_rax == 0ull);			/* delivered RAX */
	CHECK(seen_r11 == 0xDEADBEEFull);		/* restored from fs_save_r11 */
	CHECK(rec.entered == 101);
	CHECK(rec.commit == 101);
	CHECK(rec.entry_id == 0x55ull);
	CHECK(rec.kind_obs == UML_NT_HOP_KIND_SYS);
	CHECK(rec.target_obs == (unsigned long long)(uintptr_t)&hop_landing);
	CHECK(rec.rax_obs == 0ull);
	CHECK(rec.rsp_obs == seen_rsp);
	uml_nt_hop_live_read(&rec, 7, 6, 0x55ull, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 1);
}

static void test_delivered_rax_not_entry_rax(void)
{
	fs_save_r11 = 0x99ull;
	fs_tramp_target = (unsigned long long)(uintptr_t)&hop_landing_short;
	memset(&rec, 0, sizeof(rec));
	uml_nt_hop_live_arm(&rec, 150, UML_NT_HOP_KIND_SYS,
			    (unsigned long long)(uintptr_t)&hop_landing_short,
			    0ull, 33, 32, 0x11ull);
	hop_in_rax = 0xAAull;
	hop_in_r11 = 0x99ull;
	hop_run_body_sets_rax();
	CHECK(seen_rax == 0x5151ull);		/* what was delivered */
	CHECK(rec.rax_obs == 0x5151ull);	/* what was recorded */
}

static void test_fault_kind_is_executed(void)
{
	struct uml_nt_hop_live_view v;

	memset(&rec, 0, sizeof(rec));
	uml_nt_hop_live_arm(&rec, 300, UML_NT_HOP_KIND_FAULT,
			    (unsigned long long)(uintptr_t)&hop_landing,
			    0x7dull, 60, 59, 0x77ull);
	fs_save_r11 = 0x1234ull;
	fs_tramp_target = (unsigned long long)(uintptr_t)&hop_landing;
	hop_in_rax = 0x7dull;		/* the fault's live RAX */
	hop_in_r11 = 0x1234ull;
	hop_run_fault();
	CHECK(seen_rax == 0x7dull);
	CHECK(rec.kind_obs == UML_NT_HOP_KIND_FAULT);	/* not forced to 1 */
	CHECK(rec.rax_obs == 0x7dull);
	CHECK(rec.commit == 300);
	uml_nt_hop_live_read(&rec, 60, 59, 0x77ull, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 1);
}

static void test_flags_unchanged(void)
{
	arm_sys(102, (unsigned long long)(uintptr_t)&hop_landing, 0ull, 9, 8, 1);
	hop_once(0ull, 0x1ull);
	/* the sequence is MOV-only: the arithmetic flags the caller set are
	 * exactly what the guest would receive */
	CHECK((seen_flags & 0x8D5ull) == (KNOWN_FLAGS & 0x8D5ull));
	CHECK((seen_flags & 0x1ull) == 0);	/* CF clear */
	CHECK((seen_flags & 0x400ull) == 0);	/* DF clear */
	CHECK((seen_flags & 0x100ull) == 0);	/* TF clear */
}

static void test_red_zone_untouched(void)
{
	arm_sys(103, (unsigned long long)(uintptr_t)&hop_landing, 0ull, 11, 10, 2);
	hop_once(0ull, 0x2ull);
	{
		int i;

		for (i = 0; i < RZ_WORDS; i++)
			CHECK(seen_rz[i] == (0xC0DE0000ull + (unsigned)i));
	}
}

static void test_callee_saved_untouched(void)
{
	arm_sys(104, (unsigned long long)(uintptr_t)&hop_landing, 0ull, 13, 12, 3);
	hop_once(0ull, 0x3ull);
	CHECK(seen_rbx == 0x1b1b1b1bull);
	CHECK(seen_r12 == 0x12121212ull);
	CHECK(seen_r13 == 0x13131313ull);
	CHECK(seen_r14 == 0x14141414ull);
	CHECK(seen_r15 == 0x15151515ull);
	CHECK(seen_rcx == 0x0c0c0c0cull);
	CHECK(seen_rdx == 0x0d0d0d0dull);	/* guest-live in fault replay */
	CHECK(seen_rsi == 0x0e0e0e0eull);
	CHECK(seen_rdi == 0x0f0f0f0full);
	CHECK(seen_rbp == 0x0b0b0b0bull);
	CHECK(seen_r8 == 0x08080808ull);
	CHECK(seen_r9 == 0x09090909ull);
	CHECK(seen_r10 == 0x0a0a0a0aull);
	/* RSP is compared against its PRE-sequence value, not just with itself */
	CHECK(seen_rsp == rsp_before);
}

static void test_back_to_back(void)
{
	struct uml_nt_hop_live_view v;

	arm_sys(201, (unsigned long long)(uintptr_t)&hop_landing, 0ull, 20, 19, 4);
	hop_once(0xA0ull, 0x4ull);
	CHECK(rec.commit == 201 && rec.rax_obs == 0xA0ull);

	arm_sys(202, (unsigned long long)(uintptr_t)&hop_landing, 0ull, 21, 20, 5);
	uml_nt_hop_live_read(&rec, 21, 20, 5, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ARMED_ONLY);
	hop_once(0xB0ull, 0x5ull);
	CHECK(rec.commit == 202 && rec.rax_obs == 0xB0ull);
	uml_nt_hop_live_read(&rec, 21, 20, 5, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
}

int main(void)
{
	test_sys_hop_delivers_and_restores();
	test_delivered_rax_not_entry_rax();
	test_fault_kind_is_executed();
	test_flags_unchanged();
	test_red_zone_untouched();
	test_callee_saved_untouched();
	test_back_to_back();

	if (fails) {
		printf("test_hop_live_asm: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_hop_live_asm: all ok (snippet control, not Windows dispatch)\n");
	return 0;
}
