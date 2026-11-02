/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hop_live_asm.h — the exact instruction sequence the plain trampolines add.
 *
 * The same macro text is used by production (stub/stub.c) and by the host
 * x86-64 control harness (tests/test_hop_live_asm.c), so the harness executes
 * the real sequence rather than a lookalike.
 *
 * Rules this sequence keeps:
 *   - MOV only. No push/pop, no call, no test/branch, no RDTSC, no RSP change:
 *     the guest's flags and stack are untouched, and no compiler prologue can
 *     appear because the whole trampoline is naked asm.
 *   - One scratch register (%r11) plus %rax borrowed through the record itself:
 *     %rax is stored into the record first and restored from it afterwards,
 *     never saved on the guest stack or in the red zone.
 *   - The commit id is written LAST, after every observation, so a reader can
 *     never see a half-written sample with a valid commit.
 *   - The caller must place HOP_LIVE_STAMP_COMMIT after the existing
 *     RDTSC save/restore block and immediately before the existing
 *     `movq fs_save_r11(%rip), %r11 ; jmp *fs_tramp_target(%rip)`.
 *
 * `fs_live_ptr` is a plain pointer global that is non-NULL from the moment the
 * shared page exists (before that it points at a private dummy record), so the
 * sequence needs no null test and therefore no flag change.
 */
#ifndef UML_NT_HOP_LIVE_ASM_H
#define UML_NT_HOP_LIVE_ASM_H

#include "hop_live.h"

/* Entry: copy the arm id into `entered` (no flags touched, RAX restored). */
#define HOP_LIVE_STAMP_ENTER()						\
	"movq	fs_live_ptr(%rip), %r11\n\t"				\
	"movq	%rax, " HOP_OFF_STR(RAX_OBS) "(%r11)\n\t"		\
	"movq	" HOP_OFF_STR(ARM) "(%r11), %rax\n\t"			\
	"movq	%rax, " HOP_OFF_STR(ENTERED) "(%r11)\n\t"		\
	"movq	" HOP_OFF_STR(RAX_OBS) "(%r11), %rax\n\t"

/* Pre-jmp: record what is about to be delivered, commit last. */
#define HOP_LIVE_STAMP_COMMIT(KIND)					\
	"movq	fs_live_ptr(%rip), %r11\n\t"				\
	"movq	%rax, " HOP_OFF_STR(RAX_OBS) "(%r11)\n\t"		\
	"movq	%rsp, " HOP_OFF_STR(RSP_OBS) "(%r11)\n\t"		\
	"movq	$" KIND ", " HOP_OFF_STR(KIND_OBS) "(%r11)\n\t"		\
	"movq	fs_tramp_target(%rip), %rax\n\t"			\
	"movq	%rax, " HOP_OFF_STR(TARGET_OBS) "(%r11)\n\t"		\
	"movq	" HOP_OFF_STR(ARM) "(%r11), %rax\n\t"			\
	"movq	%rax, " HOP_OFF_STR(COMMIT) "(%r11)\n\t"		\
	"movq	" HOP_OFF_STR(RAX_OBS) "(%r11), %rax\n\t"

/* Offset as a literal, so the asm never depends on the compiler's syntax for
 * a struct member. The two indirections are what let the macro expand to its
 * value before it is stringized. */
#define HOP_OFF_STR(which) HOP_OFF_STR_X(UML_NT_HOP_LIVE_OFF_##which)
#define HOP_OFF_STR_X(v) HOP_OFF_STR_Y(v)
#define HOP_OFF_STR_Y(v) #v

#endif /* UML_NT_HOP_LIVE_ASM_H */
