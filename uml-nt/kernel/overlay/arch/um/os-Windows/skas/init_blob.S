/* SPDX-License-Identifier: GPL-2.0 */
/*
 * M3.3 static guest init: fault round-trips + fork across stubs.
 *
 * Parent path:
 *   write(1, "hi\n")            — syscall path (M2 regression gate)
 *   *guard0 = 0x42             — FAULT #1: write to a PAGE_NOACCESS page
 *                                (INIT maps it NOACCESS; kernel answers
 *                                ACTION_PROT RW, the movb re-executes)
 *   write(1, "FAULT1-OK\n")
 *   *guard1 = 0x42             — FAULT #2 (second guard page)
 *   write(1, "FAULT2-OK\n")
 *   *guard0 = 0x43; cmp        — no fault: the protect STUCK (not a
 *                                one-shot fix-up); byte must read back
 *   write(1, "GUARD0-OK\n")
 *   fork()                     — kernel spawns the child stub with this
 *                                register snapshot, rax = 0 here
 *   test rax / parent path:
 *   write(1, "PARENT-RESUMED\n"); exit(0)
 * Child path (rax == 0):
 *   text self-write 0x37       — the child's text VMA maps COW-RO
 *                                (EXECUTE_READ) → FAULT → the kernel
 *                                copies the run private and remaps
 *                                RWX (ARCHITECTURE §4 COW; the fault
 *                                dispatches on the RW stack — the
 *                                stack itself eager-copied at fork,
 *                                see mm_clone's NT constraint)
 *   read back and verify
 *   write(1, "CHILD-ALIVE\n"); exit(7)
 *
 * Real Linux syscall instructions (0F 05) — uml_nt_patch_syscalls()
 * turns them into ud2 before any stub maps the page, so every
 * round-trip goes through the patched path. Position-independent: the
 * lea is rip-relative inside this blob; the guard VAs are runtime
 * data, patched by the kernel into slot0/slot1 after staging (guest
 * VA) and re-verified after the patch scan. Lives in .rodata: the
 * kernel only ever copies these bytes into the physmem section.
 */
	.section .rodata.nt_guest_init, "a"
	.globl nt_guest_init_start
	.globl nt_guest_init_end
nt_guest_init_start:
	movl	$1, %eax		# __NR_write
	movl	$1, %edi		# fd = 1 (stdout)
	leaq	msg_hi(%rip), %rsi
	movl	$3, %edx		# len = 3
	.byte	0x0f, 0x05		# syscall

	leaq	slot0(%rip), %rcx	# *guard0 = 0x42 — FAULT #1
	movq	(%rcx), %rcx
	movb	$0x42, (%rcx)

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_f1(%rip), %rsi
	movl	$10, %edx
	.byte	0x0f, 0x05

	leaq	slot1(%rip), %rcx	# *guard1 = 0x42 — FAULT #2
	movq	(%rcx), %rcx
	movb	$0x42, (%rcx)

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_f2(%rip), %rsi
	movl	$10, %edx
	.byte	0x0f, 0x05

	leaq	slot0(%rip), %rcx	# *guard0 = 0x43 — no fault now
	movq	(%rcx), %rcx
	movb	$0x43, (%rcx)
	cmpb	$0x43, (%rcx)		# read-back must agree
	jne	.Lfail

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_g0(%rip), %rsi
	movl	$10, %edx
	.byte	0x0f, 0x05

	movl	$57, %eax		# __NR_fork
	.byte	0x0f, 0x05
	testl	%eax, %eax
	jne	.Lparent

	# ---- child: rax == 0 ---------------------------------------
	movb	$0x37, nt_guest_init_start(%rip)  # text self-write: the
						  # child's text view maps
						  # COW-RO -> FAULT, the
						  # kernel copies the run
						  # private and remaps RWX
	cmpb	$0x37, nt_guest_init_start(%rip)  # read-back must agree
	jne	.Lfail

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_ch(%rip), %rsi
	movl	$12, %edx
	.byte	0x0f, 0x05

	movl	$60, %eax		# __NR_exit
	movl	$7, %edi		# code = 7 (asserted by CI)
	.byte	0x0f, 0x05

.Lparent:
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_pa(%rip), %rsi
	movl	$15, %edx
	.byte	0x0f, 0x05

	movl	$60, %eax		# __NR_exit
	xorl	%edi, %edi		# code = 0
	.byte	0x0f, 0x05

.Lfail:
	movl	$60, %eax
	movl	$33, %edi		# code = 33: verify failed
	.byte	0x0f, 0x05

	.balign 8
slot0:	.quad	0			# guard0 guest VA (kernel-patched)
slot1:	.quad	0			# guard1 guest VA (kernel-patched)

	.globl nt_guest_init_slot0
	.set nt_guest_init_slot0, slot0 - nt_guest_init_start
	.globl nt_guest_init_slot1
	.set nt_guest_init_slot1, slot1 - nt_guest_init_start

msg_hi:	.ascii	"hi\n"
msg_f1:	.ascii	"FAULT1-OK\n"
msg_f2:	.ascii	"FAULT2-OK\n"
msg_g0:	.ascii	"GUARD0-OK\n"
msg_ch:	.ascii	"CHILD-ALIVE\n"
msg_pa:	.ascii	"PARENT-RESUMED\n"
nt_guest_init_end:
