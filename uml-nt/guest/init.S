# SPDX-License-Identifier: GPL-2.0
# guest/init.S — M3.4 probe guest: a REAL statically linked ELF64
# (ET_EXEC) the kernel-side loader (skas/elf.c) loads into physmem
# runs + VMAs — the execveat(memfd) analogue replacing the M3.3 raw
# embedded blob for the native CI gate.
#
# Probe conventions (kernel side, stub_ctl.c):
#   - r12 = guard VA #0, r13 = guard VA #1 at entry (callee-saved,
#     passed via init_regs — no symbol lookup, no fixed addresses:
#     D11 forbids assuming any guest VA). Saved into .data first thing.
#   - Every `syscall` is patched to ud2 centrally before entry, so all
#     round-trips go through the kernel.
#   - Markers + exit codes double as the CI contract (uml-nt-m3.yml
#     greps): hi / FAULT1-OK / FAULT2-OK / GUARD0-OK / CHILD-ALIVE /
#     PARENT-RESUMED, parent exit 0, child exit 7, fail 33.
#
# The child's COW trigger is a .data write (fork marks writable VMAs
# COW; the kernel copies the run private on the fault and remaps) —
# proper-flag ELF text is EXECUTE_READ, a text self-write would be a
# genuine SIGSEGV-class kill, unlike the M3.3 blob's RWX text.

	.section .text,"ax"
	.globl _start
_start:
	movq	%r12, guard0(%rip)	# save the kernel-provided guard
	movq	%r13, guard1(%rip)	# VAs (probe convention)

	movl	$1, %eax		# write(1, "hi\n", 3)
	movl	$1, %edi
	leaq	msg_hi(%rip), %rsi
	movl	$3, %edx
	.byte	0x0f, 0x05		# syscall

	movq	guard0(%rip), %rcx	# *guard0 = 0x42 — FAULT #1
	movb	$0x42, (%rcx)		# (INIT maps it NOACCESS; the
					# kernel answers ACTION_PROT RW
					# and the movb re-executes)

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_f1(%rip), %rsi
	movl	$10, %edx
	.byte	0x0f, 0x05

	movq	guard1(%rip), %rcx	# *guard1 = 0x42 — FAULT #2
	movb	$0x42, (%rcx)

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_f2(%rip), %rsi
	movl	$10, %edx
	.byte	0x0f, 0x05

	movq	guard0(%rip), %rcx	# *guard0 = 0x43 — no fault now:
	movb	$0x43, (%rcx)		# the protect STUCK (not a
	cmpb	$0x43, (%rcx)		# one-shot); read-back must agree
	jne	.Lfail

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_g0(%rip), %rsi
	movl	$10, %edx
	.byte	0x0f, 0x05

	movl	$57, %eax		# fork() — kernel spawns the child
	.byte	0x0f, 0x05		# stub with this snapshot, rax = 0
	testl	%eax, %eax
	jne	.Lparent

	# ---- child: rax == 0 ---------------------------------------
	movb	$0x37, childvar(%rip)	# .data write: the child's RW VMA
					# maps COW-RO → FAULT → the kernel
					# copies the run private + remaps
					# RW (fault dispatches on the RW
					# stack — the stack eager-copied
					# at fork, mm_clone's NT constraint)
	cmpb	$0x37, childvar(%rip)	# read-back must agree
	jne	.Lfail

	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_ch(%rip), %rsi
	movl	$12, %edx
	.byte	0x0f, 0x05

	movl	$60, %eax		# exit(7) — asserted by CI
	movl	$7, %edi
	.byte	0x0f, 0x05

.Lparent:
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_pa(%rip), %rsi
	movl	$15, %edx
	.byte	0x0f, 0x05

	movl	$60, %eax		# exit(0)
	xorl	%edi, %edi
	.byte	0x0f, 0x05

.Lfail:
	movl	$60, %eax
	movl	$33, %edi		# exit(33): verify failed
	.byte	0x0f, 0x05

	.section .data,"aw"
	.balign 8
guard0:	.quad	0			# guard VA #0 (kernel → r12)
guard1:	.quad	0			# guard VA #1 (kernel → r13)
childvar: .byte 0			# child COW trigger

	.section .rodata,"a"
msg_hi:	.ascii	"hi\n"
msg_f1:	.ascii	"FAULT1-OK\n"
msg_f2:	.ascii	"FAULT2-OK\n"
msg_g0:	.ascii	"GUARD0-OK\n"
msg_ch:	.ascii	"CHILD-ALIVE\n"
msg_pa:	.ascii	"PARENT-RESUMED\n"
