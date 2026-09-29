/* SPDX-License-Identifier: GPL-2.0 */
/*
 * M2 static guest init: write(1, "hi\n", 3); exit(0).
 *
 * Real Linux syscall instructions (0F 05) — uml_nt_patch_syscalls()
 * turns them into ud2 before the stub ever maps the page, so the
 * round-trip goes through the patched path, not the raw instruction.
 * Position-independent: the lea is rip-relative inside this blob.
 * Lives in .rodata: the kernel only ever copies these bytes into the
 * physmem section (guest RAM), never executes them here.
 */
	.section .rodata.nt_guest_init, "a"
	.globl nt_guest_init_start
	.globl nt_guest_init_end
nt_guest_init_start:
	movl	$1, %eax		# __NR_write
	movl	$1, %edi		# fd = 1 (stdout)
	leaq	nt_guest_init_msg(%rip), %rsi
	movl	$3, %edx		# len = 3
	.byte	0x0f, 0x05		# syscall
	movl	$60, %eax		# __NR_exit
	xorl	%edi, %edi		# code = 0
	.byte	0x0f, 0x05		# syscall
nt_guest_init_msg:
	.ascii	"hi\n"
nt_guest_init_end:
