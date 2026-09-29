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
#     PARENT-RESUMED / WAIT4-OK / PID-OK / SIG-OK / BRK-OK / MMAP-OK /
#     SYSCALL-OK, parent exit 0, child exit 7, fail 33 (pre-M3.7
#     checks) / 34 wait4 / 35 pid family / 36 brk / 37 sigprocmask /
#     38 mmap family.
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

	# ---- M3.7: syscall surface (served by the D16 dispatch) ----

	# wait4(-1, &wstatus, 0, 0): the child may still run — the
	# kernel answers -EAGAIN and we retry (bounded); a dead child
	# reaps with its exit(7) status (WEXITSTATUS = bits 8..15).
	movl	$1000000, %r14d
.Lwait4:
	movl	$61, %eax
	movl	$-1, %edi
	leaq	wstatus(%rip), %rsi
	xorl	%edx, %edx
	xorl	%r10d, %r10d
	.byte	0x0f, 0x05
	cmpl	$-11, %eax		# -EAGAIN → retry
	je	.Lw_retry
	jmp	.Lw_got
.Lw_retry:
	decl	%r14d
	jnz	.Lwait4
	jmp	.Lfail34
.Lw_got:
	testl	%eax, %eax		# reaped pid > 0
	jle	.Lfail34
	cmpl	$0x0700, wstatus(%rip)	# child exit(7)
	jne	.Lfail34
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_w4(%rip), %rsi
	movl	$9, %edx
	.byte	0x0f, 0x05

	# getpid() → own stub pid (the same pid wait4 returned)
	movl	$39, %eax
	.byte	0x0f, 0x05
	testl	%eax, %eax
	jle	.Lfail35
	movl	%eax, pid0(%rip)
	# getppid() — root conn → 0
	movl	$110, %eax
	.byte	0x0f, 0x05
	testl	%eax, %eax
	jnz	.Lfail35
	# set_tid_address(&ctid) → own pid
	movl	$218, %eax
	leaq	ctid(%rip), %rdi
	.byte	0x0f, 0x05
	cmpl	pid0(%rip), %eax
	jne	.Lfail35
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_pid(%rip), %rsi
	movl	$7, %edx
	.byte	0x0f, 0x05

	# rt_sigprocmask(SIG_BLOCK=0, NULL, &oldset, 8) → 0, oldset = 0
	movl	$14, %eax
	xorl	%edi, %edi
	xorl	%esi, %esi
	leaq	oldset(%rip), %rdx
	movl	$8, %r10d
	.byte	0x0f, 0x05
	testl	%eax, %eax
	jnz	.Lfail37
	cmpq	$0, oldset(%rip)
	jne	.Lfail37
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_sig(%rip), %rsi
	movl	$7, %edx
	.byte	0x0f, 0x05

	# brk(0) → the reserved heap run start; grow by 16; write it
	movl	$12, %eax
	xorl	%edi, %edi
	.byte	0x0f, 0x05
	testq	%rax, %rax
	jz	.Lfail36
	movq	%rax, h0(%rip)
	movq	%rax, %rdi
	addq	$16, %rdi
	movl	$12, %eax
	.byte	0x0f, 0x05
	movq	h0(%rip), %rcx
	leaq	16(%rcx), %rcx
	cmpq	%rcx, %rax		# brk returns the new break
	jne	.Lfail36
	movq	h0(%rip), %rcx
	movb	$0x77, (%rcx)		# pre-mapped run: no fault
	cmpb	$0x77, (%rcx)
	jne	.Lfail36
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_brk(%rip), %rsi
	movl	$7, %edx
	.byte	0x0f, 0x05

	# mmap(NULL, 4K, RW, PRIVATE|ANON, -1, 0) → fresh run + MAP op
	movl	$9, %eax
	xorl	%edi, %edi
	movl	$0x1000, %esi
	movl	$3, %edx
	movl	$0x22, %r10d
	movq	$-1, %r8
	xorl	%r9d, %r9d
	.byte	0x0f, 0x05
	testq	%rax, %rax
	jz	.Lfail38
	movq	%rax, m1(%rip)
	movb	$0x11, (%rax)		# the MAP op mapped it RW already
	cmpb	$0x11, (%rax)
	jne	.Lfail38
	# munmap(va, 4K) — whole-view unmap
	movl	$11, %eax
	movq	m1(%rip), %rdi
	movl	$0x1000, %esi
	.byte	0x0f, 0x05
	testl	%eax, %eax
	jnz	.Lfail38
	# mmap MAP_FIXED back at the same VA
	movl	$9, %eax
	movq	m1(%rip), %rdi
	movl	$0x1000, %esi
	movl	$3, %edx
	movl	$0x32, %r10d
	movq	$-1, %r8
	xorl	%r9d, %r9d
	.byte	0x0f, 0x05
	cmpq	m1(%rip), %rax
	jne	.Lfail38
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_mm(%rip), %rsi
	movl	$8, %edx
	.byte	0x0f, 0x05
	movl	$1, %eax
	movl	$1, %edi
	leaq	msg_ok(%rip), %rsi
	movl	$11, %edx
	.byte	0x0f, 0x05

	movl	$60, %eax		# exit(0)
	xorl	%edi, %edi
	.byte	0x0f, 0x05

.Lfail:					# pre-M3.7 checks: verify failed
	movl	$60, %eax
	movl	$33, %edi		# exit(33): verify failed
	.byte	0x0f, 0x05

.Lfail34:					# wait4
	movl	$60, %eax
	movl	$34, %edi
	.byte	0x0f, 0x05
.Lfail35:					# pid family
	movl	$60, %eax
	movl	$35, %edi
	.byte	0x0f, 0x05
.Lfail36:					# brk
	movl	$60, %eax
	movl	$36, %edi
	.byte	0x0f, 0x05
.Lfail37:					# sigprocmask
	movl	$60, %eax
	movl	$37, %edi
	.byte	0x0f, 0x05
.Lfail38:					# mmap/munmap
	movl	$60, %eax
	movl	$38, %edi
	.byte	0x0f, 0x05

	.section .data,"aw"
	.balign 8
guard0:	.quad	0			# guard VA #0 (kernel → r12)
guard1:	.quad	0			# guard VA #1 (kernel → r13)
childvar: .byte 0			# child COW trigger
wstatus: .long	0			# wait4 status
pid0:	.long	0			# getpid result
ctid:	.quad	0			# set_tid_address target
oldset:	.quad	0			# sigprocmask oldset
h0:	.quad	0			# brk(0) result
m1:	.quad	0			# mmap result

	.section .rodata,"a"
msg_hi:	.ascii	"hi\n"
msg_f1:	.ascii	"FAULT1-OK\n"
msg_f2:	.ascii	"FAULT2-OK\n"
msg_g0:	.ascii	"GUARD0-OK\n"
msg_ch:	.ascii	"CHILD-ALIVE\n"
msg_pa:	.ascii	"PARENT-RESUMED\n"
msg_w4:	.ascii	"WAIT4-OK\n"
msg_pid: .ascii	"PID-OK\n"
msg_sig: .ascii	"SIG-OK\n"
msg_brk: .ascii	"BRK-OK\n"
msg_mm:	.ascii	"MMAP-OK\n"
msg_ok:	.ascii	"SYSCALL-OK\n"
