// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/process.c — the UML scheduler core, ported.
 * Upstream: linux v6.18.37 arch/um/os-Linux/skas/process.c
 *          (the setjmp/longjmp dispatcher half + the seccomp
 *          userspace loop, S2)
 *
 * UML 6.18 kernel tasks are STACKS, not host threads: every task has a
 * jmp_buf (switch_buf); scheduling = switch_threads(me, you) which
 * setjmp-saves the outgoing stack and longjmps into the incoming one.
 * start_idle_thread hosts the central dispatcher (initial_jmpbuf):
 * cold contexts are just {IP=handler, SP=stack_top} — new_thread fills
 * them, nothing is spawned. This is 100% host-thread agnostic, so the
 * NT port is a verbatim copy minus: set_handler(SIGWINCH) (D7 — no
 * signals), and the fatal_sigsegv path (os_dump_core instead).
 *
 * The userspace side (S2) mirrors upstream seccomp shape:
 *   init_new_context (mmctx.c, S1) spawned this mm's stub suspended;
 *   start_userspace = readiness (same call order as upstream);
 *   userspace(regs) = the per-task loop: interrupt_end → first round
 *   hands the conn its entry state and resumes the thread (the stub
 *   publishes CMD_INIT and the INIT plan streams back through the
 *   slot) → wait on THIS conn's evt_in (the D10 turnstile, per-conn —
 *   upstream blocks on the stub's futex/socket instead) → serve via
 *   uml_nt_pump_conn (the probe's machinery, one protocol) → pull
 *   the trap regs back → repeat. Syscall dispatch is the D16 surface
 *   for now; the upstream-parity handle_syscall path (sys_call_table
 *   + real VFS) lands with the task integration (S3+). The M3.7
 *   probe keeps its own service loop — two paths, one protocol.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <as-layout.h>
#include <kern_util.h>
#include <longjmp.h>
#include <mm_id.h>
#include <skas.h>
#include <user.h>
#include <stub-panic.h>
#include <stub_nt.h>
#include <syscall.h>
#include <bench.h>
#include <os.h>
#include <uaccess_walk.h>
#include "internal.h"

int is_skas_winch(int pid, int fd, void *data)
{
	stub_panic("skas/process.c: is_skas_winch — no SIGWINCH on NT (D7)");
}

/* ---- S2: start_userspace + the per-task userspace loop ------------- */

/* NtWaitForSingleObject timeout status (win32 WAIT_TIMEOUT == 258). */
#define UML_NT_STATUS_TIMEOUT ((NTSTATUS)0x00000102)
/* GetExitCodeProcess: 259 = STILL_ACTIVE (win32). */
#define UML_NT_STILL_ACTIVE 259u

/* S4d: one XSTATE-CAPTURED line per boot (the CI gate's evidence). */
static int xstate_pull_logged;

int start_userspace(struct mm_id *mm_id)
{
	struct uml_nt_stub_conn *c;

	/* Upstream: init_new_context ran first and start_userspace
	 * cloned the stub process. NT: uml_nt_mmctx_init (S1) already
	 * spawned the stub suspended; readiness = the conn carries a
	 * live stub_data view. The owning task's first userspace()
	 * round hands over the entry state and resumes the thread. */
	if (mm_id == NULL || mm_id->nt_conn == NULL) {
		os_warn("start_userspace: mm without an NT conn\n");
		return -EINVAL;
	}
	c = mm_id->nt_conn;
	if (c->d == NULL || !c->alive) {
		os_warn("start_userspace: conn pid %d not ready "
			"(d=%p alive=%d)\n", mm_id->pid, (void *)c->d,
			c->alive);
		return -EINVAL;
	}
	return 0;
}

/* First round bootstrap: the task's pt_regs (binfmt wrote the guest
 * entry there) become the stub's jump state — the stub applies
 * init_regs and jumps AFTER its INIT plan streams back. */
static void conn_bootstrap(struct uml_nt_stub_conn *c,
			   struct uml_pt_regs *regs)
{
	struct uml_nt_gp_regs *g = &c->d->init_regs;

	/* No guest code yet: entry/stack/init stay zero until the
	 * owning task hands the conn its first state. __builtin_memset:
	 * linux/string.h collides with user.h's sized_strscpy here. */
	__builtin_memset(g, 0, sizeof(*g));
	g->rax = REGS_AX(regs->gp);
	g->rcx = REGS_CX(regs->gp);
	g->rdx = REGS_DX(regs->gp);
	g->rbx = REGS_BX(regs->gp);
	g->rsp = REGS_SP(regs->gp);
	g->rbp = REGS_BP(regs->gp);
	g->rsi = REGS_SI(regs->gp);
	g->rdi = REGS_DI(regs->gp);
	g->r8 = REGS_R8(regs->gp);
	g->r9 = REGS_R9(regs->gp);
	g->r10 = REGS_R10(regs->gp);
	g->r11 = REGS_R11(regs->gp);
	g->r12 = REGS_R12(regs->gp);
	g->r13 = REGS_R13(regs->gp);
	g->r14 = REGS_R14(regs->gp);
	g->r15 = REGS_R15(regs->gp);
	g->rip = REGS_IP(regs->gp);
	g->rflags = REGS_EFLAGS(regs->gp);
	c->d->entry_va = REGS_IP(regs->gp);
	c->d->stack_va = REGS_SP(regs->gp);
}

/* get_stub_state analogue: pull the trap regs back into the task.
 * The stub's VEH wrote d->regs at the trap; a syscall round carries
 * the return value in d->retval (the stub folds it into its own rax
 * on resume — mirror it here so the guest task sees the retval). */
static void conn_pull_regs(struct uml_pt_regs *regs,
			   const struct uml_nt_stub_data *d, unsigned cmd)
{
	const struct uml_nt_gp_regs *g = &d->regs;

	REGS_AX(regs->gp) = g->rax;
	REGS_CX(regs->gp) = g->rcx;
	REGS_DX(regs->gp) = g->rdx;
	REGS_BX(regs->gp) = g->rbx;
	REGS_SP(regs->gp) = g->rsp;
	REGS_BP(regs->gp) = g->rbp;
	REGS_SI(regs->gp) = g->rsi;
	REGS_DI(regs->gp) = g->rdi;
	REGS_R8(regs->gp) = g->r8;
	REGS_R9(regs->gp) = g->r9;
	REGS_R10(regs->gp) = g->r10;
	REGS_R11(regs->gp) = g->r11;
	REGS_R12(regs->gp) = g->r12;
	REGS_R13(regs->gp) = g->r13;
	REGS_R14(regs->gp) = g->r14;
	REGS_R15(regs->gp) = g->r15;
	REGS_IP(regs->gp) = g->rip;
	REGS_EFLAGS(regs->gp) = g->rflags;
	regs->is_user = 1;
	if (cmd == UML_STUB_CMD_SYSCALL) {
		UPT_SYSCALL_NR(regs) = (long)g->rax; /* the trap's nr */
		REGS_AX(regs->gp) = d->retval; /* guest-visible retval */
	} else {
		/* upstream: "assume it's not a syscall" */
		UPT_SYSCALL_NR(regs) = -1;
	}
	/* S4d: a fault round records the fault itself — copy_sc_to_user
	 * builds the sigframe's cr2/err/trapno from thread faultinfo
	 * (upstream fills it via get_skas_faultinfo at the SIGSEGV
	 * trap). NT mapping: cr2 = the faulting VA, trap 14 (page
	 * fault), x86 error-code bits (user | write | instruction). */
	if (cmd == UML_STUB_CMD_FAULT) {
		regs->faultinfo.cr2 = (unsigned long)d->fault_addr;
		regs->faultinfo.trap_no = 14;
		regs->faultinfo.error_code = 0x4 /* user */ |
			(d->fault_type == 1 ? 0x2 /* write */ :
			 d->fault_type == 8 ? 0x10 /* exec */ : 0);
	}
	/* S4d: the FP half of get_fp_registers — the stub captured the
	 * at-exception XSAVE_FORMAT block into d->xstate (context
	 * flags gated); the task's fp block is the kernel's live copy
	 * (signal setup copies it into the sigframe, sigreturn writes
	 * it back). Zero-size while no capture: INIT rounds and POC
	 * conns (no task) never wrote it. One log line per boot: the
	 * CI gate greps it as the round-trip-live evidence. */
	if (d->xstate_flags & UML_STUB_XS_CAPTURED) {
		__builtin_memcpy(regs->fp, (const void *)d->xstate,
				 host_fp_size);
		if (!xstate_pull_logged) {
			xstate_pull_logged = 1;
			os_info("[stubtest] XSTATE-CAPTURED: %lu fp bytes "
				"round-trip live (fcw=0x%04x)\n",
				host_fp_size,
				(unsigned short)*(u16 *)regs->fp);
		}
	}
}

/* S4d: the put_fp_registers half — publish the task's FP block to
 * the stub and flag the restore. Today the bytes are the capture's
 * own (the kernel changes regs->fp only via signal delivery /
 * sigreturn, the next slice); running the identity every round
 * exercises the full capture→pull→push→restore loop with zero
 * behavior change. */
void uml_nt_fp_push(struct uml_nt_stub_conn *c, struct uml_pt_regs *regs)
{
	struct uml_nt_stub_data *d = c->d;

	if (!(d->xstate_flags & UML_STUB_XS_CAPTURED))
		return;
	__builtin_memcpy((void *)d->xstate, regs->fp, host_fp_size);
	d->xstate_flags |= UML_STUB_XS_RESTORE;
}

/* D15's guest-write (uaccess.c; linux/uaccess.h can't be included
 * here — it collides with user.h's sized_strscpy). */
extern unsigned long raw_copy_to_user(void *to, const void *from,
				      unsigned long n);

/* S4d: signal delivery between "trap served" and "stub resumed" —
 * the position upstream gets from interrupt_end() at the bottom of
 * every userspace() iteration (the stub is STOPPED there; the
 * rewritten regs ride the next iteration's SETREGS push). The NT
 * pump answers in one go, so this runs in pump_conn before the
 * evt_out release:
 *
 * 1. make current->thread.regs THIS round's state (rt_sigreturn
 *    already wrote the restored state into it — skip the pull);
 * 2. interrupt_end(): the generic machinery runs get_signal →
 *    do_signal → setup_signal_stack_si — the sigframe (GP snapshot
 *    + FP block from regs->fp + siginfo) is written through the D15
 *    walker and regs become the HANDLER's entry state; with no
 *    handler the default action kills the task right here (do_exit
 *    → exit_mm → mmctx_destroy terminates the stub — no leak);
 * 3. a delivered signal (or the sigreturn's restored state) is
 *    pushed VERBATIM: the stub must not do its own rip+2/rax=retval
 *    syscall resume over it.
 *
 * The delivery here is the task's own — force_sig_fault (the fault
 * path's SIGSEGV) and the generic send-signal syscalls mark
 * TIF_SIGPENDING on THIS task; the POC conns never reach this. */
void uml_nt_signal_check(struct uml_nt_stub_conn *c)
{
	struct uml_pt_regs *regs = c->owner_regs;
	struct uml_nt_stub_data *d = c->d;
	struct uml_nt_uacc_sink sink;
	struct uml_nt_mm *prev_mm;
	struct uml_nt_uacc_sink prev_sink;
	unsigned long long rip_before;
	unsigned long long true_sp;

	if (!c->sig_regs_current) {
		/* Syscall-shaped rounds resume past the ud2 (the stub
		 * does rip+2) — the completed-syscall state is what a
		 * signal frame must record. Fault rounds are
		 * mid-instruction: pull verbatim, no +2. */
		if (d->cmd == UML_STUB_CMD_FAULT)
			conn_pull_regs(regs, d, d->cmd);
		else
			uml_nt_sync_trap_regs(regs, d);
	}
	c->sig_regs_current = 0;

	/* The signal machinery WRITES GUEST MEMORY (the sigframe: GP
	 * snapshot + FP block + siginfo — copy_to_user/__put_user all
	 * walk through the D15 walker). The dispatch restored the
	 * uaccess globals at its exit; install THIS conn's mm + a sink
	 * for the duration (the dispatch's own pattern), so the frame
	 * setup cannot hit the null-mm fail-safe EFAULT — which would
	 * force_sigsegv the task to death with SIG_DFL (found on the
	 * first wine run: handler installed, delivery took the default
	 * action). COW fixups from the frame writes queue into the
	 * conn's plan and stream with this answer. */
	sink.ph = c->ph;
	sink.plan = &c->plan;
	prev_mm = uml_nt_uacc_set_mm(c->mm);
	prev_sink = uml_nt_uacc_set_sink(&sink);

	/* The previous ops (if any) streamed to completion (the pump
	 * gates this call on plan_left == 0) — queue fresh. */
	c->plan.n_ops = 0;

	rip_before = REGS_IP(regs->gp);

	/* Wine builds the exception dispatch state (EXCEPTION_RECORD +
	 * full CONTEXT + xstate — the exc_stack) ON THE GUEST STACK,
	 * just below the trap rsp (~12KB with the xstate area), and
	 * the context buffer LIVES there while our VEH runs. The
	 * upstream frame placement (at the interrupted rsp, growing
	 * down) lands inside that window and corrupts the dispatch
	 * context mid-round-trip: the handler resumed with wine's
	 * saved registers replaced by sigframe bytes (rdx read as
	 * 0xD), and NtSetContextThread rejected the context
	 * (C000000D) — the dispatch fell to the SEH walk and died.
	 * Deliver the frame 8KB deeper instead, then patch the frame's
	 * saved mcontext rsp back to the TRUE trap rsp: rt_sigreturn
	 * restores the guest exactly where it was, and the handler's
	 * own execution (plus any wine dispatch below IT) stays inside
	 * the 64KB stack run, away from everything else. Upstream
	 * delivers at the interrupted rsp; the sigreturn path derives
	 * the frame from the live rsp (frame = sp - 8 after the
	 * handler's ret), so the frame position is free for us to
	 * choose. */
	true_sp = REGS_SP(regs->gp);
	REGS_SP(regs->gp) = true_sp - 0x2000;

	interrupt_end();

	if (REGS_IP(regs->gp) == rip_before) {
		/* Nothing delivered: the deep sp was only a frame
		 * placement. Put the real one back — after rt_sigreturn
		 * the verbatim push below resumes the guest at exactly
		 * this sp, and a 0x2000-deep one made its next `ret` pop
		 * stale stack (the net gate's sh died at rip 0 right
		 * after its first SIGCHLD). */
		REGS_SP(regs->gp) = true_sp;
	} else {
		/* Post-setup: SP = the frame (the handler's entry rsp,
		 * kept for the verbatim push). The setup saved the DEEP
		 * sp into the frame's mcontext — patch the saved rsp
		 * back to the true one (frame + pretcode 8 + uc_flags 8
		 * + uc_link 8 + uc_stack 24 = the mcontext;
		 * sigcontext_64's sp = its 16th qword = +120 → +168
		 * total). Through the walker while the mm/sink window is
		 * still open. */
		unsigned long *sp_slot =
			(unsigned long *)(REGS_SP(regs->gp) + 168);
		unsigned long true_rsp = (unsigned long)true_sp;

		if (raw_copy_to_user(sp_slot, &true_rsp, sizeof(true_rsp)))
			os_info("[stubtest] signal frame rsp fixup "
				"EFAULT (frame %llx)\n",
				(unsigned long long)REGS_SP(regs->gp));
	}

	uml_nt_uacc_set_mm(prev_mm);
	uml_nt_uacc_set_sink(&prev_sink);

	/* The frame setup queued stub ops (a COW-shared run went
	 * private mid-write): prime the plan streaming — the answer
	 * becomes the first op, the rest stream on the PROT_DONE
	 * rounds, and the VERBATIM push below survives until the
	 * stub's final resume (it clears the flags only there). */
	if (c->plan.n_ops > 0) {
		c->plan_next = 0;
		c->plan_left = c->plan.n_ops;
		uml_nt_plan_issue_op(c, &c->plan.ops[0]);
	}

	if (REGS_IP(regs->gp) != rip_before || c->push_verbatim) {
		/* Delivered (or restored): regs = the exact resume
		 * state. Push the GP snapshot verbatim — the FP push
		 * follows in the pump (regs->fp is what setup copied
		 * into the frame, or what sigreturn restored). */
		struct uml_nt_gp_regs *g = &d->regs;

		g->rax = REGS_AX(regs->gp);
		g->rcx = REGS_CX(regs->gp);
		g->rdx = REGS_DX(regs->gp);
		g->rbx = REGS_BX(regs->gp);
		g->rsp = REGS_SP(regs->gp);
		g->rbp = REGS_BP(regs->gp);
		g->rsi = REGS_SI(regs->gp);
		g->rdi = REGS_DI(regs->gp);
		g->r8 = REGS_R8(regs->gp);
		g->r9 = REGS_R9(regs->gp);
		g->r10 = REGS_R10(regs->gp);
		g->r11 = REGS_R11(regs->gp);
		g->r12 = REGS_R12(regs->gp);
		g->r13 = REGS_R13(regs->gp);
		g->r14 = REGS_R14(regs->gp);
		g->r15 = REGS_R15(regs->gp);
		g->rip = REGS_IP(regs->gp);
		g->rflags = REGS_EFLAGS(regs->gp);
		d->xstate_flags |= UML_STUB_XS_VERBATIM;
	}
	c->push_verbatim = 0;
}

/* M4.2 fork prep: the generic fork's copy_thread memcpy's
 * current_pt_regs — which on this port is one round STALE (the
 * current trap lives in d->regs until conn_pull_regs runs after the
 * handler). Sync the trap state in, with rip +2: the child's first
 * conn_bootstrap jumps to shadow.rip, and it must resume PAST the
 * ud2 (the stub does the same +2 for the parent's own resume).
 * copy_thread then sets the child's syscall retval 0 — fork
 * semantics. */
void uml_nt_sync_trap_regs(struct uml_pt_regs *regs,
			   const struct uml_nt_stub_data *d)
{
	conn_pull_regs(regs, d, UML_STUB_CMD_SYSCALL);
	REGS_IP(regs->gp) += 2;
}

void userspace(struct uml_pt_regs *regs)
{
	interrupt_end();

	while (1) {
		struct mm_id *mm_id = current_mm_id();
		struct uml_nt_stub_conn *c;
		unsigned cmd;
		int rc;

		if (mm_id == NULL || mm_id->nt_conn == NULL) {
			printk(UM_KERN_ERR "userspace: task without an "
			       "NT mm conn\n");
			os_dump_core();
		}
		c = mm_id->nt_conn;
		/* S4d: the FP round-trip runs in the pump (before the
		 * answer releases the stub) and needs THIS task's
		 * pt_regs — record it on the conn every round (the mm
		 * can switch under execve; the conn dies with it). */
		c->owner_regs = regs;

		/* current_mm_sync() upstream flushes the pte batch into
		 * the stub; on NT the conn's VMA tree IS the truth —
		 * ops stream back through the slot at serve time. The
		 * first round hands over the entry state and starts
		 * the suspended thread. */
		if (!c->resumed) {
			conn_bootstrap(c, regs);
			c->resumed = 1;
			nt->ResumeThread(c->thread);
		}

		/* Turnstile (D10): block on THIS conn's evt_in — the
		 * per-task wait (upstream blocks on the stub's futex).
		 * M5.1c: the net reader thread also wakes us (the D19
		 * wake event) so RX IRQs run between stub traps — the
		 * upstream shape (SIGIO interrupts the blocking poll,
		 * the handler runs, delivery returns). The timeout
		 * keeps a dead/hung stub loud instead of a silent
		 * boot hang (M1.9 lesson). */
		for (;;) {
			HANDLE waits[2];
			ULONG w, code;
			LARGE_INTEGER to;

			waits[0] = c->evt_in;
			waits[1] = uml_nt_net_wake_event();
			if (waits[1] != NULL) {
				w = nt->WaitForMultipleObjects(2, waits, 0,
							       1000);
			} else {
				/* No wake event (creation failed): the
				 * old plain wait — 1s timeout, no RX
				 * wake (loud at creation site). */
				to.QuadPart = -10000000LL; /* 1s */
				w = nt->NtWaitForSingleObject(c->evt_in, 0,
							      &to) ==
				    UML_NT_STATUS_TIMEOUT ?
					    258u : 0;
			}
			if (w == 0)
				break; /* stub trap ready */
			if (w == 1) {
				/* A frame was staged: run the SIGIO
				 * machinery (registry flush → the net
				 * IRQ) on THIS thread, then re-wait. */
				uml_nt_sigio_flush();
				continue;
			}
			if (w == 258u /*WAIT_TIMEOUT*/) {
				code = 0;
				nt->GetExitCodeProcess(c->proc, &code);
				if (code != UML_NT_STILL_ACTIVE) {
					/* The last published trap is the
					 * last state the kernel handed or
					 * saw — after a verbatim push it
					 * is the resume target itself. */
					os_info("userspace: stub pid %d "
						"died silently (%lu) — last "
						"cmd=%u rip=%llx rsp=%llx "
						"rax=%llx xs_flags=%x\n",
						mm_id->pid,
						(unsigned long)code,
						(unsigned)c->d->cmd,
						c->d->regs.rip,
						c->d->regs.rsp,
						c->d->regs.rax,
						(unsigned)c->d->xstate_flags);
					uml_nt_diag_slot("death-rsp", c,
							 c->d->regs.rsp);
					uml_nt_diag_mm("death", c);
					os_dump_core();
				}
				continue;
			}
			if (w == 0xFFFFFFFFu /*WAIT_FAILED*/) {
				os_info("userspace: wait failed "
					"win32=%lu\n",
					nt->RtlGetLastWin32Error());
				nt->NtDelayExecution(0, &(LARGE_INTEGER){
					.QuadPart = -100000LL /*10ms*/ });
				continue;
			}
			/* Any other wait outcome: treat as the trap
			 * being ready (defensive; not reachable). */
			break;
		}

		cmd = c->d->cmd;
		rc = uml_nt_pump_conn(c);
		/* M4.1 bench: one QPC timestamp per round — the delta
		 * from the previous round is the full syscall RTT and
		 * is recorded only while the bench window is open
		 * (bench.c; nothing logs here per round). */
		uml_nt_bench_sample();
		if (rc == 2) {
			/* execve conn switch: the old conn (and its d)
			 * were destroyed mid-round — no reg pull (d is
			 * gone). The loop re-reads current_mm_id(); the
			 * NEW conn bootstraps from current_pt_regs,
			 * where binfmt's start_thread wrote the entry. */
			os_info("userspace: exec conn switch → new mm "
				"pid %d\n",
				current_mm_id() ? current_mm_id()->pid :
						  -1);
			continue;
		}
		/* The INIT round carries no trap regs (d->regs is still
		 * the zeroed bootstrap state — the stub publishes INIT
		 * before its first VEH trap); pulling there would wipe
		 * the task's pt_regs with zeros. Every LATER publish
		 * (VEH syscall/fault) wrote d->regs for real. */
		if (cmd != UML_STUB_CMD_INIT)
			conn_pull_regs(regs, c->d, cmd);

		if (rc < 0) {
			printk(UM_KERN_ERR "userspace: stub protocol "
			       "error (pid %d)\n", mm_id->pid);
			os_dump_core();
		}
		if (rc == 1) {
			/* The guest exited (halt) or died (KILL): the
			 * stub is already terminated. M4.2: THIS task
			 * exits kernel-side — do_exit runs the full
			 * teardown (exit_mm → destroy_context closes
			 * the conn, exit_notify wakes a wait4 parent,
			 * the scheduler moves on). The init task dying
			 * here panics generically ("Attempted to kill
			 * init") — same loud exit-1 the gates assert.
			 * Signal-death fidelity (which signal, core
			 * dump semantics) is the M4 signals slice;
			 * the wait status carries the exit code only. */
			os_info("userspace: guest pid %d halted "
				"(exit %lu) — task exit\n",
				mm_id->pid,
				(unsigned long)c->exit_code);
			do_exit((long)(c->exit_code & 0xffu) << 8);
		}
	}
}

void new_thread(void *stack, jmp_buf *buf, void (*handler)(void))
{
	(*buf)[0].JB_IP = (unsigned long) handler;
	(*buf)[0].JB_SP = (unsigned long) stack + UM_THREAD_SIZE -
		sizeof(void *);
}

void switch_threads(jmp_buf *me, jmp_buf *you)
{
	if (UML_SETJMP(me) == 0)
		UML_LONGJMP(you, 1);
}

static jmp_buf initial_jmpbuf;

static void (*cb_proc)(void *arg);
static void *cb_arg;
static jmp_buf *cb_back;

#define INIT_JMP_NEW_THREAD 0
#define INIT_JMP_CALLBACK 1
#define INIT_JMP_HALT 2
#define INIT_JMP_REBOOT 3

int start_idle_thread(void *stack, jmp_buf *switch_buf)
{
	int n;

	/*
	 * Raw setjmp (no UML_SETJMP): this context is jumped back to
	 * from arbitrary stacks — signals state must not be restored
	 * here (same reasoning as upstream).
	 */
	n = setjmp(initial_jmpbuf);
	switch (n) {
	case INIT_JMP_NEW_THREAD:
		(*switch_buf)[0].JB_IP = (unsigned long) uml_finishsetup;
		(*switch_buf)[0].JB_SP = (unsigned long) stack +
			UM_THREAD_SIZE - sizeof(void *);
		break;
	case INIT_JMP_CALLBACK:
		(*cb_proc)(cb_arg);
		longjmp(*cb_back, 1);
		break;
	case INIT_JMP_HALT:
		kmalloc_ok = 0;
		return 0;
	case INIT_JMP_REBOOT:
		kmalloc_ok = 0;
		return 1;
	default:
		printk(UM_KERN_ERR "Bad setjmp return in %s - %d\n",
		       __func__, n);
		os_dump_core();
	}
	longjmp(*switch_buf, 1);

	/* unreachable */
	printk(UM_KERN_ERR "impossible long jump!");
	os_dump_core();
	return 0;
}

void initial_thread_cb_skas(void (*proc)(void *), void *arg)
{
	jmp_buf here;

	cb_proc = proc;
	cb_arg = arg;
	cb_back = &here;

	block_signals_trace();
	if (UML_SETJMP(&here) == 0)
		UML_LONGJMP(&initial_jmpbuf, INIT_JMP_CALLBACK);
	unblock_signals_trace();

	cb_proc = 0;
	cb_arg = 0;
	cb_back = 0;
}

void halt_skas(void)
{
	longjmp(initial_jmpbuf, INIT_JMP_HALT);
}

void reboot_skas(void)
{
	longjmp(initial_jmpbuf, INIT_JMP_REBOOT);
}
