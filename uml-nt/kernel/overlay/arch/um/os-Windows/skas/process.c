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
		 * A 1s timeout keeps a dead/hung stub loud instead of
		 * a silent boot hang (M1.9 lesson; the probe's service
		 * loop does the same). */
		for (;;) {
			LARGE_INTEGER to;
			ULONG code;

			to.QuadPart = -10000000LL; /* 1s, relative */
			if (nt->NtWaitForSingleObject(c->evt_in, 0,
						      &to) !=
			    UML_NT_STATUS_TIMEOUT)
				break;
			code = 0;
			nt->GetExitCodeProcess(c->proc, &code);
			if (code != UML_NT_STILL_ACTIVE) {
				os_info("userspace: stub pid %d died "
					"silently (%lu)\n", mm_id->pid,
					(unsigned long)code);
				os_dump_core();
			}
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
			/* The guest exited; the kernel terminated the
			 * stub (halt → kill + reap). Upstream never
			 * returns here either — the task is dead. Task
			 * teardown parity (do_exit path) is the S4/M4
			 * work: fail loud, never loop on a dead conn. */
			os_info("userspace: guest pid %d halted\n",
				mm_id->pid);
			os_dump_core();
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
