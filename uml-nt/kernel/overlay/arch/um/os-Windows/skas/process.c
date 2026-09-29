// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/process.c — the UML scheduler core, ported.
 * Upstream: linux v6.18.37 arch/um/os-Linux/skas/process.c
 *          (the setjmp/longjmp dispatcher half, not the ptrace half)
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
 * The ptrace/seccomp userspace loop (start_userspace/userspace) is the
 * other half — M2 stub.exe work.
 */
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <as-layout.h>
#include <kern_util.h>
#include <longjmp.h>
#include <skas.h>
#include <user.h>
#include <stub-panic.h>
#include "internal.h"

int is_skas_winch(int pid, int fd, void *data)
{
	stub_panic("skas/process.c: is_skas_winch — no SIGWINCH on NT (D7)");
}

int start_userspace(struct mm_id *mm_id)
{
	stub_panic("skas/process.c: start_userspace — NT: spawn stub.exe (S5: suspended 1ms p50, M2)");
}

void userspace(struct uml_pt_regs *regs)
{
	stub_panic("skas/process.c: userspace — NT: VEH ud2/AV round-trip (S1, M2)");
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
