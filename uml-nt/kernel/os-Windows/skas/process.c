// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/process.c — trap loop / userspace switching.
 * Upstream: linux v6.18.37 arch/um/os-Linux/skas/process.c
 *
 * This is where upstream blocks in ptrace/seccomp waits and resumes the
 * stub. The NT backend: each guest process is a stub.exe thread
 * suspended on the cmd-slot event; the kernel-side loop checks results
 * and issues commands (S2 spin-protocol, 100ns p50). jmp_buf thread
 * switching upstream becomes NT thread suspension primitives here.
 * Status: M1.3 skeleton — PANICs; first real work in M2.
 */
#include <stub-impl.h>

int is_skas_winch(int pid, int fd, void *data)
{
	stub_panic("skas/process.c: is_skas_winch");
}

int start_userspace(struct mm_id *mm_id)
{
	stub_panic("skas/process.c: start_userspace — NT: spawn stub.exe (S5: suspended 1ms p50)");
}

void userspace(struct uml_pt_regs *regs)
{
	stub_panic("skas/process.c: userspace — NT: VEH ud2/AV round-trip (S1)");
}

void new_thread(void *stack, jmp_buf *buf, void (*handler)(void))
{
	stub_panic("skas/process.c: new_thread");
}

void switch_threads(jmp_buf *me, jmp_buf *you)
{
	stub_panic("skas/process.c: switch_threads — NT: thread-level switch redesign");
}

int start_idle_thread(void *stack, jmp_buf *switch_buf)
{
	stub_panic("skas/process.c: start_idle_thread");
}

void initial_thread_cb_skas(void (*proc)(void *), void *arg)
{
	stub_panic("skas/process.c: initial_thread_cb_skas");
}

void halt_skas(void)
{
	stub_panic("skas/process.c: halt_skas");
}

void reboot_skas(void)
{
	stub_panic("skas/process.c: reboot_skas");
}
