// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/registers.c — register save/restore across host/guest.
 * Upstream: linux v6.18.37 arch/um/os-Linux/registers.c
 *
 * Upstream decls (registers.h) are pid-based (ptrace-mode); the seccomp
 * path carries regs in stub_data instead. For the NT port, CONTEXT in
 * the VEH record is the source of truth (S1 fidelity 4/4); these seams
 * remain until M2 shows which are actually called.
 * Status: M1.8 — get_safe_registers real (zeroed: no live guest yet);
 * init_pid_registers stays skeleton until the stub work (M2).
 */
#include <stub-panic.h>
#include <registers.h>

extern unsigned long host_fp_size;

int init_pid_registers(int pid)
{
	stub_panic("registers.c: init_pid_registers — D6: no ptrace on NT");
}

void get_safe_registers(unsigned long *regs, unsigned long *fp_regs)
{
	/* M1: no live guest exists — zeroed registers satisfy the
	 * init-time callers (fresh task setup). M2 reads the real NT
	 * CONTEXT of the stub thread (VEH round-trip, S1). The xstate
	 * fp block is bounded by host_fp_size (x86 glue). */
	__builtin_memset(regs, 0, MAX_REG_NR * sizeof(unsigned long));
	if (fp_regs != 0)
		__builtin_memset(fp_regs, 0, host_fp_size);
}
