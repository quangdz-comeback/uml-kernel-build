// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/registers.c — register save/restore across host/guest.
 * Upstream: linux v6.18.37 arch/um/os-Linux/registers.c
 *
 * Upstream decls (registers.h) are pid-based (ptrace-mode); the seccomp
 * path carries regs in stub_data instead. For the NT port, CONTEXT in
 * the VEH record is the source of truth (S1 fidelity 4/4); these seams
 * remain until M2 shows which are actually called. Status: PANICs.
 */
#include <stub-impl.h>

int init_pid_registers(int pid)
{
	stub_panic("registers.c: init_pid_registers");
}

void get_safe_registers(unsigned long *regs, unsigned long *fp_regs)
{
	stub_panic("registers.c: get_safe_registers — NT: copy from NT CONTEXT (VEH)");
}
