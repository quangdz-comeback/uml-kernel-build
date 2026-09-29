// SPDX-License-Identifier: GPL-2.0
/*
 * x86/um/os-Windows/registers.c — register save/restore seams.
 * Upstream: linux v6.18.37 arch/x86/um/os-Linux/registers.c (ptrace
 * PTRACE_GETREGSET + xstate). NT: regs live in the VEH CONTEXT of the
 * stub thread; pid-based ptrace APIs have no meaning (D6 seccomp path).
 * Status: M1.4 skeleton — PANICs.
 */
#include "stub-impl.h"

int get_fp_registers(int pid, unsigned long *regs)
{
	stub_panic("registers.c: get_fp_registers — NT: XSAVE area from stub data page");
}

int put_fp_registers(int pid, unsigned long *regs)
{
	stub_panic("registers.c: put_fp_registers");
}

int arch_init_registers(int pid)
{
	stub_panic("registers.c: arch_init_registers — NT: query XSAVE size via CPUID");
}

unsigned long get_thread_reg(int reg, jmp_buf *buf)
{
	stub_panic("registers.c: get_thread_reg — NT: read from thread CONTEXT");
}
