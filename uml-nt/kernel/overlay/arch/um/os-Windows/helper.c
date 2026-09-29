// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/helper.c — helper threads/processes for user_sigio etc.
 * Upstream: linux v6.18.37 arch/um/os-Linux/helper.c
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

int run_helper(void (*pre_exec)(void *), void *pre_data, char **argv)
{
	stub_panic("helper.c: run_helper");
}

int run_helper_thread(int (*proc)(void *), void *arg,
		      unsigned int flags, unsigned long *stack_out)
{
	stub_panic("helper.c: run_helper_thread");
}

int helper_wait(int pid)
{
	stub_panic("helper.c: helper_wait");
}

int os_run_helper_thread(struct os_helper_thread **td_out,
			 void *(*routine)(void *), void *arg)
{
	stub_panic("helper.c: os_run_helper_thread — NT: CreateThread");
}

void os_kill_helper_thread(struct os_helper_thread *td)
{
	stub_panic("helper.c: os_kill_helper_thread");
}

void os_fix_helper_thread_signals(void)
{
	stub_panic("helper.c: os_fix_helper_thread_signals");
}
