// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/process.c — process/thread seams for the NT backend.
 * Upstream: linux v6.18.37 arch/um/os-Linux/process.c
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

pid_t os_reap_child(void)
{
	stub_panic("process.c: os_reap_child");
}

void os_alarm_process(int pid)
{
	stub_panic("process.c: os_alarm_process");
}

void os_kill_process(int pid, int reap_child)
{
	stub_panic("process.c: os_kill_process");
}

void os_kill_ptraced_process(int pid, int reap_child)
{
	stub_panic("process.c: os_kill_ptraced_process — ptrace-mode only; kept for os.h parity, D6 uses seccomp path");
}

int os_getpid(void)
{
	stub_panic("process.c: os_getpid — NT: GetCurrentProcessId");
}

void init_new_thread_signals(void)
{
	stub_panic("process.c: init_new_thread_signals — NT: VEH install per thread");
}

int os_map_memory(void *virt, int fd, unsigned long long off,
		  unsigned long len, int r, int w, int x)
{
	stub_panic("process.c: os_map_memory");
}

int os_protect_memory(void *addr, unsigned long len, int r, int w, int x)
{
	stub_panic("process.c: os_protect_memory — NT: VirtualProtect, 4KB page granularity");
}

int os_unmap_memory(void *addr, int len)
{
	stub_panic("process.c: os_unmap_memory");
}

int os_drop_memory(void *addr, int length)
{
	stub_panic("process.c: os_drop_memory — NT: DiscardVirtualMemory (returns error-code, S5)");
}

int can_drop_memory(void)
{
	stub_panic("process.c: can_drop_memory");
}

void os_set_pdeathsig(void)
{
	stub_panic("process.c: os_set_pdeathsig — no NT equivalent; job-object/cleanup redesign at M2");
}
