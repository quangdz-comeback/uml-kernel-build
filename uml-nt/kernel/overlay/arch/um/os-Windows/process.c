// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/process.c — guest-process + memory-mapping primitives.
 * Upstream: linux v6.18.37 arch/um/os-Linux/process.c
 *
 * os_map_memory is the demand-mapped analogue of mmap(MAP_FIXED) on the
 * physmem fd: NtMapViewOfSection at the guest address (mem.c hands out
 * pseudo-fds). The clone/ptrace stub work is M2 — everything process-
 * management below keeps the M1.3 PANIC scaffolding.
 */
#include <ntabi.h>
#include <stub-panic.h>

#include <os.h>
#include "internal.h"

int os_getpid(void)
{
	return (int)nt->GetCurrentProcessId();
}

void os_kill_process(int pid, int reap_child)
{
	stub_panic("process.c: os_kill_process — NT: M2 (stub lifetime)");
}

void os_kill_ptraced_process(int pid, int reap_child)
{
	stub_panic("process.c: os_kill_ptraced_process — D6");
}

pid_t os_reap_child(void)
{
	stub_panic("process.c: os_reap_child — NT: wait-on-thread (M2)");
	return -1;
}

void os_alarm_process(int pid)
{
	stub_panic("process.c: os_alarm_process");
}

void init_new_thread_signals(void)
{
	/* NT threads need no signal setup (D7) */
}

void os_set_pdeathsig(void)
{
	/* no parent-death signal on NT; launcher tracks the stub (M2) */
}

/* physmem mapping (moved here to mirror upstream os-Linux/process.c). */
int os_map_memory(void *virt, int fd, unsigned long long off,
		  unsigned long len, int r, int w, int x)
{
	PVOID base;
	SIZE_T view;
	LARGE_INTEGER li;
	NTSTATUS s;
	ULONG protect;

	if (fd != UML_NT_MEMFD_PHYS) {
		os_info("os_map_memory: unknown fd %d\n", fd);
		return -1;
	}

	base = virt;
	view = 0;
	li.LowPart = (unsigned int)(off & 0xffffffffu);
	li.HighPart = (int)((unsigned long long)off >> 32);

	/* PAGE_* from rwx bits (section views round to 64K — same as
	 * mmap MAP_FIXED semantics the kernel expects). */
	if (x)
		protect = 0x20;              /* PAGE_EXECUTE_READ */
	else if (w)
		protect = 0x04;              /* PAGE_READWRITE */
	else if (r)
		protect = 0x02;              /* PAGE_READONLY */
	else
		protect = 0x01;              /* PAGE_NOACCESS */

	s = nt->NtMapViewOfSection(uml_boot.physmem_section,
				   UML_NT_CURRENT_PROCESS, &base, 0, 0,
				   &li, &view, 1 /* ViewShare */,
				   0, protect);
	if (s < 0) {
		os_info("os_map_memory: map @%p+%lu failed %08x\n",
			virt, len, s);
		return -1;
	}
	if (base != virt) {
		/* The kernel picked this address; refuse drift. */
		os_info("os_map_memory: got %p want %p\n", base, virt);
		nt->NtUnmapViewOfSection(UML_NT_CURRENT_PROCESS, base);
		return -1;
	}
	return 0;
}

int os_protect_memory(void *addr, unsigned long len, int r, int w, int x)
{
	ULONG protect, old;
	PVOID base = addr;
	SIZE_T size = len;

	if (x)
		protect = 0x20;
	else if (w)
		protect = 0x04;
	else if (r)
		protect = 0x02;
	else
		protect = 0x01;

	return nt->NtProtectVirtualMemory(UML_NT_CURRENT_PROCESS, &base,
					  &size, protect, &old) < 0 ? -1 : 0;
}

int os_unmap_memory(void *addr, int len)
{
	return nt->NtUnmapViewOfSection(UML_NT_CURRENT_PROCESS, addr) < 0 ?
		-1 : 0;
}

int os_drop_memory(void *addr, int length)
{
	/* DiscardVirtualMemory semantics — used only by the balloon
	 * driver upstream; keep unreachable (M5+). */
	stub_panic("process.c: os_drop_memory");
	return -1;
}

int can_drop_memory(void)
{
	return 0;
}
