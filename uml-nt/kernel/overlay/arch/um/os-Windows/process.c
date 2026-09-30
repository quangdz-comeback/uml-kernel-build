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
	/* Upstream: kill(pid, SIGALRM) — interrupt the guest process so
	 * it traps back into the kernel (the tick's event_handler, the
	 * line AFTER this call upstream, still runs either way). The
	 * NT stub has no preempt-interrupt channel yet: injecting a
	 * trap into running guest code is the M4 signals work. The
	 * honest interim behavior is a NO-OP: the tick IRQ flag is set
	 * and the kernel sees it at the guest's NEXT trap (a sys-
	 * call/fault round-trip), which is exactly the time-travel
	 * "do not notify" mode upstream already tolerates. LOUD ONCE —
	 * this PANIC'd (parking the timer thread) the first S3 boot:
	 * current->mm exists from exec_mmap on, so every tick after
	 * exec landed here. Never park a host thread. */
	static int warned;

	if (!warned) {
		warned = 1;
		os_info("os_alarm_process: guest tick-interrupt not "
			"implemented (M4) — tick lands at next trap\n");
	}
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
	unsigned long long v = (unsigned long long)(uintptr_t)virt;

	if (fd != UML_NT_MEMFD_PHYS) {
		os_info("os_map_memory: unknown fd %d\n", fd);
		return -1;
	}

	/* Guest RAM = ONE launcher-mapped view at boot.physmem_base
	 * covering [base, base+physmem_size) — the memfd analogue. Every
	 * guest-phys VA is already resident (upstream map_memory re-maps
	 * the memfd over these VAs; on NT the view is already there).
	 * Out-of-range requests have no backing until M2 (stub areas). */
	if (v >= (unsigned long long)(uintptr_t)uml_boot.physmem_base &&
	    v + len <= (unsigned long long)(uintptr_t)uml_boot.physmem_base +
		       uml_boot.physmem_size)
		return 0;

	/* M5.1c.5: the REAL-map ledger — every map outside the flat
	 * guest RAM view (kernel vmalloc objects: task stacks, the
	 * net ring's neighbors). The out-of-range map = the alias
	 * surface: a section view at a second VA over bytes the flat
	 * view also exposes. If the net gate's stack smash returns,
	 * this names every stack map + its backing offset as it
	 * happens. */
	os_info("os_map_memory: real map @%px+%#lx off=%llx prot=%d%d%d\n",
		virt, (unsigned long)len, off, r != 0, w != 0, x != 0);

	base = (PVOID)v;
	view = 0;
	li.LowPart = (unsigned int)(off & 0xffffffffu);
	li.HighPart = (int)((unsigned long long)off >> 32);

	/* PAGE_* from rwx bits (section views round to 64K — same as
	 * mmap MAP_FIXED semantics the kernel expects). Guest RAM maps
	 * RWX (guest code lives in it); every rwx combination below is
	 * a valid NT protection. */
	if (r && w && x)
		protect = 0x40;              /* PAGE_EXECUTE_READWRITE */
	else if (r && x)
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
		os_info("os_map_memory: map @%px+%lu failed %08x\n",
			virt, len, s);
		return -1;
	}
	if (base != (PVOID)v) {
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
