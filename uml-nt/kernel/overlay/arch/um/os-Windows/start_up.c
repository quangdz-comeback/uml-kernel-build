// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/start_up.c — pre-kernel start helpers.
 * Upstream: linux v6.18.37 arch/um/os-Linux/start_up.c
 *
 * Most of start_up.c upstream is ptrace/skas setup (D6: not on NT).
 * What remains for M1: cpu-feature feeding for the boot arch code,
 * boot-time checks (no-ops on NT), and the D9 table self-check.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/vmalloc.h>
#include <ntabi.h>
#include <stub-panic.h>

#include <os.h>
#include "internal.h"

void os_early_checks(void)
{
	/* upstream: /tmp exec + tmpfs probes — nothing applies on NT */
}

void os_check_bugs(void)
{
	/* upstream /proc/cpuinfo sanity — nothing to check on NT */
}

void get_host_cpu_features(void (*flags_helper_func)(char *line),
			   void (*cache_helper_func)(char *line))
{
	/* Upstream feeds /proc/cpuinfo lines. NT: synthesize the one
	 * line the guest arch code needs (FPU flag so boot settles). */
	flags_helper_func("flags\t\t: fpu");
	cache_helper_func("cache_alignment\t: 64");
}

int __init parse_iomem(char *str, int *add)
{
	/* /proc/iomem doesn't exist on NT; no host iomem map for M1. */
	os_warn("parse_iomem: no host iomem on NT — ignored\n");
	return 0;
}

int uml_nt_check_api_table(void)
{
	/* Launcher must have handed a compatible table (D9). Checked in
	 * nt_main already; a second explicit check keeps os-layer code
	 * able to rely on `nt` unconditionally. */
	if (nt == NULL)
		return -1;
	if (nt->version != UML_NT_API_VERSION)
		return -1;
	if (nt->size < sizeof(struct uml_nt_api_table))
		return -1;
	return 0;
}

/* ---- M3.8: kernel-process crash reporter ----------------------------- *
 * Upstream parity: UML's kernel process installs a SIGSEGV handler
 * that panics loudly on kernel faults (arch/um/kernel/trap.c + the
 * os-Linux signal layer). On NT nothing caught a wild kernel-side
 * deref: the process died STATUS_ACCESS_VIOLATION and the CI shell
 * reported a bare "exit 139" — no location, no address (the busybox
 * S4c2 window). VEH fires before any debugger/wer machinery; the
 * handler must assume the world is broken:
 *   - write DIRECTLY via NtWriteFile on boot.stdio_out, bypassing
 *     nt_console_write's spinlock (the crashing thread may hold it);
 *   - then terminate exit 1 (os_dump_core parity) — never resume
 *     into a corrupted kernel.
 * Every exception in the kernel process is fatal-by-definition
 * (nothing here raises/handles exceptions legitimately — S1 kept
 * VEH strictly in the stub process). */

static void uml_nt_crash_write(const char *s, unsigned int n)
{
	IO_STATUS_BLOCK iosb;

	if (nt == NULL || uml_boot.stdio_out == NULL || n == 0)
		return;
	nt->NtWriteFile(uml_boot.stdio_out, NULL, NULL, NULL, &iosb,
			(void *)s, n, NULL, NULL);
}

/* Heuristic stack scan (the dump_trace recipe): walk [rsp, rsp+16K),
 * print every value that lands in the kernel image VA range — the
 * survivors near the top are the call chain. The reporter must not
 * assume WHICH thread faulted (dispatch vs timer host thread have
 * different stacks — rsp tells, the text hits tell why). VirtualQuery
 * first: a guard/reserved page in the scan window must skip, not
 * re-fault. */
#define UML_NT_PAGE_GUARD 0x100UL

static int uml_nt_page_readable(unsigned long long va)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (nt->VirtualQuery((PVOID)(ULONG_PTR)va, &mbi, sizeof(mbi)) !=
	    sizeof(mbi))
		return 0;
	return mbi.State == MEM_COMMIT &&
	       mbi.Protect != PAGE_NOACCESS &&
	       !(mbi.Protect & UML_NT_PAGE_GUARD);
}

static void uml_nt_crash_scan_stack(unsigned long long rsp)
{
	unsigned long long va, pg = -1;
	int n = 0;
	char buf[96];

	/* RAW window first (M5.1c.3 diagnosis): the smash pattern itself
	 * (runs of -1, heap pointers, repeated values) names the writer
	 * even when no text address survives. M5.1c.4: start BELOW rsp
	 * too — a faulted/completed retq's return-address slot sits at
	 * [rsp-8] (the pop moved rsp past it); without this the slot
	 * that named the crash was never dumped. */
	{
		char line[128];
		unsigned long long lo = rsp >= 0x200 ? rsp - 0x200 : 0;

		/* M5.1c.5: the whole 0x400 window (128 qwords) — the
		 * smash ran to the stack TOP (rsp+0x150), past the old
		 * 72-qword cap. */
		for (va = lo & ~(unsigned long long)7, n = 0;
		     n < 128 && va < rsp + 0x200; va += 8, n++) {
			int m;

			if ((va & ~0xfffULL) != pg) {
				pg = va & ~0xfffULL;
				if (!uml_nt_page_readable(pg))
					break;
			}
			m = snprintf(line, sizeof(line),
				     "  raw %llx: %llx\n", va,
				     *(unsigned long long *)va);
			if (m > 0)
				uml_nt_crash_write(line, (unsigned int)m);
		}
	}

	for (va = rsp & ~(unsigned long long)7, n = 0;
	     n < 12 && va < rsp + 0x4000; va += 8) {
		unsigned long long v;

		if ((va & ~0xfffULL) != pg) {
			pg = va & ~0xfffULL;
			if (!uml_nt_page_readable(pg))
				break;
		}
		v = *(unsigned long long *)va;
		/* kernel image text/rodata zone (image < 8 MiB at
		 * UML base + entry 0x60001000) — text hits only */
		if (v < 0x60001000ull || v >= 0x60400000ull)
			continue;
		n++;
		{
			int m = snprintf(buf, sizeof(buf),
					 "  stack %llx: %llx\n",
					 va, v);

			if (m > 0)
				uml_nt_crash_write(buf, (unsigned int)m);
		}
	}
}

static volatile int in_crash_report;

/* Which kernel thread is running — set at each aux thread's entry,
 * read by the crash reporter (rsp alone can't name the thread). */
const char *uml_nt_thread_role = "boot/vcpu";

/* x64: gs:[0x30] = TEB; TEB+0x40 = ClientId {pid, tid}. The guest
 * only ever re-bases FS (arch_prctl SET_FS is the recorded syscall);
 * GS stays the host's, so this reads the true Windows tid even from
 * a vCPU mid-syscall. */
static unsigned long long uml_nt_current_tid(void)
{
	unsigned long long teb;

	__asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
	return *(unsigned long long *)(teb + 0x40 + 8);
}

static LONG __attribute__((ms_abi)) uml_nt_crash_report(void *ep)
{
	const struct uml_nt_exception_pointers *e = ep;
	const struct uml_nt_exception_record *r =
		(e != NULL) ? e->record : NULL;
	unsigned long long rip = (e != NULL && e->context != NULL) ?
				 UML_NT_X64_CTX_RIP(e->context) : 0;
	char buf[224];
	int n;

	/* A fault inside this handler (dead console handle, trashed
	 * stack) must terminate, never recurse. */
	if (in_crash_report) {
		if (nt != NULL)
			nt->NtTerminateProcess(UML_NT_CURRENT_PROCESS, 1);
		for (;;)
			asm volatile("");
	}

	/* The M5.1c.5 "forgiving guard-hit" path is GONE with its only
	 * producer: the switch-guard tripwire (uml_nt_switch_trace)
	 * that left stack-tail pages read-only. Its VA gate
	 * [0x64000000, 0x68000000) was the mem=64M-era band anyway —
	 * with the launcher's band reserve at [0x68000000, 0x78000000)
	 * it could no longer see what it was built for. Every write
	 * fault now takes the fatal report below, which prints the
	 * same forensic data without unprotecting anything. */

	in_crash_report = 1;

	n = snprintf(buf, sizeof(buf),
		     "\numl-nt: KERNEL NATIVE FAULT code=%08x rip=%llx "
		     "rsp=%llx op=%d info1=%llx exaddr=%llx tid=%llu — "
		     "terminating\n",
		     r != NULL ? (unsigned int)r->code : 0, rip,
		     (e != NULL && e->context != NULL) ?
			     UML_NT_X64_CTX_RSP(e->context) : 0,
		     (r != NULL && r->nparams > 1) ?
			     (int)r->info[0] : -1,
		     (r != NULL && r->nparams > 1) ? r->info[1] : 0,
		     (r != NULL) ? (unsigned long long)(uintptr_t)
				     r->address : 0,
		     uml_nt_current_tid());
	if (n > 0)
		uml_nt_crash_write(buf, (unsigned int)n);
	/* Page-offset anchors: uml_physmem IS page_offset/PAGE_OFFSET —
	 * if it got trashed, every virt_to_page/kmem_cache_free faults
	 * far from the write that trashed it. Print them so a
	 * corruption signature is readable from the log alone
	 * (expected: physmem 0x60000000, high = physmem + mem= size). */
	{
		extern unsigned long uml_physmem;
		extern unsigned long high_physmem;
		extern unsigned long long physmem_size;

		n = snprintf(buf, sizeof(buf),
			     "  physmem=%llx high=%llx size=%llx\n",
			     (unsigned long long)uml_physmem,
			     (unsigned long long)high_physmem,
			     physmem_size);
		if (n > 0)
			uml_nt_crash_write(buf, (unsigned int)n);
	}
	if (e != NULL && e->context != NULL) {
		unsigned long long teb, base, limit;
		unsigned long long frsp = UML_NT_X64_CTX_RSP(e->context);

		__asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
		base = *(unsigned long long *)(teb + 0x08);
		limit = *(unsigned long long *)(teb + 0x10);
		n = snprintf(buf, sizeof(buf),
			     "  rax=%llx rcx=%llx rdx=%llx rsi=%llx "
			     "rdi=%llx tid=%llu thread=%s stackbase=%llx "
			     "stacklimit=%llx inbounds=%d\n",
			     UML_NT_X64_CTX_RAX(e->context),
			     UML_NT_X64_CTX_RCX(e->context),
			     UML_NT_X64_CTX_RDX(e->context),
			     UML_NT_X64_CTX_RSI(e->context),
			     UML_NT_X64_CTX_RDI(e->context),
			     uml_nt_current_tid(),
			     uml_nt_thread_role, base, limit,
			     frsp <= base && frsp >= limit);
		if (n > 0)
			uml_nt_crash_write(buf, (unsigned int)n);
		uml_nt_crash_scan_stack(frsp);
	}
	/* M5.1c.4: WHO was running + the switch chain that led here.
	 * The TEB bounds above are NOT the kernel's truth (kernel
	 * contexts run on vmalloc'd task stacks — inbounds=0 is
	 * normal); the task identity + the last 32 switches are.
	 * M5.1c.5: the smash window (task 21's stack top ~0x360 bytes
	 * of 0/1 boolean bytes over the caller chain) vs the vmalloc
	 * area map — find_vm_area on the stack and on the smash
	 * window's edges aliases any object that owns those pages
	 * (a freed-and-reallocated stack, an overlapping net-ring or
	 * flat view), which is the root-cause class to name. */
	{
		const struct uml_nt_switch_rec *ring;
		unsigned long long have, i, frsp;
		struct task_struct *t = current;
		struct vm_struct *va;

		frsp = (e != NULL && e->context != NULL) ?
			       UML_NT_X64_CTX_RSP(e->context) :
			       (unsigned long long)(uintptr_t)task_stack_page(t);
		n = snprintf(buf, sizeof(buf),
			     "  task=%d stack=%px state=%ld\n",
			     t->pid, task_stack_page(t),
			     (long)t->__state);
		if (n > 0)
			uml_nt_crash_write(buf, (unsigned int)n);

		/* The stack's own vmalloc area + whatever owns the
		 * smash window's edges. */
		va = find_vm_area(task_stack_page(t));
		n = snprintf(buf, sizeof(buf),
			     "  vmalloc stack: %px size=%lx\n",
			     va != NULL ? va->addr : NULL,
			     va != NULL ? va->size : 0UL);
		if (n > 0)
			uml_nt_crash_write(buf, (unsigned int)n);
		va = find_vm_area((void *)(unsigned long)
				  ((frsp & ~(unsigned long long)7) - 0x8));
		n = snprintf(buf, sizeof(buf),
			     "  vmalloc rsp: %px size=%lx\n",
			     va != NULL ? va->addr : NULL,
			     va != NULL ? va->size : 0UL);
		if (n > 0)
			uml_nt_crash_write(buf, (unsigned int)n);

		{
			unsigned long long raddr, rhead, rtail;

			uml_nt_net_ring_info(&raddr, &rhead, &rtail);
			va = (raddr != 0) ? find_vm_area(
				(void *)(uintptr_t)raddr) : NULL;
			n = snprintf(buf, sizeof(buf),
				     "  net ring: %llx head=%llu tail=%llu "
				     "varea=%px size=%lx\n",
				     raddr, rhead, rtail,
				     va != NULL ? va->addr : NULL,
				     va != NULL ? va->size : 0UL);
			if (n > 0)
				uml_nt_crash_write(buf, (unsigned int)n);
		}

		/* Pending kernel PTE syncs (M5.1c.5): the port never
		 * syncs init_mm's marked range (vmalloc VAs run on the
		 * launcher's section identity bytes instead of their
		 * backing pages). Print how much the kernel thinks is
		 * still owed. */
		{
			extern struct task_struct init_task;

			n = snprintf(buf, sizeof(buf),
				     "  init_mm pending sync: from=%llx "
				     "to=%llx\n",
				     init_task.mm ?
				     (unsigned long long)init_task.mm->
				     context.sync_tlb_range_from : 0,
				     init_task.mm ?
				     (unsigned long long)init_task.mm->
				     context.sync_tlb_range_to : 0);
			if (n > 0)
				uml_nt_crash_write(buf, (unsigned int)n);
		}

		have = uml_nt_switch_ring(&ring);
		for (i = 0; i < have && i < UML_NT_SWITCH_RING; i++) {
			unsigned long long idx =
				(have <= UML_NT_SWITCH_RING) ?
					i :
					(have - UML_NT_SWITCH_RING + i) %
					UML_NT_SWITCH_RING;

			n = snprintf(buf, sizeof(buf),
				     "  sw[%llu] %llu -> %llu state=%llu "
				     "stack=%llx\n",
				     i, ring[idx].from_pid,
				     ring[idx].to_pid,
				     ring[idx].to_state,
				     ring[idx].to_stack);
			if (n > 0)
				uml_nt_crash_write(buf, (unsigned int)n);
		}

		/* The smash-writer hunt: resolve each page of the
		 * faulting task's stack to its section offset and ask
		 * the guest mms whether a VMA is backed by it — the
		 * flat view gives every section offset a permanent
		 * kernel-side identity, so a guest VMA over the same
		 * run = the same bytes under two owners (any guest
		 * write = a kernel-stack write). Runs after the ring
		 * dump: it uses os_info (console path) — if the fault
		 * happened inside console code this stalls instead of
		 * corrupting the report above. */
		{
			unsigned char *sp = task_stack_page(t);
			int pi;

			for (pi = 0; pi < THREAD_SIZE / PAGE_SIZE; pi++) {
				struct page *pg =
					vmalloc_to_page(sp +
							pi * PAGE_SIZE);
				unsigned long long off;

				if (pg == NULL)
					continue;
				off = (unsigned long long)
					page_to_pfn(pg) << PAGE_SHIFT;
				uml_nt_alias_scan(off, off + PAGE_SIZE);
			}
		}
	}
	if (nt != NULL)
		nt->NtTerminateProcess(UML_NT_CURRENT_PROCESS, 1);
	for (;;)
		asm volatile("");
	/* Unreachable at runtime (the loop above spins forever), but
	 * -ffinite-loops (GCC 13+) models the empty loop as exiting —
	 * the compiler wants the return, so it gets one. 0L = the
	 * EXCEPTION_CONTINUE_SEARCH disposition (ntabi.h keeps no
	 * winnt.h names). */
	return 0L;
}

void uml_nt_install_crash_reporter(void)
{
	/* FIRST handler: the reporter must see the exception before
	 * anything else could swallow it. A non-AV kill (terminate from
	 * outside) does not go through VEH — the process just exits. */
	if (nt->AddVectoredExceptionHandler(1,
			(PVOID)uml_nt_crash_report) == NULL)
		os_warn("crash reporter: VEH install failed win32=%u\n",
			nt->RtlGetLastWin32Error());
}

/* Kernel glue data (declared extern by kernel sources):
 * no seccomp on NT (D6); no auxv hwcap on NT (no ELF loader). */
int using_seccomp;
long elf_aux_hwcap;
