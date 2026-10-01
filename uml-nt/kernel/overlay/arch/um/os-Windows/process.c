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

#include <physalloc.h>
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

/* Private backing ledger for kernel VAs BEYOND the flat guest-RAM
 * view (the vmalloc band: task stacks, vmap'd kernel objects).
 *
 * Why not NtMapViewOfSection there: NT section views are 64K-granular
 * in BOTH the view offset and the base VA and preserve byte position
 * — a section byte at offset `off` can only appear at a VA `v` with
 * v ≡ off (mod 64K). The kernel's out-of-RAM maps are per-PAGE
 * (kern_map per pte: offset = pfn<<12, order-0 allocations), so the
 * congruence generally fails and the map dies with
 * STATUS_MAPPED_ALIGNMENT (c0000220 — run 36791266017, mem=120M:
 * "real map @0x68000000 off=0x834000"; 0x834000 is 4K-aligned only).
 * The vmalloc base is NOT section-derived (that hypothesis was
 * wrong): upstream VMALLOC_START = end_iomem + VMALLOC_OFFSET, i.e.
 * mem-end + 8MiB — 0x67800000 + 8M = 0x68000000, exactly the failing
 * map. The map is upstream-correct; the BACKING mechanics were the
 * bug.
 *
 * Private blocks honor the contract that matters: the kernel owns
 * these VAs exclusively (no stub/guest aliasing exists at
 * VAs >= base + section), and vmalloc pages are __GFP_ZERO'd right
 * after the map — no section content ever flows in. The flat-alias
 * era proves content identity is irrelevant there: the band silently
 * aliased the WRONG section offsets (VA 0x65000000 ↔ section byte
 * 80MiB, not the page's own offset) for every boot and worked.
 *
 * Ledger: one commit count per 64K block over [base, base+512MiB) —
 * the launcher reserves the kernel's out-of-RAM band
 * ([base+section, +256MiB), see below) so nothing else claims it;
 * the ledger window must contain the band for any mem=. Commits are
 * MEM_COMMIT-only sub-ranges of that reservation (the documented
 * reserve-then-commit pair; run 36795717610: re-passing MEM_RESERVE
 * into the reservation itself died 487).
 * Consecutive order-0 pages share a block (idempotent re-commit);
 * per-page unmaps decommit, and the block releases only at zero —
 * two vmalloc areas can share one 64K block (the 4K inter-area hole
 * is smaller than 64K). Unpaired maps saturate instead of wrapping
 * (a stale block stays reserved — address space only, no charge). */
#define UML_NT_PRIV_BLOCK_SHIFT 16
#define UML_NT_PRIV_BLOCK_SIZE  (1ull << UML_NT_PRIV_BLOCK_SHIFT)
#define UML_NT_PRIV_BLOCKS      8192 /* 512 MiB window [base, base+512M) —
	* the launcher reserves the band [base+section, base+section+256M)
	* (2GiB-line bound), the ledger window must contain it for ANY
	* mem= up to the ceiling */
#define UML_NT_PRIV_PAGES       16   /* 64K / 4K */

static unsigned char priv_commits[UML_NT_PRIV_BLOCKS];

static int priv_block_idx(unsigned long long v)
{
	long long delta = (long long)(v - UML_NT_GUEST_VA_BASE);

	if (delta < 0 || (delta >> UML_NT_PRIV_BLOCK_SHIFT) >=
				 UML_NT_PRIV_BLOCKS)
		return -1;
	return (int)(delta >> UML_NT_PRIV_BLOCK_SHIFT);
}

/* One line per boot names the first crossing — the per-map ledger
 * noise would flood the boot log (one map per vmalloc page; every
 * task stack). */
static int priv_logged;

int os_map_memory(void *virt, int fd, unsigned long long off,
		  unsigned long len, int r, int w, int x)
{
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

	/* Beyond the flat view: private backing (see the ledger comment
	 * above). */
	if (!priv_logged) {
		priv_logged = 1;
		os_info("os_map_memory: first real map @%px+%#lx "
			"off=%llx prot=%d%d%d -> private block "
			"(section view impossible: v %% 64K != off %% 64K; "
			"content is __GFP_ZERO, not section bytes)\n",
			virt, (unsigned long)len, off, r != 0, w != 0,
			x != 0);
	}

	/* PAGE_* from rwx bits — every rwx combination is a valid NT
	 * protection (same table the section path used). */
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

	{
		unsigned long long end = (v + len + 0xFFFull) & ~0xFFFull;
		unsigned long long b = v & ~(UML_NT_PRIV_BLOCK_SIZE - 1);

		/* One ledger unit PER PAGE covered (the unmap path
		 * decommits and decrements per page): two maps sharing
		 * a block keep the release until the last claim dies.
		 * A repeated map of an already-covered page saturates
		 * the counter instead of wrapping — the block then
		 * releases late (address space only), never early. */
		while (b < end) {
			unsigned long long b_end =
				b + UML_NT_PRIV_BLOCK_SIZE;
			unsigned long long p0 = (v > b) ? v : b;
			unsigned long long p1 = (end < b_end) ? end : b_end;
			int n_pages = (int)((p1 - p0 + 0xFFFull) >> 12);
			int bi = priv_block_idx(b);
			PVOID got;

			if (bi < 0) {
				os_info("os_map_memory: private block "
					"out of ledger window @%px\n",
					virt);
				return -1;
			}
			got = nt->VirtualAlloc((PVOID)(uintptr_t)b,
					       UML_NT_PRIV_BLOCK_SIZE,
					       MEM_COMMIT,
					       protect);
			if (got == NULL) {
				MEMORY_BASIC_INFORMATION mbi;
				SIZE_T q = nt->VirtualQuery(
					(PVOID)(uintptr_t)b, &mbi,
					sizeof(mbi));

				os_info("os_map_memory: private block "
					"@%px failed win32=%lu "
					"(region: base=%px size=%#lx "
					"state=%#lx protect=%#lx "
					"type=%lx q=%lu)\n",
					(void *)(uintptr_t)b,
					(unsigned long)nt->RtlGetLastWin32Error(),
					mbi.BaseAddress,
					(unsigned long)mbi.RegionSize,
					(unsigned long)mbi.State,
					(unsigned long)mbi.Protect,
					(unsigned long)mbi.Type,
					(unsigned long)q);
				return -1;
			}
			if (priv_commits[bi] + n_pages >
			    UML_NT_PRIV_PAGES)
				n_pages = UML_NT_PRIV_PAGES -
					  priv_commits[bi];
			if (n_pages > 0)
				priv_commits[bi] +=
					(unsigned char)n_pages;
			b = b_end;
		}
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
	unsigned long long v = (unsigned long long)(uintptr_t)addr;
	unsigned long long va0 = v & ~(UML_NT_PRIV_BLOCK_SIZE - 1);
	int idx = priv_block_idx(v);

	/* Private-backed range (see the ledger comment in os_map_
	 * memory): decommit the pages — NtUnmapViewOfSection cannot
	 * undo a VirtualAlloc. The block releases only when its last
	 * committed page goes (two vmalloc areas may share it). */
	if (idx >= 0 && priv_commits[idx] > 0) {
		BOOLEAN ok;

		(void)len; /* per-page decommit; len is a page here */
		ok = nt->VirtualFree((PVOID)(uintptr_t)v, 0x1000,
				     0x00004000UL /* MEM_DECOMMIT */);
		if (!ok) {
			os_info("os_unmap_memory: private decommit "
				"@%px failed\n", addr);
			return -1;
		}
		if (priv_commits[idx] < 0xff)
			priv_commits[idx]--;
		if (priv_commits[idx] == 0 &&
		    !nt->VirtualFree((PVOID)(uintptr_t)va0, 0,
				     MEM_RELEASE)) {
			os_info("os_unmap_memory: private release "
				"@%px failed\n", addr);
			return -1;
		}
		return 0;
	}

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
