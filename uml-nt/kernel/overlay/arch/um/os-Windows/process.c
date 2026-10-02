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
#include <linux/errno.h>

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

/* R17 FIX (proposed — NOT landed; patch awaits Shelley's ruling):
 * per-page BITS replace the per-block counters. The counter design
 * undercounted by construction ("a repeated map of an
 * already-covered page saturates the counter") and its mirror
 * underflow wrapped 0 -> 255 — run 36997741821's ring caught
 * MEM_RELEASE firing at ledger-0 while pages d9000/da000/db000 of
 * block 0x680d0000 were still live (the timer-stack corruption
 * pair, run 36984931372's fetch fault). Bits are idempotent: a
 * repeated map SETS the same bit, the block releases only when
 * ALL its pages are clear — the undercount and the underflow both
 * vanish by construction. */
static unsigned char
priv_pages[UML_NT_PRIV_BLOCKS][UML_NT_PRIV_PAGES];

static int priv_page_idx(unsigned long long v)
{
	return (int)((v >> 12) & (UML_NT_PRIV_PAGES - 1));
}

static int priv_block_live(int bi)
{
	int p;

	for (p = 0; p < UML_NT_PRIV_PAGES; p++)
		if (priv_pages[bi][p])
			return 1;
	return 0;
}

static int priv_block_cnt(int bi)
{
	int p, n = 0;

	for (p = 0; p < UML_NT_PRIV_PAGES; p++)
		n += priv_pages[bi][p] != 0;
	return n;
}

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

/* R17 DIAG (vmalloc stale-PTE + timer text-fault pair, run
 * 36984931372): ring of ledger-window ops. The WARN
 * __vmap_pages_range_noflush !pte_none (mm/vmalloc.c:542) and the
 * timer c0000005 fetch-fault inside get_free_pages (console_
 * unlock path — printing the WARN itself) both beg the question
 * WHO last mapped/unmapped window VAs around the victims. Two
 * poison shapes live in os_unmap_memory (NO flat-view guard):
 * (a) a flat-view block (guest RAM / kernel text!) holding
 * priv_commits > 0 gets its pages MEM_DECOMMIT'd — the launcher's
 * own image page dies; (b) a flat-view VA with commits == 0 falls
 * to NtUnmapViewOfSection — which unmaps the ENTIRE 128M section
 * view. Neither may ever happen; the tripwires dump the ring when
 * they do, naming the previous window ops. */
#define UML_NT_VMR_RING_N 128
struct uml_nt_vmr_ent {
	unsigned long long v;
	unsigned long long len;
	unsigned char op;	/* 0 = map, 1 = unmap */
	unsigned char commits;	/* block ledger count after the op */
};
static struct uml_nt_vmr_ent vmr_ring[UML_NT_VMR_RING_N];
static unsigned int vmr_head;
static unsigned int vmr_count;

static void vmr_push(unsigned long long v, unsigned long long len,
		     int op, unsigned char commits)
{
	struct uml_nt_vmr_ent *e = &vmr_ring[vmr_head];

	e->v = v;
	e->len = len;
	e->op = (unsigned char)op;
	e->commits = commits;
	vmr_head = (vmr_head + 1) % UML_NT_VMR_RING_N;
	if (vmr_count < UML_NT_VMR_RING_N)
		vmr_count++;
}

void uml_nt_vmr_dump(const char *why, unsigned int n)
{
	unsigned int i, k;

	if (vmr_count == 0) {
		os_info("[vmr] %s: ring empty\n", why);
		return;
	}
	if (n > vmr_count)
		n = vmr_count;
	os_info("[vmr] %s: last %u of %u window ops\n", why, n,
		vmr_count);
	for (i = 0; i < n; i++) {
		k = (vmr_head + UML_NT_VMR_RING_N - 1 - i) %
		    UML_NT_VMR_RING_N;
		os_info("[vmr]   -%u: %s 0x%llx len=0x%llx commits=%u\n",
			i, vmr_ring[k].op == 0 ? "map" : "unmap",
			vmr_ring[k].v, vmr_ring[k].len,
			vmr_ring[k].commits);
	}
}

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

	/* PAGE_* from the rwx bits — for the LEDGER LOG only. The COMMIT
	 * is UNCONDITIONALLY RWX: these VAs are the kernel's own direct
	 * memory (the vmalloc band — no stub/guest isolation boundary
	 * exists above the section), and upstream's kern_map prot dance
	 * (tlb.c update_pte_range: !pte_young zeroes r+w, !pte_dirty
	 * zeroes w) is cosmetic for the guest-view sync — a clean pte
	 * (w=0) must NOT materialize as a read-only or no-access block
	 * or the kernel's next write to its own stack faults c0000005
	 * (run 36796131915: timer task, rip in uml_nt_switch_trace,
	 * write to its own band stack's next block). In the flat-alias
	 * era the prot never mattered: the section view underneath is
	 * RWX and the per-map calls were skipped entirely. */
	(void)r; (void)w; (void)x;
	protect = 0x40;              /* PAGE_EXECUTE_READWRITE */

	{
		unsigned long long end = (v + len + 0xFFFull) & ~0xFFFull;
		unsigned long long b = v & ~(UML_NT_PRIV_BLOCK_SIZE - 1);

		/* One ledger bit PER PAGE covered (the unmap path
		 * decommits and clears per page): two maps sharing a
		 * block keep the release until the last claim dies.
		 * A repeated map of an already-covered page re-sets
		 * the same bit — idempotent, no saturation, no
		 * undercount (the R17 fix; see the bitmap comment). */
		while (b < end) {
			unsigned long long b_end =
				b + UML_NT_PRIV_BLOCK_SIZE;
			unsigned long long p0 = (v > b) ? v : b;
			unsigned long long p1 = (end < b_end) ? end : b_end;
			int bi = priv_block_idx(b);
			unsigned int pp;
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
			for (pp = (unsigned int)((p0 - b) >> 12);
			     pp < (unsigned int)((p1 - b) >> 12);
			     pp++)
				priv_pages[bi][pp] = 1;
			/* 098 ζ: R17 escalation ledger — block 2048 is
			 * where the untracked-page guard keeps firing
			 * (0x6800f000, page 15). Trace every claim in
			 * this one block for the whole boot: the pair
			 * claim/refusal names the map that never
			 * claimed its last page. */
			if (bi == 2048)
				os_info("[r17-ledger] block 2048 claim "
					"va=0x%llx len=%llu pages "
					"[%u,%u)\n", v, len,
					(unsigned int)((p0 - b) >> 12),
					(unsigned int)((p1 - b) >> 12));
			b = b_end;
		}
	}
	{
		int bi0 = priv_block_idx(v);

		vmr_push(v, len, 0,
			 bi0 >= 0 ?
			 (unsigned char)priv_block_cnt(bi0) : 0);
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
	unsigned long long flat_end =
		(unsigned long long)(uintptr_t)uml_boot.physmem_base +
		uml_boot.physmem_size;
	int idx = priv_block_idx(v);
	int pi = priv_page_idx(v);

	(void)len; /* per-page decommit; len is a page here */

	/* R17 FIX (proposed — NOT landed; the DIAG tripwires this
	 * replaces fired log-only until Shelley ruled): the flat
	 * view is section-backed and PERMANENT (the map path
	 * short-circuits it). A private-ledger op on it is always a
	 * kernel bug: a set bit means MEM_DECOMMIT kills a RAM/text
	 * page of the launcher's own view (the timer fetch-fault
	 * class, run 36984931372), a clear bit means
	 * NtUnmapViewOfSection would drop the WHOLE 128M section
	 * view. Refuse loud instead. */
	if (v < flat_end && idx >= 0) {
		os_info("os_unmap_memory: FLAT-VIEW GUARD: unmap of "
			"section-backed VA 0x%llx refused "
			"(page bit=%d)\n", v, priv_pages[idx][pi]);
		uml_nt_vmr_dump("flat-view guard refused", 24);
		return -EINVAL;
	}

	/* Untracked page: the old path decommitted it anyway and
	 * wrapped the counter 0 -> 255 (the saturation undercount's
	 * mirror). With per-page bits, a clear bit means no live
	 * claim of ours — refusing is the only sound answer. */
	if (idx < 0 || priv_pages[idx][pi] == 0) {
		static int nuntracked_refused;

		nuntracked_refused++;
		os_info("os_unmap_memory: untracked page 0x%llx "
			"refused (idx=%d pi=%d refusal #%d)\n", v, idx,
			pi, nuntracked_refused);
		if (idx >= 0) {
			/* 097 γ': WHICH pages of this block are still
			 * claimed — a partially-claimed block here is
			 * the R17 hole's shape (some pages claimed by
			 * a dead region, their bits never cleared);
			 * a fully-clear block means the whole block's
			 * ledger was lost. The vmr dump names the last
			 * ops. */
			os_info("os_unmap_memory:   block %d bits "
				"%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d "
				"cnt=%d\n", idx, priv_pages[idx][0],
				priv_pages[idx][1], priv_pages[idx][2],
				priv_pages[idx][3], priv_pages[idx][4],
				priv_pages[idx][5], priv_pages[idx][6],
				priv_pages[idx][7], priv_pages[idx][8],
				priv_pages[idx][9], priv_pages[idx][10],
				priv_pages[idx][11], priv_pages[idx][12],
				priv_pages[idx][13], priv_pages[idx][14],
				priv_pages[idx][15],
				priv_block_cnt(idx));
		}
		uml_nt_vmr_dump("untracked-page guard refused", 24);
		return -EINVAL;
	}

	if (!nt->VirtualFree((PVOID)(uintptr_t)v, 0x1000,
			     0x00004000UL /* MEM_DECOMMIT */)) {
		os_info("os_unmap_memory: private decommit @%px "
			"failed\n", addr);
		uml_nt_vmr_dump("decommit failed", 24);
		return -1;
	}
	priv_pages[idx][pi] = 0;
	if (idx == 2048)
		os_info("[r17-ledger] block 2048 decommit va=0x%llx "
			"page %d\n", v, pi);
	vmr_push(v, 0x1000, 1, (unsigned char)priv_block_cnt(idx));
	if (!priv_block_live(idx) &&
	    !nt->VirtualFree((PVOID)(uintptr_t)va0, 0, MEM_RELEASE)) {
		os_info("os_unmap_memory: private release @%px "
			"failed\n", addr);
		uml_nt_vmr_dump("release failed", 24);
		return -1;
	}
	if (idx == 2048 && !priv_block_live(idx))
		os_info("[r17-ledger] block 2048 release (all pages "
			"gone)\n");
	return 0;
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
