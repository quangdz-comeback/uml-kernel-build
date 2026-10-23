// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/physbackend.c — kernel page allocator backend for
 * the guest run refcount layer (physalloc.h, D11/D12).
 *
 * Upstream analogue: none needed — upstream UML's guest pages come
 * from the same alloc_pages() as everything else (the kernel's
 * physical memory IS the UML process memory). The M3.3 bug was this
 * port handing guest runs out of a PRIVATE allocator over the section
 * while the kernel's buddy/slab owned the same pages: the guest wrote
 * into live SLUB/maple objects and the kernel died after the fork
 * probe (kmem_cache_alloc NULL-cache, mtree_load(sparse_irqs) garbage
 * node). Guest pages must BE kernel pages — hence alloc_pages and
 * nothing else.
 *
 * D12 (M3.4, spans): a multi-run VMA (ELF segment, stack) needs one
 * CONTIGUOUS block — a buddy block of order 4 + ceil(log2(nruns)) is
 * contiguous by construction, so the span backend just bumps the
 * order. Over-allocation (block bigger than the span) is accepted
 * fragmentation; the refcount layer tracks only the requested runs.
 *
 * The block's section offset = page_to_pfn(pg) << PAGE_SHIFT: the
 * section IS the kernel's physical memory (the direct map), so a
 * pfn-identity offset addresses it both in the kernel's flat view
 * (memcpy source/target) and in stub MapViewOfFileEx(map_off) calls.
 */
#include <linux/gfp.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <physalloc.h>
#include <runpool_model.h>

#define RUN_ORDER (UML_NT_PHYS_RUN_SHIFT - PAGE_SHIFT)

static void clear_zone_watermark_boost(void)
{
	struct zone *z;

	for_each_populated_zone(z)
		z->watermark_boost = 0;
}

/* M5.6a K8 [runpool]: the released-run cache. The guest's runs and
 * the kernel's own page cache share one zone; the exact span trim
 * returns unused tails at RUN_ORDER while the kernel scatters order-0
 * pages between the freed run blocks. Referees 39986204407/
 * 39986213745 died why='a' on a single-run COW with ~5 MiB free after
 * the 13 MiB hwdb.bin map had already failed order-4 handouts with
 * 20 MiB free. Keep up to 64 released runs (4 MiB) out of the buddy
 * and hand them back on the fault path; a buddy failure drains the
 * pool and retries, so nothing hides from the kernel. The pure half
 * (put/get/pop) is host-tested — tests/test_runpool.c. */
#define UML_NT_RUNPOOL_MAX_RUNS 0 /* A/B: pool off (Shelley 147.1) */
static struct uml_nt_runpool g_runpool;
static int g_runpool_ready;

static void runpool_init_once(void)
{
	if (!g_runpool_ready) {
		uml_nt_runpool_init(&g_runpool, UML_NT_RUNPOOL_MAX_RUNS,
				    UML_NT_RUNPOOL_ENTRIES);
		g_runpool_ready = 1;
	}
}

/* Hand every pooled span back to the buddy (the allocator's failure
 * path — the memory must be visible to the kernel again). */
static void runpool_drain(void)
{
	unsigned long long off;
	unsigned int nruns;
	int total = 0;

	while (uml_nt_runpool_pop(&g_runpool, &off, &nruns)) {
		struct page *pg = pfn_to_page(off >> PAGE_SHIFT);
		int r;

		for (r = 0; r < nruns; r++)
			__free_pages(pg + (r << RUN_ORDER), RUN_ORDER);
		total += nruns;
	}
	if (total) {
		clear_zone_watermark_boost();
		printk(KERN_INFO "[runpool] drained %d run(s) to the buddy "
		       "under alloc pressure\n", total);
	}
}

void uml_nt_runpool_stats(int *entries, int *runs)
{
	runpool_init_once();
	*entries = uml_nt_runpool_entries(&g_runpool);
	*runs = (int)uml_nt_runpool_runs(&g_runpool);
}

static int runs_order(int n)
{
	int k;

	for (k = 0; (1 << k) < n; k++)
		;
	return k;
}

long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	struct page *pg;
	int r_order = runs_order(nruns);
	int order = RUN_ORDER + r_order;
	int try;

	if (nruns < 1 || order > MAX_PAGE_ORDER)
		return -1;

	/* [runpool] first: a released span is contiguous, refcount-1
	 * backing — exactly what the buddy would have to reassemble
	 * from a fragmented free list. */
	runpool_init_once();
	{
		long long poff = uml_nt_runpool_get(&g_runpool,
						    (unsigned int)nruns);

		if (poff >= 0) {
			*page_out = pfn_to_page((unsigned long long)poff >>
						PAGE_SHIFT);
			return poff;
		}
	}

	/* D25 (Shelley 2026-10-03, to-shelley 134): the handout ASSERT.
	 * A block the buddy just handed must be a clean free block —
	 * a slab/reserved/still-buddy page here = the kernel's own
	 * memory double-booked into the guest run pool (the writer-2
	 * pool alias: task_structs living inside PID 1's heap runs,
	 * referee 37128298095's 452 copy_process+0x883 catches).
	 * Tainted blocks go straight back to the buddy (it hands a
	 * different block next); 16 strikes = the handout fails loud
	 * and the caller sees -ENOMEM instead of poisoned memory.
	 *
	 * __GFP_RETRY_MAYFAIL: every 64 KiB run has order >= 4 >
	 * PAGE_ALLOC_COSTLY_ORDER (3). Without __GFP_RETRY_MAYFAIL,
	 * __alloc_pages_slowpath (mm/page_alloc.c:4891) bails out to
	 * nopage after a single pass without retrying pagecache reclaim
	 * or compaction (referee H1 39898282926: order-8/9 failed with
	 * 16 MiB reclaimable file cache + 10 MiB order 4..7 free). */
	for (try = 0; try < 16; try++) {
		clear_zone_watermark_boost();
		pg = alloc_pages(GFP_KERNEL | __GFP_ZERO |
				 __GFP_RETRY_MAYFAIL | __GFP_NOWARN, order);
		clear_zone_watermark_boost();
		if (pg == NULL) {
			while (uml_nt_fcache_reclaim_one() > 0) {
				pg = alloc_pages(GFP_KERNEL | __GFP_ZERO |
						 __GFP_RETRY_MAYFAIL |
						 __GFP_NOWARN, order);
				clear_zone_watermark_boost();
				if (pg != NULL)
					break;
			}
			if (pg == NULL) {
				/* [runpool] the shared buddy is dry for this
				 * order — give the cached runs back and retry
				 * once before failing the fault (why='a'). */
				if (uml_nt_runpool_runs(&g_runpool) != 0) {
					runpool_drain();
					continue;
				}
				return -1;
			}
		}
		if (!PageSlab(pg) && !PageReserved(pg) &&
		    page_ref_count(pg) == 1) {
			if (r_order > 0) {
				int total_runs = 1 << r_order;
				int r;

				for (r = 1; r < total_runs; r++)
					set_page_count(pg + (r << RUN_ORDER), 1);
				for (r = nruns; r < total_runs; r++)
					__free_pages(pg + (r << RUN_ORDER),
						     RUN_ORDER);
			}
			*page_out = pg;
			return (long long)page_to_pfn(pg) << PAGE_SHIFT;
		}
		printk(KERN_WARNING
		       "[phys-handout] tainted block pfn=%lld flags=0x%lx "
		       "ref=%d — returned, retry %d\n",
		       (long long)page_to_pfn(pg), pg->flags,
		       (int)page_ref_count(pg), try);
		__free_pages(pg, order);
	}
	return -1;
}

void uml_nt_phys_backend_free(void *page, int nruns)
{
	struct page *pg = (struct page *)page;
	unsigned long long off;
	int r;

	if (pg == NULL || nruns <= 0)
		return;
	runpool_init_once();
	off = (unsigned long long)page_to_pfn(pg) << PAGE_SHIFT;
	if (uml_nt_runpool_put(&g_runpool, off, (unsigned int)nruns) == 0)
		return;
	for (r = 0; r < nruns; r++)
		__free_pages(pg + (r << RUN_ORDER), RUN_ORDER);
	clear_zone_watermark_boost();
}
