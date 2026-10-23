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

#define RUN_ORDER (UML_NT_PHYS_RUN_SHIFT - PAGE_SHIFT)

static int runs_order(int n)
{
	int k;

	for (k = 0; (1 << k) < n; k++)
		;
	return k;
}

static void clear_zone_watermark_boost(void)
{
	struct zone *z;

	for_each_populated_zone(z)
		z->watermark_boost = 0;
}

long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	struct page *pg;
	int r_order = runs_order(nruns);
	int order = RUN_ORDER + r_order;
	int try;

	if (nruns < 1 || order > MAX_PAGE_ORDER)
		return -1;

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
		if (pg == NULL)
			return -1;
		if (!PageSlab(pg) && !PageReserved(pg) &&
		    page_ref_count(pg) == 1) {
			if ((1 << r_order) > nruns) {
				int want_pages = nruns << RUN_ORDER;
				int total_pages = 1 << order;
				int i;

				split_page(pg, order);
				for (i = want_pages; i < total_pages; i++)
					__free_pages(pg + i, 0);
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
	int r_order = runs_order(nruns);

	if ((1 << r_order) == nruns) {
		__free_pages(pg, RUN_ORDER + r_order);
	} else {
		int want_pages = nruns << RUN_ORDER;
		int i;

		for (i = 0; i < want_pages; i++)
			__free_pages(pg + i, 0);
	}
	clear_zone_watermark_boost();
}
