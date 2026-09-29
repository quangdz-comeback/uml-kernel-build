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

long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	struct page *pg;
	int order = RUN_ORDER + runs_order(nruns);

	pg = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (pg == NULL)
		return -1;
	*page_out = pg;
	return (long long)page_to_pfn(pg) << PAGE_SHIFT;
}

void uml_nt_phys_backend_free(void *page, int nruns)
{
	__free_pages((struct page *)page, RUN_ORDER + runs_order(nruns));
}
