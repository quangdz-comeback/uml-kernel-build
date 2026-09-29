// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/physbackend.c — kernel page allocator backend for
 * the guest run refcount layer (physalloc.h, D11).
 *
 * Upstream analogue: none needed — upstream UML's guest pages come
 * from the same alloc_pages() as everything else (the kernel's
 * physical memory IS the UML process memory). The M3.3 bug was this
 * port handing guest runs out of a PRIVATE allocator over the section
 * while the kernel's buddy/slab owned the same pages: the guest wrote
 * into live SLUB/maple objects and the kernel died after the fork
 * probe (kmem_cache_alloc NULL-cache, mtree_load(sparse_irqs) garbage
 * node). Guest pages must BE kernel pages — hence alloc_pages(order
 * 4) and nothing else.
 *
 * The run's section offset = page_to_pfn(pg) << PAGE_SHIFT: the
 * section IS the kernel's physical memory (the direct map), so a
 * pfn-identity offset addresses it both in the kernel's flat view
 * (memcpy source/target) and in stub MapViewOfFileEx(map_off) calls.
 */
#include <linux/gfp.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <physalloc.h>

#define RUN_ORDER (UML_NT_PHYS_RUN_SHIFT - PAGE_SHIFT)

long long uml_nt_phys_backend_alloc(void **page_out)
{
	struct page *pg;

	pg = alloc_pages(GFP_KERNEL | __GFP_ZERO, RUN_ORDER);
	if (pg == NULL)
		return -1;
	*page_out = pg;
	return (long long)page_to_pfn(pg) << PAGE_SHIFT;
}

void uml_nt_phys_backend_free(void *page)
{
	__free_pages((struct page *)page, RUN_ORDER);
}
