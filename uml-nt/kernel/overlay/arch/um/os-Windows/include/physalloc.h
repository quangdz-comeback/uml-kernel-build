/* SPDX-License-Identifier: GPL-2.0 */
/*
 * physalloc.h — guest physical run REFCOUNT layer (M3.2, backend M3.3).
 *
 * Upstream analogue: guest user pages come from the kernel page
 * allocator (alloc_pages) — upstream UML's "physical memory" IS the
 * kernel's own memory. On NT the same holds: the whole guest physmem
 * is ONE pagefile-backed section whose pages the kernel buddy manages
 * past the loaded image (min_low_pfn excludes the head). The M3.3
 * lesson (D11): a PRIVATE allocator over the section double-allocated
 * against the kernel's buddy/slab — guest writes to "its" runs trashed
 * live SLUB/maple data and the kernel died after the fork probe. So
 * the run allocator is now a thin REFCOUNT layer over the page
 * allocator backend (skas/physbackend.c kernel-side, mocked in unit
 * tests): alloc = alloc_pages(order 4 = 64 KiB — MapViewOfFile offset
 * granularity), unref-to-zero = __free_pages. Run offsets are DYNAMIC
 * (pfn << PAGE_SHIFT) — nothing may assume a fixed layout above the
 * image.
 *
 * The stub still maps per-VMA VIEWS of the section at run offsets:
 * a VMA's backing must be CONTIGUOUS runs (one MapViewOfFileEx covers
 * it). Single-run VMAs are trivially contiguous; multi-run spans need
 * a contiguous backend allocation (open design point, M4).
 *
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI
 * (the backend is mocked).
 */
#ifndef __UM_OS_WINDOWS_PHYSALLOC_H
#define __UM_OS_WINDOWS_PHYSALLOC_H

#define UML_NT_PHYS_RUN_SHIFT  16ull /* 64 KiB — MapViewOfFile offset granularity */
#define UML_NT_PHYS_RUN_SIZE   (1ull << UML_NT_PHYS_RUN_SHIFT)
#define UML_NT_PHYS_MAX_RUNS   4096  /* 4096 * 64K = 256 MiB POC ceiling */

struct uml_nt_phys {
	unsigned long long size;      /* section bytes (rounded to runs) */
	unsigned short refs[UML_NT_PHYS_MAX_RUNS]; /* 0 = run not in use */
	void *pages[UML_NT_PHYS_MAX_RUNS]; /* backend page handle per run */
};

/* Initialize the refcount layer over a section of `size` bytes.
 * Returns 0, or -1 if size exceeds UML_NT_PHYS_MAX_RUNS runs. */
int uml_nt_phys_init(struct uml_nt_phys *p, unsigned long long size);

/* Backend hooks (skas/physbackend.c kernel-side, mocked in tests):
 * hand out one 64 KiB run from the kernel page allocator — returns
 * the section offset (64K-aligned) or -1; *page_out receives the
 * opaque handle for the matching free. */
long long uml_nt_phys_backend_alloc(void **page_out);
void uml_nt_phys_backend_free(void *page);

/* Allocate one run: section offset in bytes, or -1 when the backend
 * is exhausted. The run enters with refcount 1. */
long long uml_nt_phys_alloc(struct uml_nt_phys *p);

/* refcount helpers. unref returns the refcount AFTER the drop; when
 * it reaches 0 the backend frees the run's pages (the content was
 * copied out before the drop — the COW copy is kernel-side memcpy
 * through the flat view). -1 on bad offsets. */
int uml_nt_phys_ref(struct uml_nt_phys *p, long long off);
int uml_nt_phys_unref(struct uml_nt_phys *p, long long off);
int uml_nt_phys_refs(struct uml_nt_phys *p, long long off);

#endif /* __UM_OS_WINDOWS_PHYSALLOC_H */
