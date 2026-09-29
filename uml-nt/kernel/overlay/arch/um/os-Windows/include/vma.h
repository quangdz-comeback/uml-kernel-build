/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vma.h — per-guest-process VMA manager (M3.2), uml-nt.
 *
 * Upstream analogue: the guest address-space bookkeeping that upstream
 * realizes with host mmap (arch/um/kernel/tlb.c drives
 * mmap/munmap/mprotect batches into the stub). On NT the guest VA
 * space of one stub process is materialized as per-VMA VIEWS of the
 * single physmem section (stub_nt.h "M3 model"); this module owns the
 * kernel-side truth of those VMAs and the COW state between mm
 * contexts (ARCHITECTURE §4: COW lives in the guest kernel — copy the
 * page inside physmem on write-fault, never share one flat view).
 *
 * Granularity note: MapViewOfFile offsets must be 64 KiB-aligned, so
 * COW copies/splits happen at RUN granularity (physalloc.h), not 4K.
 * A write-fault on a shared run copies that run and splits the VMA at
 * its run boundaries — all resulting pieces keep 64K-aligned offsets.
 *
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI.
 */
#ifndef __UM_OS_WINDOWS_VMA_H
#define __UM_OS_WINDOWS_VMA_H

#include <physalloc.h>

#define UML_NT_VMA_MAX 64 /* fixed table for the POC; heap later */

/* NT PAGE_* protection constants (winnt.h values, declared here
 * because the kernel ELF must not include windows.h — D1). */
#define UML_NT_PAGE_NOACCESS            0x01u
#define UML_NT_PAGE_READONLY            0x02u
#define UML_NT_PAGE_READWRITE           0x04u
#define UML_NT_PAGE_WRITECOPY           0x08u
#define UML_NT_PAGE_EXECUTE             0x10u
#define UML_NT_PAGE_EXECUTE_READ        0x20u
#define UML_NT_PAGE_EXECUTE_READWRITE   0x40u

/* VMA flags. */
#define UML_NT_VMA_COW 0x1u /* write-fault copies the run (sharing) */

struct uml_nt_vma {
	unsigned long long start, end; /* guest VA, end exclusive */
	unsigned prot;    /* NT PAGE_* the guest sees once fixed up */
	unsigned flags;   /* UML_NT_VMA_* */
	unsigned long long run_off; /* backing run offset (64K aligned) */
};

/* One guest process address space. VMAs sorted by start, non-overlap
 * (the guest mmap contract). */
struct uml_nt_mm {
	struct uml_nt_vma vma[UML_NT_VMA_MAX];
	int nvma;
};

void uml_nt_mm_init(struct uml_nt_mm *mm);

/* Insert [start, end) backed by run_off with prot/flags. Returns 0,
 * -1 on overlap, table full, or unsorted input. */
int uml_nt_vma_add(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end, unsigned long long run_off,
		   unsigned prot, unsigned flags);

/* VMA containing addr, or NULL. */
struct uml_nt_vma *uml_nt_vma_find(struct uml_nt_mm *mm,
				   unsigned long long addr);

/* munmap analogue: remove (possibly splitting VMAs at the edges).
 * Run refcounts are NOT touched here — pair with mm_drop/phys unrefs
 * at the caller (fork/exec integration, M3.3). Returns 0, -1 on
 * table full or unmap of nothing. */
int uml_nt_vma_del(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end);

/* mprotect analogue over [start, end) (must be inside VMAs). */
int uml_nt_vma_chg(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end, unsigned prot);

/* Fork analogue: deep-copy src into dst; every writable VMA becomes
 * COW (reads keep working off the shared run), refcounts bumped once
 * per distinct run. Returns 0, -1 on table full / refcount failure. */
int uml_nt_mm_clone(struct uml_nt_mm *dst, const struct uml_nt_mm *src,
		    struct uml_nt_phys *ph);

/* Drop the mm: unref every distinct backing run (adjacent VMAs on the
 * same run counted once). */
void uml_nt_mm_drop(struct uml_nt_mm *mm, struct uml_nt_phys *ph);

/*
 * COW surgery for one write-fault: split `vma` around the 64K run
 * containing `page`; the intersecting piece is repointed to `new_run`
 * (allocated by the caller via uml_nt_phys_alloc, content copied by
 * the integration — kernel memcpy in its own flat view) and loses the
 * COW flag. Flanking pieces keep the shared run + COW flag. The old
 * run's refcount is unchanged (this mm still references it through
 * the flanks). Returns 0, -1 on table full / bad geometry.
 */
int uml_nt_vma_cow_split(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			 struct uml_nt_vma *vma, unsigned long long page,
			 unsigned long long new_run);

/* Protection classification (NT PAGE_* values; see fault.h). */
int uml_nt_prot_writable(unsigned prot);
int uml_nt_prot_execable(unsigned prot);
int uml_nt_prot_readable(unsigned prot);
/* Read-only variant of a protection (what a COW-sharing view is
 * mapped with — writes must fault to reach the COW logic). */
unsigned uml_nt_prot_readonly(unsigned prot);

#endif /* __UM_OS_WINDOWS_VMA_H */
