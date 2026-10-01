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

#define UML_NT_VMA_MAX 256 /* fixed table; systemd's loader-chunked
	* mm blew past 64 — "fork: mm clone failed" run 36776389525
	* (38 vma(s) seeded at the first fork, grown past the cap by
	* the next) */

#define UML_NT_FAULT_PAGE_SIZE 0x1000ull /* guest page granularity —
	* owned here (vma geometry: guards are page-granular); fault.h
	* keeps a compat redefinition guard */

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
/* M5.4 c2 (D20): file-backed mapping (the loader's MAP_COPY|MAP_FILE
 * shape — private). MAP_FIXED re-mappings over it REFILL the bytes
 * (file content / zeros) instead of replacing VMAs: a run is the
 * indivisible backing unit, but content is byte-ranged — each
 * mapping writes exactly the VA bytes it owns at its file offset.
 * The view prot of a file VMA is the union-privileged RWX: segment
 * mappings arrive one per PT_LOAD (4K-aligned, mid-run), per-run prot
 * state would buy nothing boot-critical, and the D20 sweep fires per
 * exec mapping anyway. Tightening to per-run prot = later slice if a
 * workload needs W^X honesty. */
#define UML_NT_VMA_FILE 0x2u

struct uml_nt_vma {
	unsigned long long start, end; /* guest VA, end exclusive */
	unsigned prot;    /* NT PAGE_* the guest sees once fixed up */
	unsigned flags;   /* UML_NT_VMA_* */
	unsigned long long run_off; /* backing run offset (64K aligned) */
};

/* Sub-run PROT_NONE region (M4 slice 5): the musl mallocng brk guard
 * is mmap(4K, PROT_NONE, MAP_FIXED) INSIDE a run-backed VMA —
 * unexpressible as VMA state (VMAs are run multiples) and wrong as a
 * wholesale VMA protect. Guards are PAGE-granular VA ranges the mm
 * remembers beside the VMA tree: the stub view is NOACCESS there
 * (FOP_PROTECT op), a fault inside one is a REAL SIGSEGV (ACCERR —
 * the tripwire musl wants), and any later mapping/mprotect over the
 * range kills the guard (Linux: the change wins). The kernel never
 * auto-repairs a guard fault (the tripwire must fire), but the state
 * is the ONLY truth for faults — after a COW split's remap the view
 * piece comes up writable, so a guard READ can succeed where Linux
 * would fault (musl never reads its guard; documented divergence). */
#define UML_NT_GUARD_MAX 32

/* uml_nt_mm_clone failure reason codes (positive; the caller logs
 * them — vma.c stays pure logic for the Linux unit test). */
#define UML_NT_CLONE_SPAN  1 /* the eager stack span alloc failed */
#define UML_NT_CLONE_TABLE 2 /* the dst VMA table is full */
#define UML_NT_CLONE_REF   3 /* a shared run had refs==0 in the table */

const char *uml_nt_clone_reason(int rc);

struct uml_nt_guard {
	unsigned long long start, end; /* guest VA, end exclusive */
};

/* One guest process address space. VMAs sorted by start, non-overlap
 * (the guest mmap contract). */
struct uml_nt_mm {
	struct uml_nt_vma vma[UML_NT_VMA_MAX];
	int nvma;
	/* brk bookkeeping (M3.7, grown since M4 slice 4): [heap_start,
	 * heap_end) starts as the ONE pre-reserved, pre-mapped run the
	 * exec setup hands the mm; brk(2) past heap_end re-homes the
	 * heap in a fresh contiguous span (contents memcpy'd, VMA
	 * swapped, stub ops queued — syscall.c sys_brk). heap_end == 0
	 * = no heap reserved: brk fails (returns current brk). */
	unsigned long long heap_start, heap_end, brk;
	/* Sub-run PROT_NONE guards (M4 slice 5, vma.h note). VA-keyed
	 * so they survive VMA resizes and COW splits; cloned with the
	 * mm, cleared on drop. */
	struct uml_nt_guard guard[UML_NT_GUARD_MAX];
	int nguard;
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

/* First free guest-VA range of `len` bytes inside [base, limit),
 * walking the sorted VMA list bottom-up (first gap). `len` must be a
 * run multiple (the geometry contract). Returns the VA or 0 when
 * nothing fits (0 is never a valid guest VA base). */
unsigned long long uml_nt_vma_find_free(const struct uml_nt_mm *mm,
					unsigned long long len,
					unsigned long long base,
					unsigned long long limit);

/* Collect the DISTINCT physical runs backing the VMAs intersecting
 * [start, end) — the munmap unref set. Each VMA contributes ITS OWN
 * span (run_off .. run_off + size), deduped per physical run (two
 * VMAs may share one run; a multi-run VMA contributes all of it).
 * Fills runs[] (section offsets), returns the count or -1 when the
 * set exceeds `max`. */
int uml_nt_vma_span_runs(const struct uml_nt_mm *mm,
			 unsigned long long start, unsigned long long end,
			 unsigned long long *runs, int max);

/* Upstream MAP_FIXED replace check: 0 when every VMA intersecting
 * [start, end) lies FULLY inside it (whole views — the stub can
 * unmap exactly those), -1 when any VMA only partially overlaps
 * (a flank piece would need view surgery — refuse loud). */
int uml_nt_vma_span_fits(const struct uml_nt_mm *mm,
			 unsigned long long start, unsigned long long end);

/* M5.4 c2: the file-backed mmap target decision for the 4K-aligned
 * request [start, end). Returns 0 = FRESH (no VMA intersects the
 * run-rounded span — a new VMA + span can be created), 1 = INSIDE
 * (the whole request sits in ONE VMA, reported through *inside —
 * bytes refill in place), -1 = MIXED (flank overlap — refuse loud;
 * no loader we serve needs it). Pure logic — unit-tested. */
int uml_nt_vma_map_kind(struct uml_nt_mm *mm,
			unsigned long long start, unsigned long long end,
			struct uml_nt_vma **inside);

/* mprotect analogue over [start, end) (must be inside VMAs). */
int uml_nt_vma_chg(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end, unsigned prot);

/* Guard API (M4 slice 5). add: page-aligned non-overlapping region —
 * 0 or -1 (alignment/overlap/table full). del_range: drop guards the
 * range fully covers AND partially overlaps (the mapping/mprotect
 * wins; an unrecorded NOACCESS region would mis-fault later) —
 * returns how many died (a partial kill is the caller's loud-log
 * signal). hit: 1 when addr falls inside a guard. */
int uml_nt_guard_add(struct uml_nt_mm *mm, unsigned long long start,
		     unsigned long long end);
int uml_nt_guard_del_range(struct uml_nt_mm *mm, unsigned long long start,
			   unsigned long long end);
int uml_nt_guard_hit(const struct uml_nt_mm *mm, unsigned long long addr);

/* The translate boundary (048): a physmem section offset is only
 * valid BELOW this line. The kernel pins it to uml_boot.physmem_size
 * at boot (no allocation can hand out a run at/above it); the
 * default keeps the historical e938b68 VA-base bound so a walk
 * before the pin is refused-safe, not unbounded. */
extern unsigned long long uml_nt_vma_phys_limit;

/* Guest VA buffer [va, va+len) → physmem section offset, or -1 when
 * any byte is unmapped or the buffer crosses the VMA end. D11: the
 * syscall path (write/… buffers) MUST translate through this — the
 * identity va == RAM_BASE + off only holds for runs never COW-copied. */
long long uml_nt_vma_translate(const struct uml_nt_mm *mm,
			       unsigned long long va, unsigned long long len);

/* Fork analogue: deep-copy src into dst; writable VMAs become COW
 * (reads keep working off the shared run), refcounts bumped once per
 * distinct run — EXCEPT the VMA holding `rsp` (the guest stack): the
 * NT VEH dispatch pushes the exception frame on the faulting thread's
 * stack, so a COW-faulted stack page kills the dispatch before any
 * handler runs (Linux fixes the page pre-signal; NT has no such
 * step). That VMA eager-copies into a fresh private span (contents
 * are the CALLER's job, through its flat view) and carries no COW
 * flag. Returns 0 or a positive UML_NT_CLONE_* reason code (the
 * caller logs it and owns the dst teardown — vma.c note; the eager
 * span is contiguous by construction — phys alloc_span, D12). */
int uml_nt_mm_clone(struct uml_nt_mm *dst, const struct uml_nt_mm *src,
		    struct uml_nt_phys *ph, unsigned long long rsp);

/* Drop the mm: unref every distinct backing run (adjacent VMAs on the
 * same run counted once). */
void uml_nt_mm_drop(struct uml_nt_mm *mm, struct uml_nt_phys *ph);

/*
 * COW surgery for one write-fault: split `vma` around the 64K run
 * containing `page`; the intersecting piece is repointed to `new_run`
 * (allocated by the caller via uml_nt_phys_alloc, content copied by
 * the integration — kernel memcpy in its own flat view) and loses the
 * COW flag. Flanking pieces keep the shared BLOCK (each at its own
 * base within it) + the COW flag. The faulting run's refcount drops
 * by one — this mm's claim moves to new_run; the sharers keep the old
 * run and the flanks' refcounts are untouched. Returns 0, positive
 * reason codes are clone-only; -1 on table full / bad geometry.
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
