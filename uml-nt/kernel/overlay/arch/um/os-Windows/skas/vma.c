// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/vma.c — per-guest-process VMA manager (M3.2).
 * See vma.h for the model. Self-contained by design: compiled as-is
 * by the Linux CI unit test (with physalloc.c).
 */
#include <vma.h>

void uml_nt_mm_init(struct uml_nt_mm *mm)
{
	mm->nvma = 0;
}

/* Insert keeping sort order; overlap rejected (caller's mmap contract). */
int uml_nt_vma_add(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end, unsigned long long run_off,
		   unsigned prot, unsigned flags)
{
	int i, pos;

	if (mm->nvma >= UML_NT_VMA_MAX)
		return -1;
	if (start >= end)
		return -1;
	for (i = 0; i < mm->nvma; i++) {
		if (start < mm->vma[i].end && end > mm->vma[i].start)
			return -1; /* overlap */
	}
	pos = mm->nvma;
	for (i = 0; i < mm->nvma; i++) {
		if (start < mm->vma[i].start) {
			pos = i;
			break;
		}
	}
	for (i = mm->nvma; i > pos; i--)
		mm->vma[i] = mm->vma[i - 1];
	mm->vma[pos].start = start;
	mm->vma[pos].end = end;
	mm->vma[pos].run_off = run_off;
	mm->vma[pos].prot = prot;
	mm->vma[pos].flags = flags;
	mm->nvma++;
	return 0;
}

/* Raw insert at a known-sorted position (cow_split bookkeeping). */
static int vma_insert(struct uml_nt_mm *mm, int pos, unsigned long long start,
		      unsigned long long end, unsigned long long run_off,
		      unsigned prot, unsigned flags)
{
	int i;

	if (mm->nvma >= UML_NT_VMA_MAX)
		return -1;
	for (i = mm->nvma; i > pos; i--)
		mm->vma[i] = mm->vma[i - 1];
	mm->vma[pos].start = start;
	mm->vma[pos].end = end;
	mm->vma[pos].run_off = run_off;
	mm->vma[pos].prot = prot;
	mm->vma[pos].flags = flags;
	mm->nvma++;
	return 0;
}

struct uml_nt_vma *uml_nt_vma_find(struct uml_nt_mm *mm,
				   unsigned long long addr)
{
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (addr >= mm->vma[i].start && addr < mm->vma[i].end)
			return &mm->vma[i];
	}
	return 0;
}

int uml_nt_vma_del(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end)
{
	int i, hit = 0;

	/* Sorted + non-overlapping: the range fully covers zero or
	 * more VMAs and cuts at most one head piece and one tail piece
	 * (a middle hole cuts the same VMA as both). */
	for (i = mm->nvma - 1; i >= 0; i--) {
		unsigned long long s = mm->vma[i].start;
		unsigned long long e = mm->vma[i].end;

		if (s >= end || e <= start)
			continue; /* disjoint */
		hit = 1;
		if (s >= start && e <= end) {
			int j;

			for (j = i; j + 1 < mm->nvma; j++)
				mm->vma[j] = mm->vma[j + 1];
			mm->nvma--;
		} else if (s >= start) {
			/* head cut: [end, e) survives */
			mm->vma[i].start = end;
		} else if (e <= end) {
			/* tail cut: [s, start) survives */
			mm->vma[i].end = start;
		} else {
			/* middle hole: [s, start) + [end, e) survive */
			unsigned long long run = mm->vma[i].run_off;
			unsigned prot = mm->vma[i].prot;
			unsigned flags = mm->vma[i].flags;
			int rc;

			rc = vma_insert(mm, i + 1, end, e, run, prot, flags);
			if (rc < 0)
				return -1;
			mm->vma[i].end = start;
		}
	}
	return hit ? 0 : -1;
}

int uml_nt_vma_chg(struct uml_nt_mm *mm, unsigned long long start,
		   unsigned long long end, unsigned prot)
{
	int i, hit = 0;

	for (i = 0; i < mm->nvma; i++) {
		if (start >= mm->vma[i].end || end <= mm->vma[i].start)
			continue;
		hit = 1;
		mm->vma[i].prot = prot;
	}
	return hit ? 0 : -1;
}

/* Ref/unref every run of a VMA's span (VMAs are run multiples —
 * vma.h). */
static int span_ref(struct uml_nt_phys *ph, const struct uml_nt_vma *v)
{
	unsigned long long off;

	for (off = v->run_off; off < v->run_off + (v->end - v->start);
	     off += UML_NT_PHYS_RUN_SIZE) {
		if (uml_nt_phys_ref(ph, (long long)off) < 0)
			return -1;
	}
	return 0;
}

static void span_unref(struct uml_nt_phys *ph, const struct uml_nt_vma *v)
{
	unsigned long long off;

	for (off = v->run_off; off < v->run_off + (v->end - v->start);
	     off += UML_NT_PHYS_RUN_SIZE)
		uml_nt_phys_unref(ph, (long long)off);
}

int uml_nt_mm_clone(struct uml_nt_mm *dst, const struct uml_nt_mm *src,
		    struct uml_nt_phys *ph)
{
	int i;

	uml_nt_mm_init(dst);
	for (i = 0; i < src->nvma; i++) {
		const struct uml_nt_vma *v = &src->vma[i];
		unsigned flags = v->flags;
		int rc;

		/* Writable VMAs become COW: the child reads the shared
		 * run, its first write faults into a private copy. */
		if (uml_nt_prot_writable(v->prot))
			flags |= UML_NT_VMA_COW;

		rc = uml_nt_vma_add(dst, v->start, v->end, v->run_off,
				    v->prot, flags);
		if (rc < 0)
			goto fail;

		/* The child now references every run of the span. */
		if (span_ref(ph, v) < 0)
			goto fail;
	}
	return 0;

fail:
	uml_nt_mm_drop(dst, ph);
	return -1;
}

void uml_nt_mm_drop(struct uml_nt_mm *mm, struct uml_nt_phys *ph)
{
	int i;

	for (i = 0; i < mm->nvma; i++)
		span_unref(ph, &mm->vma[i]);
	mm->nvma = 0;
}

int uml_nt_vma_cow_split(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			 struct uml_nt_vma *vma, unsigned long long page,
			 unsigned long long new_run)
{
	unsigned long long run_start, run_end, mid_s, mid_e;
	unsigned long long orig_start, orig_end, orig_run, old_run;
	unsigned prot, flags;
	int idx, extra, rc;

	idx = (int)(vma - &mm->vma[0]);
	if (idx < 0 || idx >= mm->nvma)
		return -1;
	run_start = page & ~(UML_NT_PHYS_RUN_SIZE - 1);
	run_end = run_start + UML_NT_PHYS_RUN_SIZE;

	orig_start = vma->start;
	orig_end = vma->end;
	orig_run = vma->run_off;
	prot = vma->prot;
	flags = vma->flags;

	mid_s = orig_start > run_start ? orig_start : run_start;
	mid_e = orig_end < run_end ? orig_end : run_end;
	if (mid_s >= mid_e)
		return -1; /* the faulting run does not intersect the VMA */
	if (page < mid_s || page >= mid_e)
		return -1; /* faulting page outside the intersecting piece */

	extra = (mid_s > orig_start) + (orig_end > mid_e);
	if (mm->nvma + extra > UML_NT_VMA_MAX)
		return -1; /* split would overflow the table */

	/* This mm gives up its claim on the faulting run (the sharers
	 * keep theirs): the refcount tracks contexts, not pieces. */
	old_run = orig_run +
		  ((mid_s - orig_start) / UML_NT_PHYS_RUN_SIZE) *
			  UML_NT_PHYS_RUN_SIZE;
	if (uml_nt_phys_unref(ph, (long long)old_run) < 0)
		return -1;

	/* Middle piece first (in place): private run, COW cleared. */
	vma->start = mid_s;
	vma->end = mid_e;
	vma->run_off = new_run;
	vma->flags = flags & ~UML_NT_VMA_COW;

	/* Insertions keep the sort order: post above, pre below. Both
	 * keep the shared run and the COW flag (further writes there
	 * fault and copy again — correct COW semantics). */
	if (orig_end > mid_e) {
		rc = vma_insert(mm, idx + 1, mid_e, orig_end, orig_run,
				prot, flags);
		if (rc < 0)
			return -1;
	}
	if (mid_s > orig_start) {
		rc = vma_insert(mm, idx, orig_start, mid_s, orig_run,
				prot, flags);
		if (rc < 0)
			return -1;
	}
	return 0;
}

/* NT PAGE_* classification (winnt.h values, D1: no windows.h here). */
int uml_nt_prot_writable(unsigned prot)
{
	return prot == 0x04u /* READWRITE */ ||
	       prot == 0x40u /* EXECUTE_READWRITE */ ||
	       prot == 0x08u /* WRITECOPY */;
}

int uml_nt_prot_execable(unsigned prot)
{
	return prot == 0x10u /* EXECUTE */ ||
	       prot == 0x20u /* EXECUTE_READ */ ||
	       prot == 0x40u /* EXECUTE_READWRITE */ ||
	       prot == 0x80u /* EXECUTE_WRITECOPY */;
}

int uml_nt_prot_readable(unsigned prot)
{
	return prot != 0x01u /* NOACCESS */ && prot != 0x00u;
}

unsigned uml_nt_prot_readonly(unsigned prot)
{
	switch (prot) {
	case 0x04u: /* READWRITE */
		return 0x02u; /* READONLY */
	case 0x40u: /* EXECUTE_READWRITE */
		return 0x20u; /* EXECUTE_READ */
	case 0x08u: /* WRITECOPY */
		return 0x02u;
	case 0x80u: /* EXECUTE_WRITECOPY */
		return 0x20u;
	default:
		return prot;
	}
}
