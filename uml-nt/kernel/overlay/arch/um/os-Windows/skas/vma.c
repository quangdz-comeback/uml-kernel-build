// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/vma.c — per-guest-process VMA manager (M3.2).
 * See vma.h for the model. Self-contained by design: compiled as-is
 * by the Linux CI unit test (with physalloc.c).
 */
#include <vma.h>

/* The translate boundary (048): a physmem section offset is only
 * valid BELOW this line. Boot pins it to uml_boot.physmem_size
 * (main.c) — no allocation can ever hand out a run at/above it, so
 * any translate result there is a rotten-VMA read, not memory we
 * own. The default keeps the historical e938b68 VA-base bound so a
 * walk before the pin is refused-safe, not unbounded. */
unsigned long long uml_nt_vma_phys_limit = UML_NT_GUEST_VA_BASE;

void uml_nt_mm_init(struct uml_nt_mm *mm)
{
	mm->nvma = 0;
	mm->heap_start = 0;
	mm->heap_end = 0;
	mm->brk = 0;
	mm->nguard = 0;
}

/* ---- sub-run PROT_NONE guards (M4 slice 5, vma.h note) ---- */

int uml_nt_guard_add(struct uml_nt_mm *mm, unsigned long long start,
		     unsigned long long end)
{
	int i;

	if (mm->nguard >= UML_NT_GUARD_MAX)
		return -1;
	if (start >= end ||
	    (start | end) & (UML_NT_FAULT_PAGE_SIZE - 1))
		return -1;
	for (i = 0; i < mm->nguard; i++) {
		if (start < mm->guard[i].end && end > mm->guard[i].start)
			return -1; /* overlap */
	}
	mm->guard[mm->nguard].start = start;
	mm->guard[mm->nguard].end = end;
	mm->nguard++;
	return 0;
}

int uml_nt_guard_del_range(struct uml_nt_mm *mm, unsigned long long start,
			   unsigned long long end)
{
	int i, n = 0;

	for (i = mm->nguard - 1; i >= 0; i--) {
		int j;

		if (start >= mm->guard[i].end || end <= mm->guard[i].start)
			continue; /* disjoint */
		for (j = i; j + 1 < mm->nguard; j++)
			mm->guard[j] = mm->guard[j + 1];
		mm->nguard--;
		n++;
	}
	return n;
}

int uml_nt_guard_hit(const struct uml_nt_mm *mm, unsigned long long addr)
{
	int i;

	for (i = 0; i < mm->nguard; i++) {
		if (addr >= mm->guard[i].start && addr < mm->guard[i].end)
			return 1;
	}
	return 0;
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

unsigned long long uml_nt_vma_find_free(const struct uml_nt_mm *mm,
					unsigned long long len,
					unsigned long long base,
					unsigned long long limit)
{
	unsigned long long cand = base;
	int i;

	if (len == 0 || base > limit)
		return 0;
	for (i = 0; i < mm->nvma; i++) {
		if (cand + len <= mm->vma[i].start)
			return cand; /* the gap before this VMA fits */
		if (mm->vma[i].end > cand)
			cand = mm->vma[i].end;
	}
	if (cand + len <= limit)
		return cand;
	return 0;
}

int uml_nt_vma_span_runs(const struct uml_nt_mm *mm,
			 unsigned long long start, unsigned long long end,
			 unsigned long long *runs, int max)
{
	int i, j, n = 0;

	for (i = 0; i < mm->nvma; i++) {
		const struct uml_nt_vma *v = &mm->vma[i];
		unsigned long long off, off_end;

		if (v->start >= end || v->end <= start)
			continue;
		/* the VMA's OWN backing span — never derived from the
		 * caller's range length (a multi-run VMA contributes
		 * all its runs; a neighbour's run is not ours) */
		for (off = v->run_off,
		     off_end = v->run_off + (v->end - v->start);
		     off < off_end; off += UML_NT_PHYS_RUN_SIZE) {
			for (j = 0; j < n && runs[j] != off; j++)
				;
			if (j == n) {
				if (n >= max)
					return -1;
				runs[n++] = off;
			}
		}
	}
	return n;
}

/* Upstream MAP_FIXED replace check: the stub's UNMAP releases one
 * whole view per op (UnmapViewOfFile), so "replace the range" is
 * only expressible when every intersecting VMA lies fully inside it
 * — those unmap cleanly; a flank piece (head/tail cut) has no whole
 * view to release (partial-map surgery = M4). Empty range/disjoint
 * VMAs fit trivially. */
int uml_nt_vma_span_fits(const struct uml_nt_mm *mm,
			 unsigned long long start, unsigned long long end)
{
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (mm->vma[i].start < end && mm->vma[i].end > start &&
		    (mm->vma[i].start < start || mm->vma[i].end > end))
			return -1;
	}
	return 0;
}

/* M5.4 c2 (see vma.h): FRESH / INSIDE-one-VMA / MIXED for the
 * 4K-aligned request range. FRESH is judged on the RUN-ROUNDED span
 * (that is the VMA a fresh map creates — a neighbour anywhere inside
 * it would be a flank overlap the stub cannot unmap); INSIDE needs
 * the whole request in ONE VMA (one refill walk, one view). */
int uml_nt_vma_map_kind(struct uml_nt_mm *mm,
			unsigned long long start, unsigned long long end,
			struct uml_nt_vma **inside)
{
	unsigned long long rs = start & ~(UML_NT_PHYS_RUN_SIZE - 1);
	unsigned long long re = (end + UML_NT_PHYS_RUN_SIZE - 1) &
				~(UML_NT_PHYS_RUN_SIZE - 1);
	struct uml_nt_vma *hit = 0;
	int i, any = 0;

	*inside = 0;
	for (i = 0; i < mm->nvma; i++) {
		if (mm->vma[i].start >= re || mm->vma[i].end <= rs)
			continue;
		any = 1;
		if (mm->vma[i].start <= start && end <= mm->vma[i].end)
			hit = &mm->vma[i];
	}
	if (!any)
		return 0;
	if (hit) {
		*inside = hit;
		return 1;
	}
	return -1;
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

/* Clone the address-space bookkeeping for a fork child. Returns 0,
 * or a positive UML_NT_CLONE_* reason code on failure (the caller
 * logs it — this file is pure logic, unit-tested without kernel
 * logging). Teardown contract: on failure the caller owns dst's
 * partial state (mmctx_destroy / the POC fork fail path both
 * uml_nt_mm_drop it) — dropping HERE would double-unref: the
 * executor-era boot died of exactly that (the first failed fork
 * unref'd the parent's shared runs twice, the buddy handed them to
 * the next mmap and the parent's libc/TLS pages rotted under it). */
int uml_nt_mm_clone(struct uml_nt_mm *dst, const struct uml_nt_mm *src,
		    struct uml_nt_phys *ph, unsigned long long rsp)
{
	int i;

	uml_nt_mm_init(dst);
	for (i = 0; i < src->nvma; i++) {
		const struct uml_nt_vma *v = &src->vma[i];
		unsigned flags = v->flags;
		unsigned long long run_off = v->run_off;
		int rc;

		/* NT constraint (M3.3): the VEH dispatch pushes the
		 * exception frame on the faulting thread's stack — a
		 * COW-faulted STACK page kills the dispatch before the
		 * handler runs. The VMA holding the fork rsp therefore
		 * eager-copies into a fresh private span; everything
		 * else keeps COW (its faults dispatch on the RW
		 * stack). Contents are the caller's job. The stack
		 * VMA owns [start, rsp): rsp itself = the first byte
		 * PAST the stack (the guard run's start, if any), so
		 * test rsp - 1 — the last stack byte. */
		if (uml_nt_prot_writable(v->prot) && rsp != 0 &&
		    rsp - 1 >= v->start && rsp - 1 < v->end) {
			/* alloc_span: contiguous by construction (D12 —
			 * the buddy hands a whole block; single-run
			 * allocs owe no adjacency). */
			long long off = uml_nt_phys_alloc_span(ph,
				(int)((v->end - v->start) /
				      UML_NT_PHYS_RUN_SIZE));

			if (off < 0)
				return UML_NT_CLONE_SPAN;
			run_off = (unsigned long long)off;
			flags &= ~UML_NT_VMA_COW;
		} else if (uml_nt_prot_writable(v->prot)) {
			flags |= UML_NT_VMA_COW;
			/* Upstream fork marks BOTH pte tables read-only
			 * (copy_page_range on both mms): the parent's
			 * writable view must fault too, or its post-
			 * fork writes land on the shared run and the
			 * child sees them. Effective prot still reads
			 * writable while refs==1 (parent after the
			 * child exits) — the mark only bites shared. */
			((struct uml_nt_vma *)v)->flags |= UML_NT_VMA_COW;
		}

		rc = uml_nt_vma_add(dst, v->start, v->end, run_off,
				    v->prot, flags);
		if (rc < 0)
			return UML_NT_CLONE_TABLE;

		/* Eager runs: alloc_span() reffed them (the child
		 * owns). Shared runs: ref the source span for this mm. */
		if (run_off == v->run_off && span_ref(ph, v) < 0)
			return UML_NT_CLONE_REF;
	}
	/* brk bookkeeping survives fork (the child's brk == parent's;
	 * the COW machinery already duplicated the pages it backs) —
	 * as do the sub-run guards (the child's views re-apply them:
	 * fault.c init_plan emits the NOACCESS ops). */
	dst->heap_start = src->heap_start;
	dst->heap_end = src->heap_end;
	dst->brk = src->brk;
	{
		int gi;

		for (gi = 0; gi < src->nguard; gi++)
			dst->guard[gi] = src->guard[gi];
		dst->nguard = src->nguard;
	}
	return 0;
}

/* Reason-code name for the caller's failure log. */
const char *uml_nt_clone_reason(int rc)
{
	switch (rc) {
	case UML_NT_CLONE_SPAN:
		return "stack-span-alloc";
	case UML_NT_CLONE_TABLE:
		return "vma-table-full";
	case UML_NT_CLONE_REF:
		return "shared-run-refs-zero";
	default:
		return "unknown";
	}
}

void uml_nt_mm_drop(struct uml_nt_mm *mm, struct uml_nt_phys *ph)
{
	int i;

	for (i = 0; i < mm->nvma; i++)
		span_unref(ph, &mm->vma[i]);
	mm->nvma = 0;
	mm->nguard = 0;
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

	/* This mm gives up its claim on the FAULTING run (the sharers
	 * keep theirs): the refcount tracks contexts, not pieces. The
	 * flanking runs' refcounts are untouched — this mm references
	 * them through the pieces it just grew. */
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
	 * keep the shared BLOCK and the COW flag (further writes there
	 * fault and copy again — correct COW semantics); each piece's
	 * run_off is ITS OWN base within the block — the post piece's
	 * content lives orig_run + (mid_e - orig_start) on, and every
	 * consumer (translate, the fault plan's MAP ops, the mm_drop
	 * unref walk) keys off the piece's run_off. The block base
	 * here made the child-inherited post piece unref the WRONG
	 * runs at drop — the parent's faulting run went to 0 while
	 * its VMA still pointed there (the next fork died
	 * shared-run-refs-zero, run 36782313512; the POC never saw it:
	 * every probed VMA was single-run, no post piece existed). */
	if (orig_end > mid_e) {
		rc = vma_insert(mm, idx + 1, mid_e, orig_end,
				orig_run + (mid_e - orig_start), prot,
				flags);
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

/* Guest VA buffer [va, va+len) → physmem section offset (D11: the
 * identity va == RAM_BASE + off only holds for runs never COW-copied;
 * the VMA tree is the truth — this is what every syscall buffer
 * translate goes through). Returns -1 when any byte falls outside a
 * VMA or the buffer crosses the VMA end (multi-VMA buffers: split at
 * the caller, M3.7). len == 0 translates trivially. */
long long uml_nt_vma_translate(const struct uml_nt_mm *mm,
			       unsigned long long va, unsigned long long len)
{
	const struct uml_nt_vma *v = 0;
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (va >= mm->vma[i].start && va < mm->vma[i].end) {
			v = &mm->vma[i];
			break;
		}
	}
	if (v == 0)
		return -1;
	if (len != 0 && (len > v->end - va))
		return -1;
	/* A translate result is a PHYSMEM SECTION OFFSET — it must land
	 * inside the physmem window itself, not merely below the guest
	 * VA base. The e938b68 bound (>= UML_NT_GUEST_VA_BASE) caught
	 * the ABSOLUTE run_off class (run 36803515813's VMA
	 * [0x60670000,0x60680000) walked as off=0x6069ff10, the
	 * walker's own memcpy deref'd base+off = 0xc069ff10) — but the
	 * freed-then-reused-mm walks (report 048) also emit run_off
	 * values BETWEEN the section end and the VA base; those
	 * translated fine and WROTE into a wrong guest run (the
	 * "STREAM=7"-in-a-pointer-slot / wild 0x3577fffff0003d40
	 * injection class in the SIGSEGV victims). The correct boundary
	 * is the physmem limit: one compare, no fork-seed interaction
	 * (every legit VMA's run_off lives below it by construction). */
	if ((unsigned long long)(v->run_off + (va - v->start)) >=
	    uml_nt_vma_phys_limit)
		return -1;
	return (long long)(v->run_off + (va - v->start));
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
