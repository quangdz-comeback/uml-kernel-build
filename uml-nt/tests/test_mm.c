/* test_mm.c — unit tests for the M3.2 memory core: physalloc (run
 * refcount layer + backend mocks), vma (mm/VMA surgery), fault (plan
 * generation). Pure logic, compiled with the overlay files as-is on
 * Linux CI (same pattern as test_scan_patch.c).
 *
 * Ownership model: a run enters use via uml_nt_phys_alloc (the backend
 * hands a page-allocator run, refs = 1); sharing bumps it via
 * uml_nt_phys_ref. Refcounts track REFERENCING CONTEXTS (mm's), not
 * VMA pieces — a COW split unrefs the old run.
 *
 * D11 (M3.3): the backend IS the kernel page allocator kernel-side
 * (alloc_pages order 4); here it is mocked. Offsets are DYNAMIC — the
 * mock deliberately starts at a non-zero base so no test can pass by
 * assuming the section head or a fixed layout above the image.
 *
 * Geometry contract under test (vma.h): VMAs are 64K-run multiples —
 * every COW split keeps MapViewOfFile offsets 64K-aligned.
 */
#include <stdio.h>
#include <string.h>
#include <fault.h>
#include <vma.h>
#include <physalloc.h>
#include <stub_nt.h>

static int fails;

#define CHECK(cond) do { if (!(cond)) { \
	fails++; \
	printf("FAIL %d: %s\n", __LINE__, #cond); \
} } while (0)

#define RUN  UML_NT_PHYS_RUN_SIZE
#define RAM  0x60000000ull

/* ---- backend mock (D11/D12): a tiny "buddy" of MOCK_RUNS runs ----
 * Block-granular like the real one: an nrun span hands a whole
 * 2^ceil(log2 n) block (contiguous), first-fit; the padding runs stay
 * taken while the block lives (the buddy never rehands them). */

#define MOCK_RUNS 16
#define MOCK_BASE (1ull << 20) /* 1 MiB — deliberately not the head */
static unsigned char mock_taken[MOCK_RUNS];

static void mock_reset(void)
{
	memset(mock_taken, 0, sizeof(mock_taken));
}

static int mock_need(int nruns)
{
	int k;

	for (k = 0; (1 << k) < nruns; k++)
		;
	return 1 << k;
}

long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	int i, j, need = mock_need(nruns);

	for (i = 0; i + need <= MOCK_RUNS; i++) {
		int ok = 1;

		for (j = 0; j < need; j++) {
			if (mock_taken[i + j]) {
				ok = 0;
				i += j; /* skip the busy run */
				break;
			}
		}
		if (!ok)
			continue;
		for (j = 0; j < need; j++)
			mock_taken[i + j] = 1;
		*page_out = &mock_taken[i];
		return MOCK_BASE + (long long)i * RUN;
	}
	return -1;
}

void uml_nt_phys_backend_free(void *page, int nruns)
{
	int i = (int)((char *)page - (char *)mock_taken);
	int j, need = mock_need(nruns);

	for (j = 0; j < need; j++)
		if (i + j >= 0 && i + j < MOCK_RUNS)
			mock_taken[i + j] = 0;
}

static void test_phys(void)
{
	struct uml_nt_phys p;
	unsigned long long r0, r1;

	CHECK(uml_nt_phys_init(&p, 64 * RUN) == 0);
	CHECK(uml_nt_phys_init(&p, (UML_NT_PHYS_MAX_RUNS + 1) *
			       RUN) == -1);

	mock_reset();
	r0 = uml_nt_phys_alloc(&p);
	r1 = uml_nt_phys_alloc(&p);
	CHECK(r0 == MOCK_BASE);
	CHECK(r1 == MOCK_BASE + (long long)RUN);
	CHECK(uml_nt_phys_refs(&p, r0) == 1);

	/* sharing: ref an ALLOCATED run */
	CHECK(uml_nt_phys_ref(&p, r0) == 2);
	CHECK(uml_nt_phys_unref(&p, r0) == 1);
	CHECK(uml_nt_phys_unref(&p, r0) == 0);
	CHECK(uml_nt_phys_refs(&p, r0) == 0);
	/* freed run is reusable (the backend hands it out again) */
	CHECK(uml_nt_phys_alloc(&p) == (long long)r0);

	/* bad handles */
	CHECK(uml_nt_phys_ref(&p, RUN * 1000) == -1);   /* out of range */
	CHECK(uml_nt_phys_ref(&p, 0x1000) == -1);       /* not run-aligned */
	CHECK(uml_nt_phys_unref(&p, r1 + 8 * RUN) == -1); /* free run */
	CHECK(uml_nt_phys_ref(&p, r1 + 8 * RUN) == -1);   /* ref free run */

	/* exhaust: the MOCK pool (16 runs), 2 taken so far */
	{
		int i;

		for (i = 0; i < MOCK_RUNS - 2; i++)
			CHECK((long long)uml_nt_phys_alloc(&p) >= 0);
		CHECK((long long)uml_nt_phys_alloc(&p) == -1);
	}
}

/* Span allocation (D12): one backend block for n runs, every run
 * refs=1, block released exactly once — when the LAST run drops. */
static void test_span(void)
{
	struct uml_nt_phys p;
	unsigned long long s;

	mock_reset();
	CHECK(uml_nt_phys_init(&p, 32 * RUN) == 0);

	/* degenerate requests */
	CHECK(uml_nt_phys_alloc_span(&p, 0) == -1);
	CHECK(uml_nt_phys_alloc_span(&p, -3) == -1);
	CHECK(uml_nt_phys_alloc_span(&p, UML_NT_PHYS_MAX_RUNS + 1) == -1);

	/* 3-run span: block granularity 4 — runs 0..2 tracked, run 3
	 * is block padding (taken at the backend, untracked here). */
	s = uml_nt_phys_alloc_span(&p, 3);
	CHECK(s == MOCK_BASE);
	CHECK(uml_nt_phys_refs(&p, s) == 1);
	CHECK(uml_nt_phys_refs(&p, s + RUN) == 1);
	CHECK(uml_nt_phys_refs(&p, s + 2 * RUN) == 1);

	/* pieces drop independently; the block survives until the
	 * LAST tracked run drops (COW pieces outlive the owner run) */
	CHECK(uml_nt_phys_unref(&p, s + RUN) == 0);
	CHECK(uml_nt_phys_refs(&p, s) == 1);
	/* padding run never rehanded while the block lives */
	CHECK((unsigned long long)uml_nt_phys_alloc(&p) ==
	      s + 4 * RUN);
	CHECK(uml_nt_phys_unref(&p, s) == 0);
	CHECK(uml_nt_phys_refs(&p, s + 2 * RUN) == 1);
	CHECK(mock_taken[0] && mock_taken[3]); /* block still alive */

	CHECK(uml_nt_phys_unref(&p, s + 2 * RUN) == 0);
	CHECK(!mock_taken[0] && !mock_taken[3]); /* freed exactly once */

	/* freed span is fully reusable */
	CHECK((unsigned long long)uml_nt_phys_alloc(&p) == s);
}

/* D11 translate: syscall buffers go through the VMA tree, never the
 * identity (va - ram_base). */
static void test_translate(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm, child;
	struct uml_nt_fault_plan plan;
	unsigned long long r0, r1;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	/* inside → run_off + delta */
	CHECK(uml_nt_vma_translate(&mm, RAM + 0x1234, 8) ==
	      (long long)(r0 + 0x1234));
	/* len 0 at the last byte: fine */
	CHECK(uml_nt_vma_translate(&mm, RAM + 2 * RUN - 1, 0) ==
	      (long long)(r0 + 2 * RUN - 1));
	/* buffer crossing the VMA end: -EFAULT class */
	CHECK(uml_nt_vma_translate(&mm, RAM + 2 * RUN - 4, 8) == -1);
	/* unmapped */
	CHECK(uml_nt_vma_translate(&mm, RAM + 2 * RUN, 1) == -1);
	CHECK(uml_nt_vma_translate(&mm, RAM - 1, 1) == -1);

	/* translate follows COW: after a split the same VA resolves
	 * through the NEW run (this is the whole point of D11) */
	r1 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2); /* a sharer joins */
	CHECK(uml_nt_vma_chg(&mm, RAM, RAM + 2 * RUN,
			     UML_NT_PAGE_READWRITE) == 0);
	mm.vma[0].flags |= UML_NT_VMA_COW;
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill);
	/* single-run VMA: UNMAP + MAP(private) — the fresh run is the
	 * mock's next free one (r1 + RUN; the buddy owes nothing) */
	CHECK(mm.vma[0].run_off == r1 + RUN);
	CHECK(uml_nt_vma_translate(&mm, RAM + 0x1234, 8) ==
	      (long long)(r1 + RUN + 0x1234));

	/* clone keeps translating: the child shares the run (COW) so
	 * the same VA resolves to the SAME offset in the child */
	uml_nt_mm_init(&child);
	CHECK(uml_nt_mm_clone(&child, &mm, &ph, RAM + 4 * RUN) == 0);
	CHECK(uml_nt_vma_translate(&child, RAM + 0x1234, 8) ==
	      (long long)(r1 + RUN + 0x1234));
}

static void test_vma(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm a, b, c;
	struct uml_nt_vma *v;
	unsigned long long r0, r1;

	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&a);

	/* add: sorted, run-multiple geometry enforced by the caller */
	CHECK(uml_nt_vma_add(&a, RAM + 0x10000, RAM + 0x30000,
			     0x10000, UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_add(&a, RAM + 0x00000, RAM + 0x10000,
			     0x00000, UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(a.nvma == 2);

	/* overlap rejected */
	CHECK(uml_nt_vma_add(&a, RAM + 0x18000, RAM + 0x28000,
			     0x18000, UML_NT_PAGE_READWRITE, 0) == -1);
	/* degenerate range rejected */
	CHECK(uml_nt_vma_add(&a, RAM + 0x40000, RAM + 0x40000,
			     0x40000, UML_NT_PAGE_READWRITE, 0) == -1);

	/* find */
	v = uml_nt_vma_find(&a, RAM + 0x10800);
	CHECK(v != 0 && v->start == RAM + 0x10000);
	CHECK(uml_nt_vma_find(&a, RAM + 0xf0000) == 0);

	/* chg: prot update over a range */
	CHECK(uml_nt_vma_chg(&a, RAM + 0x10000, RAM + 0x20000,
			     UML_NT_PAGE_READONLY) == 0);
	v = uml_nt_vma_find(&a, RAM + 0x10800);
	CHECK(v->prot == UML_NT_PAGE_READONLY);
	CHECK(uml_nt_vma_chg(&a, RAM + 0x80000, RAM + 0x90000,
			     UML_NT_PAGE_READONLY) == -1);

	/* del: tail cut keeps the head piece */
	CHECK(uml_nt_vma_del(&a, RAM + 0x20000, RAM + 0x30000) == 0);
	v = uml_nt_vma_find(&a, RAM + 0x10800);
	CHECK(v != 0 && v->end == RAM + 0x20000);
	CHECK(uml_nt_vma_find(&a, RAM + 0x20000) == 0);

	/* del: full removal of the first VMA — the second survives */
	CHECK(uml_nt_vma_del(&a, RAM + 0x00000, RAM + 0x10000) == 0);
	CHECK(a.nvma == 1);
	CHECK(uml_nt_vma_del(&a, RAM + 0x00000, RAM + 0x10000) == -1);

	/* sorted-by-start invariant after out-of-order inserts —
	 * find_free_base (elf.c) walks the list assuming ascending
	 * order; vma_add's insert must keep it (M3.5 review note). */
	{
		int i;
		unsigned long long prev = 0;

		uml_nt_mm_init(&a);
		CHECK(uml_nt_vma_add(&a, RAM + 0x60000, RAM + 0x70000,
				     0x60000, UML_NT_PAGE_READWRITE,
				     0) == 0);
		CHECK(uml_nt_vma_add(&a, RAM + 0x30000, RAM + 0x40000,
				     0x30000, UML_NT_PAGE_READWRITE,
				     0) == 0);
		CHECK(uml_nt_vma_add(&a, RAM, RAM + 0x10000, 0,
				     UML_NT_PAGE_READWRITE, 0) == 0);
		CHECK(a.nvma == 3);
		for (i = 0; i < a.nvma; i++) {
			CHECK(a.vma[i].start >= prev);
			prev = a.vma[i].start;
		}
	}

	/* clone: writable VMAs become COW; every run of the span is
	 * reffed (owner alloc'd them); drop releases. rsp outside the
	 * VMA = nothing eager-copies. */
	mock_reset();
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	r0 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph);
	CHECK(r0 == MOCK_BASE && r1 == MOCK_BASE + (long long)RUN);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_clone(&b, &a, &ph, RAM + 8 * RUN) == 0);
	CHECK(b.nvma == 1);
	CHECK((b.vma[0].flags & UML_NT_VMA_COW) != 0);
	CHECK(uml_nt_phys_refs(&ph, r0) == 2);
	CHECK(uml_nt_phys_refs(&ph, r1) == 2);
	uml_nt_mm_drop(&b, &ph);
	CHECK(uml_nt_phys_refs(&ph, r0) == 1);
	CHECK(uml_nt_phys_refs(&ph, r1) == 1);

	/* clone with rsp INSIDE the VMA (rsp = one past the last stack
	 * byte — the VMA owns [start, rsp)): eager-copy into a fresh
	 * run pair, no COW flag, source refs untouched. The pair is
	 * contiguous by construction: alloc_span hands a whole block
	 * (D12 — the mock mirrors the buddy's granularity). */
	mock_reset();
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	r0 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_clone(&b, &a, &ph, RAM + 2 * RUN) == 0);
	CHECK(b.nvma == 1);
	CHECK((b.vma[0].flags & UML_NT_VMA_COW) == 0);
	CHECK(b.vma[0].run_off == r0 + 2 * (long long)RUN);
	CHECK(uml_nt_phys_refs(&ph, r0) == 1);   /* parent-only now */
	CHECK(uml_nt_phys_refs(&ph, r1) == 1);
	CHECK(uml_nt_phys_refs(&ph, r0 + 2 * (long long)RUN) == 1);
	CHECK(uml_nt_phys_refs(&ph, r0 + 3 * (long long)RUN) == 1);
	uml_nt_mm_drop(&b, &ph);
	CHECK(uml_nt_phys_refs(&ph, r0 + 2 * (long long)RUN) == 0);
	CHECK(uml_nt_phys_refs(&ph, r0 + 3 * (long long)RUN) == 0);

	/* read-only VMAs do NOT become COW */
	mock_reset();
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READONLY, 0) == 0);
	CHECK(uml_nt_mm_clone(&c, &a, &ph, RAM + 8 * RUN) == 0);
	CHECK((c.vma[0].flags & UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_phys_refs(&ph, r0) == 2);
	uml_nt_mm_drop(&c, &ph);
	CHECK(uml_nt_phys_refs(&ph, r0) == 1);

	/* cow_split: fault at RAM+RUN+0x8000 (run k=1 of a 2-run VMA) */
	mock_reset();
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	r0 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2);   /* a sharer joins */
	CHECK(uml_nt_phys_ref(&ph, r1) == 2);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	{
		unsigned long long new_run = uml_nt_phys_alloc(&ph);

		CHECK(new_run == r0 + 2 * RUN);
		v = uml_nt_vma_find(&a, RAM + RUN + 0x8000);
		CHECK(v != 0);
		CHECK(uml_nt_vma_cow_split(&a, &ph, v, RAM + RUN + 0x8000,
					   new_run) == 0);
		CHECK(a.nvma == 2);
		/* pre piece: shared run, COW kept */
		v = uml_nt_vma_find(&a, RAM + 0x8000);
		CHECK(v != 0 && v->run_off == (unsigned long long)r0 &&
		      v->end == RAM + RUN &&
		      (v->flags & UML_NT_VMA_COW));
		/* middle piece: private run, COW cleared, prot intact */
		v = uml_nt_vma_find(&a, RAM + RUN + 0x8000);
		CHECK(v != 0 && v->run_off == (unsigned long long)new_run &&
		      v->start == RAM + RUN && v->end == RAM + 2 * RUN &&
		      !(v->flags & UML_NT_VMA_COW) &&
		      v->prot == UML_NT_PAGE_READWRITE);
		/* refcounts: this mm gave up its claim on the old run
		 * (2 -> 1, the sharer keeps it) and owns the new one */
		CHECK(uml_nt_phys_refs(&ph, r0) == 2);
		CHECK(uml_nt_phys_refs(&ph, r1) == 1);
		CHECK(uml_nt_phys_refs(&ph, new_run) == 1);
	}

	/* cow_split of a single-run VMA: no pieces beyond the middle */
	mock_reset();
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	r0 = uml_nt_phys_alloc(&ph);          /* sharer holder */
	CHECK(uml_nt_phys_ref(&ph, r0) == 2);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	r1 = uml_nt_phys_alloc(&ph);          /* private target */
	CHECK(r1 == r0 + (long long)RUN);
	v = uml_nt_vma_find(&a, RAM + 0x8000);
	CHECK(v != 0);
	CHECK(uml_nt_vma_cow_split(&a, &ph, v, RAM + 0x8000, r1) == 0);
	CHECK(a.nvma == 1);
	CHECK(a.vma[0].run_off == (unsigned long long)r1 &&
	      !(a.vma[0].flags & UML_NT_VMA_COW));
	CHECK(uml_nt_phys_refs(&ph, r0) == 1); /* sharer keeps it */
	CHECK(uml_nt_phys_refs(&ph, r1) == 1);

	/* protection classification */
	CHECK(uml_nt_prot_writable(UML_NT_PAGE_READWRITE));
	CHECK(uml_nt_prot_writable(UML_NT_PAGE_EXECUTE_READWRITE));
	CHECK(!uml_nt_prot_writable(UML_NT_PAGE_READONLY));
	CHECK(uml_nt_prot_execable(UML_NT_PAGE_EXECUTE_READWRITE));
	CHECK(!uml_nt_prot_execable(UML_NT_PAGE_READWRITE));
	CHECK(uml_nt_prot_readonly(UML_NT_PAGE_READWRITE) == 0x02u);
	CHECK(uml_nt_prot_readonly(UML_NT_PAGE_EXECUTE_READWRITE) == 0x20u);
}

/* Fixture: a 2-run COW-shared VMA [RAM, RAM+2RUN) backed by the mock's
 * first two runs; a second context references both (refs = 2). The
 * offsets are recorded for the caller in fix_r0/fix_r1. */
static unsigned long long fix_r0, fix_r1;

static void fixture(struct uml_nt_phys *ph, struct uml_nt_mm *mm)
{
	mock_reset();
	CHECK(uml_nt_phys_init(ph, 32 * RUN) == 0);
	uml_nt_mm_init(mm);
	fix_r0 = uml_nt_phys_alloc(ph);
	fix_r1 = uml_nt_phys_alloc(ph);
	CHECK(uml_nt_phys_ref(ph, fix_r0) == 2);  /* the second context */
	CHECK(uml_nt_phys_ref(ph, fix_r1) == 2);
	CHECK(uml_nt_vma_add(mm, RAM, RAM + 2 * RUN, fix_r0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
}

static void test_fault(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_fault_plan plan;
	unsigned long long r0, r1;

	/* wild pointer */
	fixture(&ph, &mm);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0xf0000, UML_NT_FAULT_WRITE,
			      &plan) == -1);
	CHECK(plan.kill);

	/* private write fault (unref the sharer): single PROTECT op
	 * with the VMA's own protection */
	fixture(&ph, &mm);
	CHECK(uml_nt_phys_unref(&ph, fix_r0) == 1);
	CHECK(uml_nt_phys_unref(&ph, fix_r1) == 1);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 1);
	CHECK(plan.ops[0].op == UML_NT_FOP_PROTECT);
	CHECK(plan.ops[0].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.ops[0].va == RAM);

	/* COW write fault on run k=1 (page RAM+RUN+0x8000): unmap the
	 * old view, map pre (readonly), map middle (private RW), copy
	 * directive run fix_r1 -> fresh run (allocated inside the
	 * fault path — the test does not pre-allocate it). */
	fixture(&ph, &mm);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + RUN + 0x8000,
			      UML_NT_FAULT_WRITE, &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 3);
	CHECK(plan.ops[0].op == UML_NT_FOP_UNMAP);
	CHECK(plan.ops[0].va == RAM && plan.ops[0].len == 2 * RUN);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[1].va == RAM && plan.ops[1].len == RUN);
	CHECK(plan.ops[1].prot == UML_NT_PAGE_READONLY);
	CHECK(plan.ops[1].off == fix_r0);
	CHECK(plan.ops[2].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[2].va == RAM + RUN &&
	      plan.ops[2].len == RUN);
	CHECK(plan.ops[2].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.ops[2].off == fix_r0 + 2 * RUN);
	CHECK(plan.copy_src_off == fix_r1 &&
	      plan.copy_dst_off == fix_r0 + 2 * RUN);
	/* mm surgery visible: pre stays shared+COW, middle private */
	CHECK(mm.nvma == 2);
	CHECK(mm.vma[0].run_off == (unsigned long long)fix_r0 &&
	      (mm.vma[0].flags & UML_NT_VMA_COW));
	CHECK(mm.vma[1].run_off ==
	      (unsigned long long)(fix_r0 + 2 * RUN) &&
	      !(mm.vma[1].flags & UML_NT_VMA_COW));
	/* refcounts: old run 2 -> 1 (sharer), new run owned */
	CHECK(uml_nt_phys_refs(&ph, fix_r1) == 1);
	CHECK(uml_nt_phys_refs(&ph, fix_r0 + 2 * RUN) == 1);

	/* COW write fault on the FIRST run: no pre piece */
	fixture(&ph, &mm);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x8000, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 3);
	CHECK(plan.ops[0].op == UML_NT_FOP_UNMAP);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[1].va == RAM);       /* middle now */
	CHECK(plan.ops[1].off == fix_r0 + 2 * (long long)RUN);
	CHECK(plan.ops[2].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[2].va == RAM + RUN); /* post piece */
	CHECK(plan.ops[2].off == fix_r1);
	CHECK(plan.copy_src_off == fix_r0);

	/* COW on a single-run VMA: UNMAP + MAP only */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x8000, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 2);
	CHECK(plan.ops[0].op == UML_NT_FOP_UNMAP);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP &&
	      plan.ops[1].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.copy_src_off == r0 &&
	      plan.copy_dst_off == r0 + (long long)RUN);

	/* write into a read-only VMA: kill (SIGSEGV at M4) */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READONLY, 0) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_WRITE,
			      &plan) == -1);
	CHECK(plan.kill);

	/* DEP fault on an executable VMA: restore, no copy */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_EXECUTE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_EXEC,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 1 &&
	      plan.ops[0].prot == UML_NT_PAGE_EXECUTE_READWRITE);

	/* DEP fault on a non-exec VMA: kill */
	r1 = uml_nt_phys_alloc(&ph);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r1,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_EXEC,
			      &plan) == -1);
	CHECK(plan.kill);

	/* read fault restores the EFFECTIVE (readonly while shared)
	 * protection — reads never copy */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_READ,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 1 &&
	      plan.ops[0].prot == UML_NT_PAGE_READONLY);
	CHECK(plan.copy_src_off == 0 && plan.copy_dst_off == 0);

	/* unknown access class: kill */
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, 5u, &plan) == -1);
	CHECK(plan.kill);

	/* physmem exhaustion during COW: kill, no ops leak out */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	{
		int i;

		for (i = 0; i < MOCK_RUNS; i++)
			CHECK(uml_nt_phys_alloc(&ph) >= 0);
	}
	CHECK(uml_nt_phys_ref(&ph, MOCK_BASE) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, MOCK_BASE,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x8000, UML_NT_FAULT_WRITE,
			      &plan) == -1);
	CHECK(plan.kill && plan.n_ops == 0);

	/* INIT plan (M3.3): one MAP per VMA with the EFFECTIVE
	 * protection — COW-shared runs map read-only so the first
	 * write faults into the private copy. */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2);   /* a second context */
	CHECK(uml_nt_phys_ref(&ph, r1) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_EXECUTE_READWRITE,
			     UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM + RUN, RAM + 2 * RUN, r1,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_init_plan(&mm, &ph, &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 2);
	CHECK(plan.ops[0].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[0].prot == UML_NT_PAGE_EXECUTE_READ);
	CHECK(plan.ops[0].va == RAM && plan.ops[0].len == RUN &&
	      plan.ops[0].off == r0);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[1].prot == UML_NT_PAGE_READONLY);
	CHECK(plan.ops[1].va == RAM + RUN && plan.ops[1].len == RUN &&
	      plan.ops[1].off == r1);

	/* mirroring contract: plan ops == stub actions (drift breaks
	 * both sides silently) */
	CHECK(UML_NT_FOP_UNMAP == UML_STUB_ACTION_UNMAP);
	CHECK(UML_NT_FOP_MAP == UML_STUB_ACTION_MAP);
	CHECK(UML_NT_FOP_PROTECT == UML_STUB_ACTION_PROT);
}

/* M3.7: first-gap placement (mmap without a hint) + brk bookkeeping
 * fields. VMAs are 1 run each, backed by REALLY allocated runs (the
 * refcount layer rejects refs of unused runs — clone's span_ref). */
static void test_find_free(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	long long r0, r1, r2;

	CHECK(uml_nt_phys_init(&ph, MOCK_BASE + 16 * RUN) == 0);
	r0 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph);
	r2 = uml_nt_phys_alloc(&ph);
	CHECK(r0 >= 0 && r1 >= 0 && r2 >= 0);

	uml_nt_mm_init(&mm);
	CHECK(mm.heap_start == 0 && mm.heap_end == 0 && mm.brk == 0);
	/* empty mm: the whole span is one gap */
	CHECK(uml_nt_vma_find_free(&mm, 3 * RUN, RAM, RAM + 16 * RUN)
	      == RAM);
	/* one VMA at [RAM, +1 run): the gap AFTER it */
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_find_free(&mm, 2 * RUN, RAM, RAM + 16 * RUN)
	      == RAM + RUN);
	/* exactly fills the tail gap */
	CHECK(uml_nt_vma_find_free(&mm, 15 * RUN, RAM, RAM + 16 * RUN)
	      == RAM + RUN);
	/* one run more than the tail = 0 (nothing fits) */
	CHECK(uml_nt_vma_find_free(&mm, 16 * RUN, RAM, RAM + 16 * RUN)
	      == 0);
	/* second VMA far above: still fits in the tail, first-gap */
	CHECK(uml_nt_vma_add(&mm, RAM + 8 * RUN, RAM + 9 * RUN, r1,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_find_free(&mm, 3 * RUN, RAM, RAM + 16 * RUN)
	      == RAM + RUN);
	/* bottom-up: first gap wins even when a smaller one exists */
	CHECK(uml_nt_vma_add(&mm, RAM + RUN, RAM + 2 * RUN, r2,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_find_free(&mm, 2 * RUN, RAM, RAM + 16 * RUN)
	      == RAM + 2 * RUN);
	/* the 6-run hole [RAM+2, RAM+8) fits 6, not 7 */
	CHECK(uml_nt_vma_find_free(&mm, 6 * RUN, RAM, RAM + 16 * RUN)
	      == RAM + 2 * RUN);
	CHECK(uml_nt_vma_find_free(&mm, 7 * RUN, RAM, RAM + 16 * RUN)
	      == RAM + 9 * RUN);
	/* heap bookkeeping survives clone (child brk == parent brk) */
	{
		struct uml_nt_mm child;

		mm.heap_start = RAM + 12 * RUN;
		mm.heap_end = RAM + 13 * RUN;
		mm.brk = RAM + 12 * RUN + 0x100;
		CHECK(uml_nt_mm_clone(&child, &mm, &ph, 0) == 0);
		CHECK(child.heap_start == mm.heap_start);
		CHECK(child.heap_end == mm.heap_end);
		CHECK(child.brk == mm.brk);
		uml_nt_mm_drop(&child, &ph);
	}
}

/* M3.8 review regression: the munmap unref set must be each VMA's
 * OWN span, deduped per physical run — looping len/RUN from every
 * selected VMA's run_off unrefs unrelated backing (refcount
 * underflow → premature free). */
static void test_span_runs(void)
{
	struct uml_nt_mm mm;
	unsigned long long runs[UML_NT_VMA_MAX];
	int n;

	uml_nt_mm_init(&mm);
	/* VMA1: multi-run [RAM, +2R) on r0/r0+R; VMA2: [RAM+2R, +1R)
	 * on r2; VMA3: [RAM+3R, +1R) SHARES r2 (adjacent, same run);
	 * VMA4: [RAM+8R, +1R) on r3 — outside the probed range. */
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + 2 * RUN, 0x100000,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM + 2 * RUN, RAM + 3 * RUN, 0x300000,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM + 3 * RUN, RAM + 4 * RUN, 0x300000,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM + 8 * RUN, RAM + 9 * RUN, 0x500000,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	/* whole 4-run range: VMA1's span (2 runs) + r2 (shared by
	 * VMA2+VMA3, counted ONCE) = 3 physical runs, never the
	 * neighbour run 0x500000 and never a duplicate 0x300000 */
	n = uml_nt_vma_span_runs(&mm, RAM, RAM + 4 * RUN, runs,
				 UML_NT_VMA_MAX);
	CHECK(n == 3);
	CHECK(runs[0] == 0x100000);
	CHECK(runs[1] == 0x100000 + RUN);
	CHECK(runs[2] == 0x300000);

	/* single middle VMA (shared run) → just r2 */
	n = uml_nt_vma_span_runs(&mm, RAM + 2 * RUN, RAM + 3 * RUN, runs,
				 UML_NT_VMA_MAX);
	CHECK(n == 1 && runs[0] == 0x300000);

	/* nothing intersecting → 0 */
	n = uml_nt_vma_span_runs(&mm, RAM + 4 * RUN, RAM + 6 * RUN, runs,
				 UML_NT_VMA_MAX);
	CHECK(n == 0);

	/* disjoint VMA contributes nothing even when the range ends
	 * flush against it */
	n = uml_nt_vma_span_runs(&mm, RAM, RAM + 2 * RUN, runs,
				 UML_NT_VMA_MAX);
	CHECK(n == 2 && runs[0] == 0x100000 && runs[1] == 0x100000 + RUN);

	/* overflow = -1 (tiny out buffer) */
	n = uml_nt_vma_span_runs(&mm, RAM, RAM + 4 * RUN, runs, 2);
	CHECK(n == -1);
}

int main(void)
{
	test_phys();
	test_span();
	test_vma();
	test_translate();
	test_fault();
	test_find_free();
	test_span_runs();

	if (fails) {
		printf("test_mm: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_mm: all ok\n");
	return 0;
}
