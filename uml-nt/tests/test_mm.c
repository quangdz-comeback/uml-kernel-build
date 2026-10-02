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

/* D22 (Shelley phê): owner-view quarantine — a dropped block does not
 * return to the backend while the dropping conn's pending plan UNMAP
 * may still have the stub view mapped; a mis-ordered settle (the
 * OTHER conn's) releases nothing; fork-mid (mm_clone) keeps a shared
 * run alive on the child's claim. */
static void test_phys_d22(void)
{
	struct uml_nt_phys p;
	struct uml_nt_mm parent, child;
	static int connA, connB;
	unsigned long long r;

	mock_reset();
	CHECK(uml_nt_phys_init(&p, 32 * RUN) == 0);

	/* two views of one run: alloc (A's claim) + ref (B's) */
	r = uml_nt_phys_alloc(&p);
	CHECK((long long)r >= 0);
	CHECK(uml_nt_phys_ref(&p, r) == 2);

	/* B drops first: refs 1 — no park, no free */
	uml_nt_phys_set_drop_owner(&p, &connB);
	CHECK(uml_nt_phys_unref(&p, r) == 1);
	CHECK(uml_nt_phys_parked(&p) == 0);
	CHECK(mock_taken[0]);

	/* A drops last: refs 0 — PARKED, the backend block stays
	 * claimed and the allocator cannot hand IT out (the mis-
	 * ordered drop must not free); other blocks are unaffected */
	uml_nt_phys_set_drop_owner(&p, &connA);
	CHECK(uml_nt_phys_unref(&p, r) == 0);
	CHECK(uml_nt_phys_parked(&p) == 1);
	CHECK(mock_taken[0]);
	{
		unsigned long long other =
			(unsigned long long)uml_nt_phys_alloc(&p);

		CHECK(other != r);
		uml_nt_phys_set_drop_owner(&p, (const void *)0);
		CHECK(uml_nt_phys_unref(&p, (long long)other) == 0);
	}

	/* the WRONG owner's settle releases nothing */
	uml_nt_phys_settle(&p, &connB);
	CHECK(uml_nt_phys_parked(&p) == 1);
	CHECK(mock_taken[0]);

	/* the owner's settle frees; the block is reusable again */
	uml_nt_phys_settle(&p, &connA);
	CHECK(uml_nt_phys_parked(&p) == 0);
	CHECK(!mock_taken[0]);
	CHECK((unsigned long long)uml_nt_phys_alloc(&p) == r);

	/* fork giữa chừng: the shared run survives both drops on the
	 * child's own claim; the last drop parks under ITS OWN conn
	 * (mm_drop_for names the dropper — M5.6a: the teardown never
	 * touches the table-global tag) */
	mock_reset();
	CHECK(uml_nt_phys_init(&p, 32 * RUN) == 0);
	uml_nt_mm_init(&parent);
	r = uml_nt_phys_alloc_span(&p, 2); /* the VMA backs 2 runs */
	CHECK((long long)r >= 0);
	CHECK(uml_nt_vma_add(&parent, RAM, RAM + 2 * RUN, r,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_clone(&child, &parent, &p, 0) == 0);
	CHECK(uml_nt_phys_refs(&p, r) == 2);

	uml_nt_mm_drop_for(&parent, &p, &connA);
	CHECK(uml_nt_phys_refs(&p, r) == 1);
	CHECK(mock_taken[0]);

	uml_nt_mm_drop_for(&child, &p, &connB);
	CHECK(uml_nt_phys_parked(&p) == 1);
	CHECK(mock_taken[0]);

	/* the WRONG owner's settle frees nothing of B's park */
	uml_nt_phys_settle(&p, &connA);
	CHECK(uml_nt_phys_parked(&p) == 1);
	CHECK(mock_taken[0]);

	uml_nt_phys_settle(&p, &connB);
	CHECK(!mock_taken[0]);
	CHECK(uml_nt_phys_parked(&p) == 0);

	/* M5.6a regression (runs 36984940632 + 36987612985): a live
	 * conn's drop inside ANOTHER conn's teardown window parks
	 * under the LIVE conn — the dying conn's settle must not
	 * free it. unref_for ignores the table-global tag entirely
	 * (the old bug: the teardown overwrote the shared table's
	 * tag and its settle freed live conns' blocks with their
	 * UNMAP ops still pending — the free-while-mapped alias
	 * reborn). */
	mock_reset();
	CHECK(uml_nt_phys_init(&p, 32 * RUN) == 0);
	r = uml_nt_phys_alloc(&p); /* the LIVE conn's block */
	CHECK((long long)r >= 0);

	uml_nt_phys_set_drop_owner(&p, &connA); /* stale teardown tag */
	CHECK(uml_nt_phys_unref_for(&p, (long long)r, &connB) == 0);
	CHECK(uml_nt_phys_parked(&p) == 1);
	CHECK(mock_taken[0]);

	uml_nt_phys_settle(&p, &connA);      /* the teardown's settle */
	CHECK(uml_nt_phys_parked(&p) == 1);  /* B's park SURVIVES it */
	CHECK(mock_taken[0]);

	uml_nt_phys_settle(&p, &connB);      /* B's own round settle */
	CHECK(uml_nt_phys_parked(&p) == 0);
	CHECK(!mock_taken[0]);
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

/* 048: the translate boundary is the PHYSMEM WINDOW, not the guest
 * VA base — a rotten VMA (freed-then-reused mm) whose run_off lands
 * between the section end and the VA base must refuse, not inject. */
static void test_translate_boundary(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	unsigned long long r0, saved;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 8 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	saved = uml_nt_vma_phys_limit;
	/* window tight INSIDE the VMA: limit = mid-span, so the
	 * boundary (not the VMA-end rule) is what refuses */
	uml_nt_vma_phys_limit = r0 + RUN + 0x1000;

	/* below the boundary: fine */
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN, 0x800) ==
	      (long long)(r0 + RUN));
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN + 0x800, 0x800) ==
	      (long long)(r0 + RUN + 0x800));
	/* AT the boundary: refused — and this offset is ~1 MB, far
	 * below the VA base: the e938b68 bound let it THROUGH */
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN + 0x1000, 0x800) == -1);
	CHECK(uml_nt_vma_translate(&mm, RAM + 2 * RUN - 1, 1) == -1);

	/* the rotten run_off classes: a VMA whose base itself sits
	 * at/above the window (kernel-slab-shaped garbage below the
	 * VA base, and the absolute-VA shape as a bonus) */
	mm.vma[0].run_off = r0 + RUN + 0x1000;
	CHECK(uml_nt_vma_translate(&mm, RAM, 1) == -1);
	mm.vma[0].run_off = UML_NT_GUEST_VA_BASE - RUN;
	CHECK(uml_nt_vma_translate(&mm, RAM, 1) == -1);
	mm.vma[0].run_off = UML_NT_GUEST_VA_BASE;
	CHECK(uml_nt_vma_translate(&mm, RAM, 1) == -1);

	/* restore: the same VA translates again (no sticky state) */
	mm.vma[0].run_off = r0;
	uml_nt_vma_phys_limit = saved;
	CHECK(uml_nt_vma_translate(&mm, RAM + 0x1234, 8) ==
	      (long long)(r0 + 0x1234));
}

/* map 049: a vma_del CUT must keep translate continuity for the
 * survivor pieces — a piece's run_off keys off ITS OWN start, so a
 * head cut shifts the survivor's run base by the cut size and a
 * middle hole shifts the post piece. Both were latent (sys_munmap
 * refuses partial cuts; MAP_FIXED replace pre-checks span_fits) —
 * the same run_off-keying mistake cow_split's post piece made
 * (5c2f8d7). */
static void test_vma_del_pieces(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	unsigned long long r0;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 8 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + 4 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	/* head cut [RAM, RAM+RUN): survivor [RAM+RUN, RAM+4*RUN) must
	 * translate EXACTLY like the original VMA did */
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN + 0x1234, 8) ==
	      (long long)(r0 + RUN + 0x1234));
	CHECK(uml_nt_vma_del(&mm, RAM, RAM + RUN) == 0);
	CHECK(mm.nvma == 1 && mm.vma[0].start == RAM + RUN);
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN + 0x1234, 8) ==
	      (long long)(r0 + RUN + 0x1234));

	/* middle hole [RAM+2*RUN, RAM+3*RUN) in the survivor: the post
	 * piece [RAM+3*RUN, RAM+4*RUN) keeps the original mapping */
	CHECK(uml_nt_vma_translate(&mm, RAM + 3 * RUN + 0x1234, 8) ==
	      (long long)(r0 + 3 * RUN + 0x1234));
	CHECK(uml_nt_vma_del(&mm, RAM + 2 * RUN,
			     RAM + 3 * RUN) == 0);
	CHECK(mm.nvma == 2);
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN + 0x1234, 8) ==
	      (long long)(r0 + RUN + 0x1234));
	CHECK(uml_nt_vma_translate(&mm, RAM + 3 * RUN + 0x1234, 8) ==
	      (long long)(r0 + 3 * RUN + 0x1234));
	/* the hole is unmapped */
	CHECK(uml_nt_vma_translate(&mm, RAM + 2 * RUN, 1) == -1);

	/* tail cut: the head survivor's run_off is untouched (the
	 * original correct case) */
	CHECK(uml_nt_vma_del(&mm, RAM + 3 * RUN + 0x8000,
			     RAM + 4 * RUN) == 0);
	CHECK(mm.nvma == 2);
	CHECK(uml_nt_vma_translate(&mm, RAM + RUN + 0x1234, 8) ==
	      (long long)(r0 + RUN + 0x1234));
	/* the post survivor keeps [3*RUN, 3*RUN+0x8000): its first
	 * byte translates, the cut tail is unmapped */
	CHECK(uml_nt_vma_translate(&mm, RAM + 3 * RUN, 1) ==
	      (long long)(r0 + 3 * RUN));
	CHECK(uml_nt_vma_translate(&mm, RAM + 3 * RUN + 0x8000, 1) == -1);
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

	/* cow_split MIDDLE run of a 3-run VMA: BOTH flank pieces
	 * exist. The post piece's run_off is ITS OWN base within the
	 * shared block — translate/refcount/mm_drop all key off it.
	 * The block base here made a forked child's drop unref the
	 * parent's faulting run to 0 (the next fork died
	 * shared-run-refs-zero, run 36782313512 — no test caught it:
	 * the 2-run case above never produces a post piece). */
	mock_reset();
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	r0 = uml_nt_phys_alloc_span(&ph, 3);  /* one block, runs 0..2 */
	CHECK(r0 == MOCK_BASE);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2); /* a sharer joins */
	CHECK(uml_nt_phys_ref(&ph, r0 + RUN) == 2);
	CHECK(uml_nt_phys_ref(&ph, r0 + 2 * RUN) == 2);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + 3 * RUN, r0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	{
		unsigned long long new_run = uml_nt_phys_alloc_span(&ph, 1);

		/* the mock's 3-run span rides a 4-run block — the next
		 * handout starts after the padding */
		CHECK(new_run == r0 + 4 * RUN);
		v = uml_nt_vma_find(&a, RAM + RUN + 0x8000);
		CHECK(v != 0);
		CHECK(uml_nt_vma_cow_split(&a, &ph, v, RAM + RUN + 0x8000,
					   new_run) == 0);
		CHECK(a.nvma == 3);
		/* pre: [RAM, RAM+RUN) at the block base, COW kept */
		v = uml_nt_vma_find(&a, RAM + 0x8000);
		CHECK(v != 0 && v->run_off == (unsigned long long)r0 &&
		      v->end == RAM + RUN &&
		      (v->flags & UML_NT_VMA_COW));
		/* middle: private, COW cleared */
		v = uml_nt_vma_find(&a, RAM + RUN + 0x8000);
		CHECK(v != 0 && v->run_off == (unsigned long long)new_run &&
		      !(v->flags & UML_NT_VMA_COW));
		/* post: [RAM+2RUN, RAM+3RUN) at ITS OWN base — the fix */
		v = uml_nt_vma_find(&a, RAM + 2 * RUN + 0x8000);
		CHECK(v != 0 && v->start == RAM + 2 * RUN &&
		      v->run_off == (unsigned long long)(r0 + 2 * RUN) &&
		      (v->flags & UML_NT_VMA_COW));
		/* translate continuity: each piece maps to the ORIGINAL
		 * physical runs (this is the assertion the old code
		 * failed — the post piece translated to the block base) */
		CHECK(uml_nt_vma_translate(&a, RAM + 2 * RUN, 0) ==
		      (long long)(r0 + 2 * RUN));
		CHECK(uml_nt_vma_translate(&a, RAM + 3 * RUN - 1, 0) ==
		      (long long)(r0 + 3 * RUN - 1));
		/* refs: the faulting run's claim moved to new_run, the
		 * flanks keep theirs (this mm + the sharer) */
		CHECK(uml_nt_phys_refs(&ph, r0) == 2);
		CHECK(uml_nt_phys_refs(&ph, r0 + RUN) == 1);
		CHECK(uml_nt_phys_refs(&ph, r0 + 2 * RUN) == 2);
		CHECK(uml_nt_phys_refs(&ph, new_run) == 1);
		/* the drop must unref each run ONCE — the sharer's
		 * claims survive everywhere; the faulting run keeps
		 * the sharer's claim (this mm's moved to new_run) */
		uml_nt_mm_drop(&a, &ph);
		CHECK(uml_nt_phys_refs(&ph, r0) == 1);
		CHECK(uml_nt_phys_refs(&ph, r0 + RUN) == 1);
		CHECK(uml_nt_phys_refs(&ph, r0 + 2 * RUN) == 1);
		CHECK(uml_nt_phys_refs(&ph, new_run) == 0);
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

	/* COW-BREAK AUDIT (M5.6a): the plan above maps shared runs
	 * READ-ONLY (the effective-prot contract) — the audit stays
	 * at 0. A WRITABLE view over a SHARED run = the heap-trasher
	 * class (the write skips the COW fault and eats the sharer's
	 * heap: cowwatch 37014552047/37017936382 — the fork child's
	 * own malloc init at nr=56/clone). The audit counts it and
	 * records the first offender. */
	CHECK(uml_nt_cowbreak_audit_count == 0);
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	r0 = uml_nt_phys_alloc(&ph);
	CHECK(r0 >= 0);
	CHECK(uml_nt_phys_ref(&ph, r0) == 2);   /* shared: two contexts */
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_init_plan(&mm, &ph, &plan) == 0);
	CHECK(uml_nt_cowbreak_audit_count == 1);
	CHECK(uml_nt_cowbreak_va == RAM &&
	      uml_nt_cowbreak_run == (unsigned long long)r0 &&
	      uml_nt_cowbreak_refs == 2);

	/* FAULT-side witness: a write fault on a NON-COW VMA whose run
	 * is shared = the restore-W remap stomps the sharer — the
	 * stomp counted, the recorded identity exact. */
	uml_nt_cowbreak_faults = 0;
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(uml_nt_cowbreak_faults == 1);
	CHECK(uml_nt_cowbreak_va == RAM); /* the PAGE (0x800 is in it) */
	CHECK(uml_nt_cowbreak_run == (unsigned long long)r0);
	CHECK(uml_nt_cowbreak_refs == 2);
	/* and the plan itself = the stomp: a bare PROTECT-W, no copy */
	CHECK(plan.n_ops == 1 &&
	      plan.ops[0].op == UML_NT_FOP_PROTECT &&
	      plan.ops[0].prot == UML_NT_PAGE_READWRITE);
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

/* M3.8 S4c3: MAP_FIXED replace semantics — the stub releases one
 * whole view per UNMAP op, so "replace the range" is only legal
 * when every intersecting VMA lies fully inside it. A flank piece
 * (head/tail cut, container VMA) must refuse loud. */
static void test_span_fits(void)
{
	struct uml_nt_mm mm;

	uml_nt_mm_init(&mm);
	/* empty mm: MAP_FIXED on free space fits */
	CHECK(uml_nt_vma_span_fits(&mm, RAM, RAM + 2 * RUN) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM + 2 * RUN, RAM + 4 * RUN, 0x100000,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	/* the VMA is fully inside the probed range: replace ok */
	CHECK(uml_nt_vma_span_fits(&mm, RAM, RAM + 4 * RUN) == 0);
	/* exact match: ok */
	CHECK(uml_nt_vma_span_fits(&mm, RAM + 2 * RUN, RAM + 4 * RUN)
	      == 0);
	/* disjoint: ok */
	CHECK(uml_nt_vma_span_fits(&mm, RAM + 5 * RUN, RAM + 6 * RUN)
	      == 0);
	/* straddles the START (head cut): refuse */
	CHECK(uml_nt_vma_span_fits(&mm, RAM + 3 * RUN, RAM + 5 * RUN)
	      == -1);
	/* straddles the END (tail cut): refuse */
	CHECK(uml_nt_vma_span_fits(&mm, RAM + 1 * RUN, RAM + 3 * RUN)
	      == -1);
	/* container VMA (range strictly inside it): refuse */
	CHECK(uml_nt_vma_span_fits(&mm, RAM + 2 * RUN + 4,
				   RAM + 4 * RUN - 4) == -1);
}

/* M5.4 c2: the file-backed mmap target decision — FRESH (no VMA in
 * the run-rounded span), INSIDE (whole request in ONE VMA), MIXED
 * (flank overlap — no loader we serve needs it; refuse loud). */
static void test_map_kind(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_vma *v;

	uml_nt_mm_init(&mm);
	CHECK(uml_nt_vma_add(&mm, RAM + RUN, RAM + 3 * RUN, 0x100000,
			     UML_NT_PAGE_EXECUTE_READWRITE,
			     UML_NT_VMA_FILE) == 0);
	/* far away: fresh */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + 6 * RUN, RAM + 7 * RUN, &v)
	      == 0);
	/* 4K-aligned sub-range strictly inside: INSIDE, reports the
	 * VMA (the refill walks its runs) */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + RUN + 0x1000,
				  RAM + 2 * RUN + 0x1000, &v) == 1);
	CHECK(v == uml_nt_vma_find(&mm, RAM + RUN));
	/* exact VMA bounds: INSIDE too */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + RUN, RAM + 3 * RUN, &v)
	      == 1);
	/* head flank (the run-rounded span reaches below the VMA
	 * start): MIXED */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + RUN - 0x1000,
				  RAM + 2 * RUN, &v) == -1);
	/* tail flank: MIXED */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + 2 * RUN, RAM + 3 * RUN + 1,
				  &v) == -1);
	/* the 4K request sits in free space but its RUN-ROUNDED fresh
	 * VMA would flank the neighbour's tail run: MIXED (the
	 * decision uses the run span, not the request) */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + 3 * RUN - 0x1000,
				  RAM + 4 * RUN, &v) == -1);
	/* free again after the VMA's run-rounded end: fresh */
	CHECK(uml_nt_vma_map_kind(&mm, RAM + 4 * RUN, RAM + 5 * RUN, &v)
	      == 0);
}

/* M4 slice 5: sub-run PROT_NONE guards — add/hit/del semantics, fault
 * kill ('g', never auto-repair), clone/drop survival, and guard ops
 * in the INIT plan (the fork child re-arms its inherited guards). */
static void test_guard(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	const unsigned long long g0 = RAM + 0x3000;
	long long heap_off, stack_off;

	mock_reset();
	/* 32 runs: the VMAs below live at run indexes the ph covers;
	 * the runs themselves must be ALLOCATED through this ph (the
	 * ref layer refuses to share unallocated runs). */
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);

	/* misaligned (4K floor) → refuse */
	CHECK(uml_nt_guard_add(&mm, g0 + 0x800, g0 + 0x1800) == -1);
	/* empty range → refuse */
	CHECK(uml_nt_guard_add(&mm, g0, g0) == -1);
	/* the musl shape: one page inside the heap run */
	CHECK(uml_nt_guard_add(&mm, g0, g0 + 0x1000) == 0);
	/* overlap → refuse */
	CHECK(uml_nt_guard_add(&mm, g0 + 0xc00, g0 + 0x1c00) == -1);
	/* disjoint adds ok */
	CHECK(uml_nt_guard_add(&mm, g0 + 0x1000, g0 + 0x2000) == 0);

	CHECK(uml_nt_guard_hit(&mm, g0) == 1);
	CHECK(uml_nt_guard_hit(&mm, g0 + 0xfff) == 1);
	CHECK(uml_nt_guard_hit(&mm, g0 + 0x1000) == 1);
	CHECK(uml_nt_guard_hit(&mm, g0 + 0x2000) == 0); /* beside them */
	CHECK(uml_nt_guard_hit(&mm, g0 - 1) == 0);

	/* fault inside a guard: kill 'g', no repair ops — ANY class */
	{
		heap_off = uml_nt_phys_alloc(&ph);
		CHECK(heap_off > 0);
		CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN,
				     (unsigned long long)heap_off,
				     UML_NT_PAGE_READWRITE, 0) == 0);
		CHECK(uml_nt_vma_find(&mm, g0) != NULL);
		CHECK(uml_nt_mm_fault(&mm, &ph, g0 + 0x40,
				      UML_NT_FAULT_WRITE, &plan) < 0);
		CHECK(plan.kill == 1 && plan.kill_why == 'g');
		CHECK(plan.n_ops == 0);
		CHECK(uml_nt_mm_fault(&mm, &ph, g0 + 0x40,
				      UML_NT_FAULT_READ, &plan) < 0);
		CHECK(plan.kill == 1 && plan.kill_why == 'g');
	}
	/* mprotect RW over ONE guard: it dies (the change wins) */
	CHECK(uml_nt_guard_del_range(&mm, g0, g0 + 0x1000) == 1);
	CHECK(uml_nt_guard_hit(&mm, g0) == 0);
	CHECK(uml_nt_guard_hit(&mm, g0 + 0x1000) == 1);

	/* mmap-replace over the survivor (partial overlap kills too —
	 * an unrecorded NOACCESS region would mis-fault later) */
	CHECK(uml_nt_guard_del_range(&mm, g0 + 0xc00, g0 + 0x1c00) == 1);
	CHECK(uml_nt_guard_hit(&mm, g0 + 0x1000) == 0);

	/* INIT plan: guards emit NOACCESS protects after the maps */
	{
		int i, nmaps;

		stack_off = uml_nt_phys_alloc(&ph);
		CHECK(stack_off > 0);
		CHECK(uml_nt_vma_add(&mm, RAM + 4 * RUN, RAM + 5 * RUN,
				     (unsigned long long)stack_off,
				     UML_NT_PAGE_READWRITE, 0) == 0);
		uml_nt_guard_del_range(&mm, RAM, RAM + 8 * RUN);
		CHECK(uml_nt_guard_add(&mm, g0, g0 + 0x1000) == 0);
		CHECK(uml_nt_mm_init_plan(&mm, &ph, &plan) == 0);
		CHECK(plan.kill == 0 && plan.n_ops == 3);
		nmaps = 0;
		for (i = 0; i < plan.n_ops; i++)
			if (plan.ops[i].op == UML_NT_FOP_MAP)
				nmaps++;
		CHECK(nmaps == 2); /* heap + stack */
		CHECK(plan.ops[2].op == UML_NT_FOP_PROTECT &&
		      plan.ops[2].prot == UML_NT_PAGE_NOACCESS &&
		      plan.ops[2].va == g0 &&
		      plan.ops[2].len == 0x1000);
	}

	/* fork survival: clone copies the guard (the child's stack VMA
	 * eager-copies like a real fork; the heap COWs and the guard
	 * state rides along) */
	{
		struct uml_nt_mm child;

		uml_nt_mm_init(&child);
		CHECK(uml_nt_mm_clone(&child, &mm, &ph,
				      RAM + 5 * RUN) == 0);
		CHECK(child.nguard == 1 &&
		      child.guard[0].start == g0);
		uml_nt_mm_drop(&child, &ph);
		CHECK(child.nguard == 0);
		/* the parent's guards survive the child's drop */
		CHECK(mm.nguard == 1);
	}

	/* table full → -1 */
	{
		int i;

		uml_nt_mm_init(&mm);
		for (i = 0; i < UML_NT_GUARD_MAX; i++)
			CHECK(uml_nt_guard_add(&mm,
			       RAM + 0x1000ull * (unsigned long long)i,
			       RAM + 0x1000ull * (unsigned long long)i +
			       0x1000) == 0);
		CHECK(uml_nt_guard_add(&mm,
		       RAM + 0x1000ull * UML_NT_GUARD_MAX,
		       RAM + 0x1000ull * UML_NT_GUARD_MAX + 0x1000) == -1);
	}
}

/* map 049 item 2: a fault on a STOLEN run (live VMA, refs==0) kills
 * 'z' — every repair would read/write foreign bytes. */
static void test_fault_stolen(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_fault_plan plan;
	unsigned long long run;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	run = uml_nt_phys_alloc(&ph);
	CHECK(run == MOCK_BASE); /* the mock never hands the head */
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, run,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	CHECK(uml_nt_phys_unref(&ph, (long long)run) == 0); /* the theft */
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x1234, UML_NT_FAULT_WRITE,
			      &plan) < 0);
	CHECK(plan.kill == 1 && plan.kill_why == 'z');
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x1234, UML_NT_FAULT_READ,
			      &plan) < 0);
	CHECK(plan.kill == 1 && plan.kill_why == 'z');

	/* the INIT plan refuses to map the stolen VMA (why='z') */
	CHECK(uml_nt_mm_init_plan(&mm, &ph, &plan) == -1);
	CHECK(plan.kill_why == 'z');
}

/* c00000fd fix (archive 065): the VEH dispatch window re-assert —
 * [rsp - GROW_AHEAD, rsp-page-end) clamped into the writable VMA
 * holding rsp-1, guards excluded, EFFECTIVE prot (COW-shared stays
 * read-only), stolen (refs==0) refused. */
static void test_stack_window(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_fault_op win[8];
	unsigned long long run;

	/* deep rsp near the BOTTOM of a 1-run stack VMA: one merged
	 * RW op, the window clamped at the VMA start */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	run = uml_nt_phys_alloc(&ph);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, run,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_stack_window_plan(&mm, &ph, RAM + 0x3028,
				       win, 8) == 1);
	CHECK(win[0].op == UML_NT_FOP_PROTECT);
	CHECK(win[0].prot == UML_NT_PAGE_READWRITE);
	CHECK(win[0].va == RAM);
	CHECK(win[0].va + win[0].len == RAM + 0x4000);

	/* mid-stack rsp: full 5-page window [rsp-16K, rsp-page-end) */
	CHECK(uml_nt_stack_window_plan(&mm, &ph, RAM + 0x6028,
				       win, 8) == 1);
	CHECK(win[0].va == RAM + 0x2000);
	CHECK(win[0].va + win[0].len == RAM + 0x7000);

	/* rsp at the very top byte: the page holding rsp-1 is the
	 * window's top page */
	CHECK(uml_nt_stack_window_plan(&mm, &ph, RAM + RUN,
				       win, 8) == 1);
	CHECK(win[0].va == RAM + RUN - 0x4000);
	CHECK(win[0].va + win[0].len == RAM + RUN);

	/* a guard inside the window splits it and keeps its NOACCESS
	 * range untouched (prot semantics = the fault truth) */
	CHECK(uml_nt_guard_add(&mm, RAM + 0x4000, RAM + 0x5000) == 0);
	CHECK(uml_nt_stack_window_plan(&mm, &ph, RAM + 0x6028,
				       win, 8) == 2);
	CHECK(win[0].va == RAM + 0x2000 && win[0].len == 0x2000);
	CHECK(win[0].prot == UML_NT_PAGE_READWRITE);
	CHECK(win[1].va == RAM + 0x5000 && win[1].len == 0x2000);
	CHECK(win[1].prot == UML_NT_PAGE_READWRITE);
	CHECK(uml_nt_guard_del_range(&mm, RAM + 0x4000, RAM + 0x5000) == 1);

	/* COW-shared run: the assertion carries the EFFECTIVE
	 * (read-only) prot — re-asserting RW would break fork sharing */
	CHECK(uml_nt_phys_ref(&ph, run) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, run,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == -1);
	{
		/* rebuild the mm with the COW flag (the add above
		 * rejected the overlap) */
		struct uml_nt_mm mm2;

		uml_nt_mm_init(&mm2);
		CHECK(uml_nt_vma_add(&mm2, RAM, RAM + RUN, run,
				     UML_NT_PAGE_READWRITE,
				     UML_NT_VMA_COW) == 0);
		CHECK(uml_nt_stack_window_plan(&mm2, &ph, RAM + 0x6028,
					       win, 8) == 1);
		CHECK(win[0].prot == UML_NT_PAGE_READONLY);
	}

	/* no writable VMA at rsp: nothing to assert */
	{
		struct uml_nt_mm mm3;

		uml_nt_mm_init(&mm3);
		CHECK(uml_nt_stack_window_plan(&mm3, &ph, RAM + 0x6028,
					       win, 8) == 0);
	}

	/* read-only VMA at rsp: nothing to assert (not a stack) */
	{
		struct uml_nt_mm mm4;

		uml_nt_mm_init(&mm4);
		CHECK(uml_nt_vma_add(&mm4, RAM, RAM + RUN, run,
				     UML_NT_PAGE_READONLY, 0) == 0);
		CHECK(uml_nt_stack_window_plan(&mm4, &ph, RAM + 0x6028,
					       win, 8) == 0);
	}

	/* stolen window run (refs==0): refused loud (-1) */
	CHECK(uml_nt_phys_unref(&ph, run) == 1);
	CHECK(uml_nt_phys_unref(&ph, run) == 0);
	CHECK(uml_nt_stack_window_plan(&mm, &ph, RAM + 0x6028,
				       win, 8) == -1);

	/* segment overflow: max_ops smaller than the guard-split
	 * segment count → -2 (the caller skips, never truncates) */
	{
		struct uml_nt_mm mm5;

		uml_nt_mm_init(&mm5);
		mock_reset();
		CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
		run = uml_nt_phys_alloc(&ph);
		CHECK(uml_nt_vma_add(&mm5, RAM, RAM + RUN, run,
				     UML_NT_PAGE_READWRITE, 0) == 0);
		CHECK(uml_nt_guard_add(&mm5, RAM + 0x2000, RAM + 0x3000) == 0);
		CHECK(uml_nt_guard_add(&mm5, RAM + 0x4000, RAM + 0x5000) == 0);
		CHECK(uml_nt_guard_add(&mm5, RAM + 0x6000, RAM + 0x7000) == 0);
		/* window [0x4000,0x9000): pages 0x4000(g) 0x5000(f)
		 * 0x6000(g) 0x7000(f) 0x8000(f) → segments
		 * [0x5000,0x6000) + [0x7000,0x9000) = 2 ops */
		CHECK(uml_nt_stack_window_plan(&mm5, &ph, RAM + 0x8028,
					       win, 1) == -2);
		/* and the full answer with a big-enough budget */
		CHECK(uml_nt_stack_window_plan(&mm5, &ph, RAM + 0x8028,
					       win, 8) == 2);
		CHECK(win[0].va == RAM + 0x5000 && win[0].len == 0x1000);
		CHECK(win[1].va == RAM + 0x7000 && win[1].len == 0x2000);
	}
}

/* Shelley-mandated (answer to 093+094, D23 (a)): the parent writes
 * its heap IMMEDIATELY after the clone retval — before ANY round.
 * The clone flagged the parent's view COW (vma.c mm_clone: "upstream
 * fork marks BOTH pte tables read-only"), so the write must take the
 * COW path (a private copy + the RO split pieces), NEVER the
 * private-page restore-W over the shared run (the stomp = the
 * heap-trasher, cowwatch 37014552047/37017936382/37021184517/
 * 37025633434). */
static void test_fork_cow_parent_write(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm parent, child;
	struct uml_nt_fault_plan plan;
	long long r0;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&parent);
	r0 = uml_nt_phys_alloc_span(&ph, 2); /* the heap = 2 runs */
	CHECK(r0 >= 0);
	/* the parent's heap: [RAM, RAM+2RUN) W, not COW yet (a fresh
	 * brk grow) */
	CHECK(uml_nt_vma_add(&parent, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	CHECK(uml_nt_mm_clone(&child, &parent, &ph, 0) == 0);
	CHECK(uml_nt_phys_refs(&ph, r0) == 2);
	CHECK(parent.vma[0].flags & UML_NT_VMA_COW);
	CHECK(child.vma[0].flags & UML_NT_VMA_COW);

	/* THE PARENT WRITES ITS HEAP IMMEDIATELY (no round in
	 * between): the fault must COW-copy, never restore-W over
	 * the shared run. */
	uml_nt_cowbreak_faults = 0;
	CHECK(uml_nt_mm_fault(&parent, &ph, RAM + RUN + 0x800,
			      UML_NT_FAULT_WRITE, &plan) == 0);
	CHECK(!plan.kill);
	CHECK(uml_nt_cowbreak_faults == 0);
	CHECK(plan.copy_src_off == (unsigned long long)r0 + RUN);
	CHECK(plan.copy_dst_off != 0);
	CHECK(uml_nt_phys_refs(&ph, r0 + RUN) == 1);
}

/* WRITER-HUNT (M5.6a): the bulk-fill boundary guard — every run
 * covering [off, off+len) must be live AND owned by the first run's
 * span (a fill spilling into the neighbor block / a dead run is the
 * direct-write heap-trasher class, refused before the write). */
static void test_phys_block_check(void)
{
	struct uml_nt_phys p;
	unsigned long long s, b;

	mock_reset();
	CHECK(uml_nt_phys_init(&p, 32 * RUN) == 0);

	/* 3-run span (mock block = 4 runs: run 3 is padding). */
	s = uml_nt_phys_alloc_span(&p, 3);
	CHECK(s == MOCK_BASE);

	/* in-span: whole span, unaligned mid-run window, tail-only */
	CHECK(uml_nt_phys_block_check(&p, (long long)s, 3 * RUN) == 0);
	CHECK(uml_nt_phys_block_check(&p, (long long)s + 0x10, RUN) == 0);
	CHECK(uml_nt_phys_block_check(&p, (long long)s + 2 * RUN - 8,
				      16) == 0);
	/* zero length is vacuously fine */
	CHECK(uml_nt_phys_block_check(&p, (long long)s, 0) == 0);

	/* out of bounds / dead runs */
	CHECK(uml_nt_phys_block_check(&p, -1, RUN) == -1);
	CHECK(uml_nt_phys_block_check(&p, 0, RUN) == -1); /* head unalloc */
	CHECK(uml_nt_phys_block_check(&p, (long long)s + 3 * RUN,
				      RUN) == -1); /* padding run */
	CHECK(uml_nt_phys_block_check(&p, (long long)s,
				      4 * RUN) == -1); /* into padding */
	CHECK(uml_nt_phys_block_check(&p, (long long)s,
				      32 * RUN) == -1); /* past table */

	/* adjacent span: a fill crossing the span boundary into the
	 * neighbor's LIVE run is refused (the spill catch) */
	b = uml_nt_phys_alloc_span(&p, 1);
	CHECK(b == s + 4 * RUN); /* mock: block padding run 3 held */
	CHECK(uml_nt_phys_block_check(&p, (long long)b, RUN) == 0);
	CHECK(uml_nt_phys_block_check(&p, (long long)s + 2 * RUN,
				      2 * RUN) == -1);
	CHECK(uml_nt_phys_block_check(&p, (long long)b - 8,
				      16) == -1); /* spill from b back */

	/* COW-piece shape: the middle run drops (refs 0), the block
	 * lives on runs 0/2 — a fill over the dead piece refused, the
	 * live tail alone still checks */
	CHECK(uml_nt_phys_unref(&p, (long long)s + RUN) == 0);
	CHECK(uml_nt_phys_block_check(&p, (long long)s,
				      2 * RUN) == -1);
	CHECK(uml_nt_phys_block_check(&p, (long long)s + 2 * RUN,
				      RUN) == 0);

	/* fully-dropped span is dead everywhere */
	CHECK(uml_nt_phys_unref(&p, (long long)s) == 0);
	CHECK(uml_nt_phys_unref(&p, (long long)s + 2 * RUN) == 0);
	CHECK(uml_nt_phys_block_check(&p, (long long)s, RUN) == -1);
}

/* WRITER-HUNT (M5.6a): the drop audit names cross-VMA run aliases —
 * two VMAs of one mm claiming overlapping runs (the double-claim /
 * refs under-count class: mm_drop's unref walk would free the run
 * out from under the survivor VMA). */
static void test_drop_audit(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	unsigned long long r0, r1;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 64 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_mm_drop_audit(&mm) == 0);

	r0 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph);
	r1 = uml_nt_phys_alloc(&ph); /* 2 runs beyond r0: the mock
				      * hands adjacent runs, and vma[0]
				      * below spans [r0, r0+2*RUN) — a
				      * VMA on r1 would be a REAL alias */
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + 2 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_drop_audit(&mm) == 0);

	/* disjoint second VMA: clean */
	CHECK(uml_nt_vma_add(&mm, RAM + 4 * RUN, RAM + 5 * RUN, r1,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_drop_audit(&mm) == 0);

	/* aliased second VMA (stale fork view on the same run block):
	 * the audit names BOTH members of the alias pair */
	CHECK(uml_nt_vma_add(&mm, RAM + 6 * RUN, RAM + 7 * RUN, r0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_drop_audit(&mm) == 2);
}

int main(void)
{
	test_phys();
	test_span();
	test_phys_d22();
	test_fork_cow_parent_write();
	test_phys_block_check();
	test_vma();
	test_vma_del_pieces();
	test_translate();
	test_translate_boundary();
	test_fault();
	test_find_free();
	test_span_runs();
	test_span_fits();
	test_map_kind();
	test_guard();
	test_fault_stolen();
	test_stack_window();
	test_drop_audit();

	if (fails) {
		printf("test_mm: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_mm: all ok\n");
	return 0;
}
