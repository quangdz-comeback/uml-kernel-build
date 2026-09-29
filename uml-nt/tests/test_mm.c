/* test_mm.c — unit tests for the M3.2 memory core: physalloc (run
 * allocator + COW refcounts), vma (mm/VMA surgery), fault (plan
 * generation). Pure logic, compiled with the overlay files as-is on
 * Linux CI (same pattern as test_scan_patch.c).
 *
 * Ownership model: a run enters use via uml_nt_phys_alloc (refs = 1);
 * sharing bumps it via uml_nt_phys_ref. Refcounts track REFERENCING
 * CONTEXTS (mm's), not VMA pieces — a COW split unrefs the old run.
 *
 * Geometry contract under test (vma.h): VMAs are 64K-run multiples —
 * every COW split keeps MapViewOfFile offsets 64K-aligned.
 */
#include <stdio.h>
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

static void test_phys(void)
{
	struct uml_nt_phys p;

	CHECK(uml_nt_phys_init(&p, 64 * RUN) == 0);
	CHECK(uml_nt_phys_init(&p, (UML_NT_PHYS_MAX_RUNS + 1) *
			       RUN) == -1);

	CHECK(uml_nt_phys_alloc(&p) == 0 * (long long)RUN);
	CHECK(uml_nt_phys_alloc(&p) == 1 * (long long)RUN);
	CHECK(uml_nt_phys_refs(&p, 0) == 1);

	/* sharing: ref an ALLOCATED run */
	CHECK(uml_nt_phys_ref(&p, 0) == 2);
	CHECK(uml_nt_phys_unref(&p, 0) == 1);
	CHECK(uml_nt_phys_unref(&p, 0) == 0);
	CHECK(uml_nt_phys_refs(&p, 0) == 0);
	/* freed run is reusable */
	CHECK(uml_nt_phys_alloc(&p) == 0 * (long long)RUN);

	/* bad handles */
	CHECK(uml_nt_phys_ref(&p, RUN * 1000) == -1);   /* out of range */
	CHECK(uml_nt_phys_ref(&p, 0x1000) == -1);       /* not run-aligned */
	CHECK(uml_nt_phys_unref(&p, 8 * RUN) == -1);    /* free run */
	CHECK(uml_nt_phys_ref(&p, 8 * RUN) == -1);      /* ref a free run */

	/* exhaust: 2 runs taken, 62 left */
	{
		int i;

		for (i = 0; i < 62; i++)
			CHECK(uml_nt_phys_alloc(&p) >= 0);
		CHECK(uml_nt_phys_alloc(&p) == -1);
	}
}

static void test_vma(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm a, b, c;
	struct uml_nt_vma *v;

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

	/* clone: writable VMAs become COW; every run of the span is
	 * reffed (owner alloc'd them); drop releases. */
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0); /* fresh pool */
	CHECK(uml_nt_phys_alloc(&ph) == 0);          /* run 0 */
	CHECK(uml_nt_phys_alloc(&ph) == RUN);        /* run 1 */
	CHECK(uml_nt_vma_add(&a, RAM, RAM + 2 * RUN, 0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_clone(&b, &a, &ph) == 0);
	CHECK(b.nvma == 1);
	CHECK((b.vma[0].flags & UML_NT_VMA_COW) != 0);
	CHECK(uml_nt_phys_refs(&ph, 0) == 2);
	CHECK(uml_nt_phys_refs(&ph, RUN) == 2);
	uml_nt_mm_drop(&b, &ph);
	CHECK(uml_nt_phys_refs(&ph, 0) == 1);
	CHECK(uml_nt_phys_refs(&ph, RUN) == 1);

	/* read-only VMAs do NOT become COW */
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0); /* fresh pool */
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_READONLY, 0) == 0);
	CHECK(uml_nt_mm_clone(&c, &a, &ph) == 0);
	CHECK((c.vma[0].flags & UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_phys_refs(&ph, 0) == 2);
	uml_nt_mm_drop(&c, &ph);
	CHECK(uml_nt_phys_refs(&ph, 0) == 1);

	/* cow_split: fault at RAM+RUN+0x8000 (run k=1 of a 2-run VMA) */
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0); /* fresh pool */
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_phys_alloc(&ph) == RUN);
	CHECK(uml_nt_phys_ref(&ph, 0) == 2);   /* a sharer joins */
	CHECK(uml_nt_phys_ref(&ph, RUN) == 2);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + 2 * RUN, 0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	{
		long long new_run = uml_nt_phys_alloc(&ph);

		CHECK(new_run == 2 * (long long)RUN);
		v = uml_nt_vma_find(&a, RAM + RUN + 0x8000);
		CHECK(v != 0);
		CHECK(uml_nt_vma_cow_split(&a, &ph, v, RAM + RUN + 0x8000,
					   new_run) == 0);
		CHECK(a.nvma == 2);
		/* pre piece: shared run, COW kept */
		v = uml_nt_vma_find(&a, RAM + 0x8000);
		CHECK(v != 0 && v->run_off == 0 &&
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
		CHECK(uml_nt_phys_refs(&ph, 0) == 2);
		CHECK(uml_nt_phys_refs(&ph, RUN) == 1);
		CHECK(uml_nt_phys_refs(&ph, 2 * RUN) == 1);
	}

	/* cow_split of a single-run VMA: no pieces beyond the middle */
	uml_nt_mm_init(&a);
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0); /* fresh pool */
	CHECK(uml_nt_phys_alloc(&ph) == 0);          /* sharer holder */
	CHECK(uml_nt_phys_ref(&ph, 0) == 2);
	CHECK(uml_nt_vma_add(&a, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_phys_alloc(&ph) == RUN);        /* private target */
	v = uml_nt_vma_find(&a, RAM + 0x8000);
	CHECK(v != 0);
	CHECK(uml_nt_vma_cow_split(&a, &ph, v, RAM + 0x8000, RUN) == 0);
	CHECK(a.nvma == 1);
	CHECK(a.vma[0].run_off == RUN &&
	      !(a.vma[0].flags & UML_NT_VMA_COW));
	CHECK(uml_nt_phys_refs(&ph, 0) == 1); /* sharer keeps it */
	CHECK(uml_nt_phys_refs(&ph, RUN) == 1);

	/* protection classification */
	CHECK(uml_nt_prot_writable(UML_NT_PAGE_READWRITE));
	CHECK(uml_nt_prot_writable(UML_NT_PAGE_EXECUTE_READWRITE));
	CHECK(!uml_nt_prot_writable(UML_NT_PAGE_READONLY));
	CHECK(uml_nt_prot_execable(UML_NT_PAGE_EXECUTE_READWRITE));
	CHECK(!uml_nt_prot_execable(UML_NT_PAGE_READWRITE));
	CHECK(uml_nt_prot_readonly(UML_NT_PAGE_READWRITE) == 0x02u);
	CHECK(uml_nt_prot_readonly(UML_NT_PAGE_EXECUTE_READWRITE) == 0x20u);
}

/* Fixture: a 2-run COW-shared VMA [RAM, RAM+2RUN) backed by runs 0
 * and RUN; a second context references both (refs = 2). */
static void fixture(struct uml_nt_phys *ph, struct uml_nt_mm *mm)
{
	CHECK(uml_nt_phys_init(ph, 32 * RUN) == 0);
	uml_nt_mm_init(mm);
	CHECK(uml_nt_phys_alloc(ph) == 0);
	CHECK(uml_nt_phys_alloc(ph) == (long long)RUN);
	CHECK(uml_nt_phys_ref(ph, 0) == 2);   /* the second context */
	CHECK(uml_nt_phys_ref(ph, RUN) == 2);
	CHECK(uml_nt_vma_add(mm, RAM, RAM + 2 * RUN, 0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
}

static void test_fault(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_fault_plan plan;

	/* wild pointer */
	fixture(&ph, &mm);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0xf0000, UML_NT_FAULT_WRITE,
			      &plan) == -1);
	CHECK(plan.kill);

	/* private write fault (unref the sharer): single PROTECT op
	 * with the VMA's own protection */
	fixture(&ph, &mm);
	CHECK(uml_nt_phys_unref(&ph, 0) == 1);
	CHECK(uml_nt_phys_unref(&ph, RUN) == 1);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 1);
	CHECK(plan.ops[0].op == UML_NT_FOP_PROTECT);
	CHECK(plan.ops[0].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.ops[0].va == RAM);

	/* COW write fault on run k=1 (page RAM+RUN+0x8000): unmap the
	 * old view, map pre (readonly), map middle (private RW), copy
	 * directive run RUN -> fresh run 2*RUN (allocated inside the
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
	CHECK(plan.ops[1].off == 0);
	CHECK(plan.ops[2].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[2].va == RAM + RUN &&
	      plan.ops[2].len == RUN);
	CHECK(plan.ops[2].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.ops[2].off == 2 * RUN);
	CHECK(plan.copy_src_off == RUN && plan.copy_dst_off == 2 * RUN);
	/* mm surgery visible: pre stays shared+COW, middle private */
	CHECK(mm.nvma == 2);
	CHECK(mm.vma[0].run_off == 0 && (mm.vma[0].flags & UML_NT_VMA_COW));
	CHECK(mm.vma[1].run_off == 2 * RUN &&
	      !(mm.vma[1].flags & UML_NT_VMA_COW));
	/* refcounts: old run 2 -> 1 (sharer), new run owned */
	CHECK(uml_nt_phys_refs(&ph, RUN) == 1);
	CHECK(uml_nt_phys_refs(&ph, 2 * RUN) == 1);

	/* COW write fault on the FIRST run: no pre piece */
	fixture(&ph, &mm);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x8000, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 3);
	CHECK(plan.ops[0].op == UML_NT_FOP_UNMAP);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[1].va == RAM);       /* middle now */
	CHECK(plan.ops[1].off == 2 * RUN);
	CHECK(plan.ops[2].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[2].va == RAM + RUN); /* post piece */
	CHECK(plan.ops[2].off == RUN);
	CHECK(plan.copy_src_off == 0);

	/* COW on a single-run VMA: UNMAP + MAP only */
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_phys_ref(&ph, 0) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x8000, UML_NT_FAULT_WRITE,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 2);
	CHECK(plan.ops[0].op == UML_NT_FOP_UNMAP);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP &&
	      plan.ops[1].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.copy_src_off == 0 && plan.copy_dst_off == RUN);

	/* write into a read-only VMA: kill (SIGSEGV at M4) */
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_READONLY, 0) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_WRITE,
			      &plan) == -1);
	CHECK(plan.kill);

	/* DEP fault on an executable VMA: restore, no copy */
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_EXECUTE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_EXEC,
			      &plan) == 0);
	CHECK(!plan.kill && plan.n_ops == 1 &&
	      plan.ops[0].prot == UML_NT_PAGE_EXECUTE_READWRITE);

	/* DEP fault on a non-exec VMA: kill */
	CHECK(uml_nt_phys_alloc(&ph) == RUN);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, RUN,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x800, UML_NT_FAULT_EXEC,
			      &plan) == -1);
	CHECK(plan.kill);

	/* read fault restores the EFFECTIVE (readonly while shared)
	 * protection — reads never copy */
	CHECK(uml_nt_phys_init(&ph, 32 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_phys_ref(&ph, 0) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, 0,
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
	CHECK(uml_nt_phys_init(&ph, 1 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_phys_ref(&ph, 0) == 2);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_READWRITE, UML_NT_VMA_COW) == 0);
	CHECK(uml_nt_mm_fault(&mm, &ph, RAM + 0x8000, UML_NT_FAULT_WRITE,
			      &plan) == -1);
	CHECK(plan.kill && plan.n_ops == 0);

	/* mirroring contract: plan ops == stub actions (drift breaks
	 * both sides silently) */
	CHECK(UML_NT_FOP_UNMAP == UML_STUB_ACTION_UNMAP);
	CHECK(UML_NT_FOP_MAP == UML_STUB_ACTION_MAP);
	CHECK(UML_NT_FOP_PROTECT == UML_STUB_ACTION_PROT);
}

int main(void)
{
	test_phys();
	test_vma();
	test_fault();

	if (fails) {
		printf("test_mm: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_mm: all ok\n");
	return 0;
}
