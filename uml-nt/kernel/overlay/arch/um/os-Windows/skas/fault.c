// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/fault.c — guest page-fault decision (M3.2).
 *
 * VMA-tree driven (vma.h): recoverable faults produce a plan of stub
 * ops; fatal ones (wild pointer, bad access class, RO write, physmem
 * exhaustion) kill loudly — never guess (M1 pitfall 17).
 *
 * Why decide here and not in the caller: the decision is pure logic
 * over the VMA tree — unit-testable on Linux CI without any NT
 * machinery (HANDOFF §8). The caller (kernel dispatch) executes the
 * copy directive in its own flat view, then drives the plan's ops
 * through the stub channel one round-trip each.
 *
 * COW geometry (run-multiple VMAs, vma.h): the VMA spans consecutive
 * runs [run_off, run_off + len). A write-fault on run k copies that
 * run to a fresh one and splits the VMA into pre [s, mid_s) @ span,
 * middle [mid_s, mid_e) @ new run, post [mid_e, e) @ span + (mid_e -
 * s) — every offset stays 64K-aligned.
 */
#include <fault.h>

/* The faulting page's run: VMAs are run multiples (vma.h contract),
 * so run index k = (page - start) / RUN and the shared run's section
 * offset is run_off + k * RUN. */
static unsigned long long page_run_off(const struct uml_nt_vma *vma,
				       unsigned long long page)
{
	return vma->run_off + ((page - vma->start) / UML_NT_PHYS_RUN_SIZE) *
				      UML_NT_PHYS_RUN_SIZE;
}

unsigned uml_nt_vma_effective_prot(const struct uml_nt_vma *vma,
				   struct uml_nt_phys *ph)
{
	if ((vma->flags & UML_NT_VMA_COW) &&
	    uml_nt_phys_refs(ph, (long long)vma->run_off) > 1)
		return uml_nt_prot_readonly(vma->prot);
	return vma->prot;
}

static int plan_op(struct uml_nt_fault_plan *plan, unsigned op, unsigned prot,
		   unsigned long long va, unsigned long long len,
		   unsigned long long off)
{
	if (plan->n_ops >= UML_NT_FAULT_MAX_OPS)
		return -1;
	plan->ops[plan->n_ops].op = op;
	plan->ops[plan->n_ops].prot = prot;
	plan->ops[plan->n_ops].va = va;
	plan->ops[plan->n_ops].len = len;
	plan->ops[plan->n_ops].off = off;
	plan->n_ops++;
	return 0;
}

/* Every goto kill records its reason — the stub_ctl FATAL print
 * reports it (CI triage: 'w' = the VMA was not in the tree, 'p' =
 * prot mismatch, ...). */
#define KILL(w) do { plan->kill_why = (w); goto kill; } while (0)

int uml_nt_mm_fault(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
		    unsigned long long addr, unsigned type,
		    struct uml_nt_fault_plan *plan)
{
	struct uml_nt_vma *vma;
	unsigned long long page;

	plan->kill = 0;
	plan->kill_why = 0;
	plan->n_ops = 0;
	plan->copy_src_off = 0;
	plan->copy_dst_off = 0;

	vma = uml_nt_vma_find(mm, addr);
	if (vma == 0)
		KILL('w'); /* wild pointer — SIGSEGV semantics at M4 */

	page = addr & ~(UML_NT_FAULT_PAGE_SIZE - 1);
	if (page < vma->start || page + UML_NT_FAULT_PAGE_SIZE > vma->end)
		KILL('b'); /* run-multiple VMAs make this unreachable */

	switch (type) {
	case UML_NT_FAULT_READ:
		/* Reads never copy: restore the effective protection.
		 * A read fault on an unreadable VMA is a guest bug —
		 * kill instead of looping. */
		if (!uml_nt_prot_readable(vma->prot))
			KILL('r');
		if (plan_op(plan, UML_NT_FOP_PROTECT,
			    uml_nt_vma_effective_prot(vma, ph), page,
			    UML_NT_FAULT_PAGE_SIZE, 0) < 0)
			KILL('o');
		return 0;

	case UML_NT_FAULT_EXEC:
		/* Executable VMAs carry exec prot; a DEP fault on a
		 * non-exec VMA is a guest bug — kill, don't loop. */
		if (!uml_nt_prot_execable(vma->prot))
			KILL('x');
		if (plan_op(plan, UML_NT_FOP_PROTECT,
			    uml_nt_vma_effective_prot(vma, ph), page,
			    UML_NT_FAULT_PAGE_SIZE, 0) < 0)
			KILL('o');
		return 0;

	case UML_NT_FAULT_WRITE: {
		unsigned long long s, e, span_base, run_start, mid_s, mid_e;
		unsigned long long old_run, new_run;
		unsigned prot;
		int rc;

		if (!uml_nt_prot_writable(vma->prot))
			KILL('p'); /* true RO violation — SIGSEGV at M4 */

		if (!(vma->flags & UML_NT_VMA_COW) ||
		    uml_nt_phys_refs(ph, (long long)page_run_off(vma, page)) <= 1) {
			/* Private page: restore write protection. The
			 * section is fully committed (pagefile-section
			 * analogue of upstream's memfd: untouched pages
			 * read zero) — no alloc needed. */
			if (plan_op(plan, UML_NT_FOP_PROTECT, vma->prot,
				    page, UML_NT_FAULT_PAGE_SIZE, 0) < 0)
				KILL('o');
			return 0;
		}

		/* COW: copy the faulting RUN private, split the VMA at
		 * its run boundaries, remap the pieces. */
		s = vma->start;
		e = vma->end;
		span_base = vma->run_off;
		prot = vma->prot;
		old_run = page_run_off(vma, page);

		new_run = (unsigned long long)uml_nt_phys_alloc(ph);
		if (new_run == (unsigned long long)-1)
			KILL('a'); /* loud: physmem exhausted */
		/* alloc returns the byte offset already (run-aligned) */

		plan->copy_src_off = old_run;
		plan->copy_dst_off = new_run;

		rc = uml_nt_vma_cow_split(mm, ph, vma, page, new_run);
		if (rc < 0) {
			uml_nt_phys_unref(ph, (long long)new_run);
			KILL('s'); /* table full — loud */
		}

		run_start = page & ~(UML_NT_PHYS_RUN_SIZE - 1);
		mid_s = run_start > s ? run_start : s;
		mid_e = run_start + UML_NT_PHYS_RUN_SIZE < e ?
			run_start + UML_NT_PHYS_RUN_SIZE : e;

		if (plan_op(plan, UML_NT_FOP_UNMAP, 0, s, e - s, 0) < 0)
			KILL('o');
		if (mid_s > s &&
		    plan_op(plan, UML_NT_FOP_MAP,
			    uml_nt_prot_readonly(prot), s, mid_s - s,
			    span_base) < 0)
			KILL('o');
		if (plan_op(plan, UML_NT_FOP_MAP, prot, mid_s, mid_e - mid_s,
			    new_run) < 0)
			KILL('o');
		if (mid_e < e &&
		    plan_op(plan, UML_NT_FOP_MAP,
			    uml_nt_prot_readonly(prot), mid_e, e - mid_e,
			    span_base + (mid_e - s)) < 0)
			KILL('o');
		return 0;
	}

	default:
		KILL('?'); /* unknown access class — the NT contract
			    * grew, or the record is garbage */
	}

kill:
	plan->kill = 1;
	plan->n_ops = 0;
	plan->copy_src_off = 0;
	plan->copy_dst_off = 0;
	return -1;
}

int uml_nt_mm_init_plan(const struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			struct uml_nt_fault_plan *plan)
{
	int i;

	plan->kill = 0;
	plan->kill_why = 0;
	plan->n_ops = 0;
	plan->copy_src_off = 0;
	plan->copy_dst_off = 0;

	if (mm->nvma > UML_NT_FAULT_MAX_OPS)
		return -1;
	for (i = 0; i < mm->nvma; i++) {
		const struct uml_nt_vma *v = &mm->vma[i];

		if (plan_op(plan, UML_NT_FOP_MAP,
			    uml_nt_vma_effective_prot(v, ph),
			    v->start, v->end - v->start, v->run_off) < 0)
			return -1;
	}
	return 0;
}
