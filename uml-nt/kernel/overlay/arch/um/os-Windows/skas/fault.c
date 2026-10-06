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

/* COW-BREAK AUDIT globals (fault.h): the init-plan's writable-map-
 * on-shared-run census — see the audit block in uml_nt_mm_init_plan. */
int uml_nt_cowbreak_audit_count;
unsigned long long uml_nt_cowbreak_va, uml_nt_cowbreak_run;
int uml_nt_cowbreak_refs;

/* COW-BREAK FAULT witness (fault.h): the restore-W rounds that hit a
 * SHARED run — the stomp itself (the mm = mid-fault; the caller owns
 * the round identity). */
int uml_nt_cowbreak_faults;
unsigned int uml_nt_cowbreak_prot, uml_nt_cowbreak_flags;

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
 * prot mismatch, 'g' = the sub-run PROT_NONE guard tripped, ...). */
#define KILL(w) do { plan->kill_why = (w); goto kill; } while (0)

/* Re-apply the NOACCESS guards intersecting [s, e) — after any plan
 * that (re)maps a range's pages writable (COW split pieces, the brk
 * span swap): the guard STATE is the fault truth, so the view must
 * match it or the tripwire dies silently. Pieces are run-multiple,
 * guards page-granular: clamp each guard to the piece it rides. */
static int plan_guards(const struct uml_nt_mm *mm,
		       struct uml_nt_fault_plan *plan,
		       unsigned long long s, unsigned long long e)
{
	int i;

	for (i = 0; i < mm->nguard; i++) {
		unsigned long long gs = mm->guard[i].start;
		unsigned long long ge = mm->guard[i].end;

		if (gs >= e || ge <= s)
			continue;
		if (gs < s)
			gs = s;
		if (ge > e)
			ge = e;
		if (plan_op(plan, UML_NT_FOP_PROTECT,
			    UML_NT_PAGE_NOACCESS, gs, ge - gs, 0) < 0)
			return -1;
	}
	return 0;
}

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

	/* The sub-run PROT_NONE guard (M4 slice 5): ANY access inside
	 * one is a guest bug the guard exists to catch — real SIGSEGV
	 * (ACCERR at the delivery), never auto-repair. */
	if (uml_nt_guard_hit(mm, addr))
		KILL('g');

	vma = uml_nt_vma_find(mm, addr);
	if (vma == 0)
		KILL('w'); /* wild pointer — SIGSEGV semantics at M4 */

	page = addr & ~(UML_NT_FAULT_PAGE_SIZE - 1);
	if (page < vma->start || page + UML_NT_FAULT_PAGE_SIZE > vma->end)
		KILL('b'); /* run-multiple VMAs make this unreachable */

	/* Map 049 item 2 — ownership guard: a live VMA whose backing
	 * run shows 0 refs is a STOLEN run (an unbalanced drop freed
	 * it under this mm — the run 0x28b0000 double-claim class).
	 * Every repair below would read/write foreign bytes: kill
	 * loud. The [phys] event lines name the thief. */
	if (uml_nt_phys_refs(ph, (long long)page_run_off(vma, page)) == 0)
		KILL('z');

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
			/* COW-BREAK WITNESS (M5.6a): the private-page
			 * path restores WRITING on the run — legal ONLY
			 * when the run is truly private (refs <= 1). A
			 * non-COW VMA (the flag lost somewhere) on a
			 * SHARED run reaches here and the restore-W
			 * remap hands the sharer's memory to this
			 * guest's writes — the heap-trasher stomp.
			 * Pure file: record for the caller's log. */
			if (uml_nt_phys_refs(ph,
			    (long long)page_run_off(vma, page)) >= 2) {
				uml_nt_cowbreak_faults++;
				uml_nt_cowbreak_va = page;
				uml_nt_cowbreak_run =
					page_run_off(vma, page);
				uml_nt_cowbreak_refs =
					uml_nt_phys_refs(ph,
					    (long long)
					    page_run_off(vma, page));
				uml_nt_cowbreak_prot = vma->prot;
				uml_nt_cowbreak_flags = vma->flags;
			}
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
		if (plan_guards(mm, plan, s, e) < 0)
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

int uml_nt_stack_window_plan(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			     unsigned long long rsp,
			     struct uml_nt_fault_op *ops, int max_ops)
{
	struct uml_nt_vma *vma;
	unsigned long long lo, hi, cur, run;
	unsigned prot;
	int n = 0;

	/* The stack VMA owns [start, rsp) — find it by rsp-1, the last
	 * stack byte (M3.3 lesson: a naive "contains rsp" test puts
	 * the fork rsp into the guard run). */
	if (rsp < 2)
		return 0;
	vma = uml_nt_vma_find(mm, rsp - 1);
	if (vma == 0 || !uml_nt_prot_writable(vma->prot))
		return 0;

	/* Effective prot: a COW-shared stack run re-asserts READ-ONLY
	 * (fork semantics — the first write must fault into the COW
	 * machinery); the M3.3 eager stack copy makes this the
	 * non-case for the rsp VMA at fork time, so a RO assertion
	 * here is an invariant sighting the caller logs. */
	prot = uml_nt_vma_effective_prot(vma, ph);

	/* The window: GROW_AHEAD below the trap rsp (the dispatch
	 * state + the handler's own frames live there), through the
	 * page containing rsp-1 — clamped into the VMA. */
	lo = (rsp >= UML_NT_STACK_GROW_AHEAD) ?
		rsp - UML_NT_STACK_GROW_AHEAD : 0;
	lo &= ~(UML_NT_FAULT_PAGE_SIZE - 1);
	if (lo < vma->start)
		lo = vma->start;
	hi = ((rsp - 1) & ~(UML_NT_FAULT_PAGE_SIZE - 1)) +
		UML_NT_FAULT_PAGE_SIZE;
	if (hi > vma->end)
		hi = vma->end;
	if (lo >= hi)
		return 0;

	/* Map-049 ownership: every run the window touches must show
	 * refs > 0 — a PROTECT op would not read/write bytes, but a
	 * zero-ref window is exactly the stolen-run shape (an
	 * unbalanced drop freed the backing under a live mm). */
	for (run = vma->run_off + ((lo - vma->start) /
				   UML_NT_PHYS_RUN_SIZE) *
			  UML_NT_PHYS_RUN_SIZE;
	     run < vma->run_off + (hi - vma->start);
	     run += UML_NT_PHYS_RUN_SIZE) {
		if (uml_nt_phys_refs(ph, (long long)run) == 0)
			return -1;
	}

	/* Emit the guard-free segments as merged PROTECT ops (guards
	 * keep their NOACCESS: the guard state is the fault truth, the
	 * view must match it — vma.h note; the decider's own
	 * plan_guards re-apply runs after these in the COW plans). */
	for (cur = lo; cur < hi;) {
		unsigned long long seg_end = cur + UML_NT_FAULT_PAGE_SIZE;

		if (uml_nt_guard_hit(mm, cur)) {
			cur = seg_end;
			continue;
		}
		while (seg_end < hi && !uml_nt_guard_hit(mm, seg_end))
			seg_end += UML_NT_FAULT_PAGE_SIZE;
		if (n < max_ops) {
			ops[n].op = UML_NT_FOP_PROTECT;
			ops[n].prot = prot;
			ops[n].va = cur;
			ops[n].len = seg_end - cur;
			ops[n].off = 0;
		}
		n++;
		cur = seg_end;
	}
	return (n > max_ops) ? -2 : n;
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

	if (mm->nvma > UML_NT_FAULT_MAX_OPS ||
	    mm->nvma + mm->nguard > UML_NT_FAULT_MAX_OPS)
		return -1;
	for (i = 0; i < mm->nvma; i++) {
		const struct uml_nt_vma *v = &mm->vma[i];

		/* Map 049 item 2: refuse to map a VMA whose run the
		 * table no longer counts (stolen at an unbalanced
		 * drop) — the child would boot on foreign bytes.
		 * kill_why='z' for the caller's log. */
		if (uml_nt_phys_refs(ph, (long long)v->run_off) == 0) {
			plan->kill_why = 'z';
			return -1;
		}
		if (plan_op(plan, UML_NT_FOP_MAP,
			    uml_nt_vma_effective_prot(v, ph),
			    v->start, v->end - v->start, v->run_off) < 0)
			return -1;
	}
	/* COW-BREAK AUDIT (M5.6a, cowwatch 37014552047/37017936382):
	 * the writer = a fork child WRITING ITS OWN heap at nr=56
	 * (clone) through ITS OWN mapping — the run was SHARED
	 * (refs>=2) and the child's view was mapped WRITABLE: the
	 * write skipped the COW fault and ate the sharer's heap
	 * (the deterministic fd=0x1a bk=0x8000 = the same malloc
	 * arena field at the same heap VA every process gets).
	 * Audit the emitted MAP ops: writable + shared = the break,
	 * recorded for the caller's log (pure file: no os_info). */
	{
		int ai;

		uml_nt_cowbreak_audit_count = 0;
		for (ai = 0; ai < plan->n_ops; ai++) {
			struct uml_nt_fault_op *ao = &plan->ops[ai];

			if (ao->op != UML_NT_FOP_MAP ||
			    !uml_nt_prot_writable(ao->prot))
				continue;
			if (uml_nt_phys_refs(ph,
				    (long long)ao->off) < 2)
				continue;
			if (uml_nt_cowbreak_audit_count == 0) {
				uml_nt_cowbreak_va = ao->va;
				uml_nt_cowbreak_run = ao->off;
				uml_nt_cowbreak_refs =
					uml_nt_phys_refs(ph,
					    (long long)ao->off);
			}
			uml_nt_cowbreak_audit_count++;
		}
	}
	/* The fork child inherits the parent's guards (vma.h): the
	 * fresh views come up at the VMA prots — re-apply NOACCESS so
	 * the tripwires survive the clone. */
	if (plan_guards(mm, plan, 0, ~0ull) < 0)
		return -1;
	return 0;
}

/* ---- M5.6a root-cause fix: the table<->view swap window airtight --
 *
 * dl18 (37512134759, [tcekey] verdict MATCH) named the tear's
 * formation class: stores a guest issued in the run-migration window
 * land in a backing the VMA table no longer owns — the run-granular
 * lost-update (a tcache_put's two CHUNK-side stores vanished while
 * its two STRUCT-side stores landed, the loss straddling the piece
 * boundary). The stub's views are built ONLY by plan ops streaming
 * from the table, so that window is exactly "a view op that does not
 * match the table": an op silently DROPPED by a full plan (the K3
 * uaccess-fixup precedent, referee 37137513174: "a plan overflow
 * AFTER the copy+split left the stub's view stranded on the OLD
 * run"), a view STRANDED by the one-UNMAP-multi-view munmap geometry
 * (UnmapViewOfFile releases the WHOLE view at map_va — one op for a
 * multi-VMA range left every later VMA's view alive over dropped,
 * recycled runs), or a STALE op issued after the table moved under
 * it. The three pure helpers below are the fix's protocol core
 * (host-tested in test_mm.c): reserve the capacity BEFORE the table
 * moves, enumerate the COMPLETE view-release set, and guard every
 * MAP at apply time against the table's current truth. */
int uml_nt_fault_plan_reserve(const struct uml_nt_fault_plan *plan,
			      int need)
{
	if (plan == (const struct uml_nt_fault_plan *)0 || need < 0)
		return -1;
	if (plan->n_ops + need > UML_NT_FAULT_MAX_OPS)
		return -1;
	return 0;
}

int uml_nt_fault_op_backed(const struct uml_nt_fault_op *op,
			   const struct uml_nt_mm *mm)
{
	long long lo, hi;

	if (op == (const struct uml_nt_fault_op *)0 ||
	    mm == (const struct uml_nt_mm *)0)
		return 0;
	if (op->op != UML_NT_FOP_MAP)
		return 1; /* PROTECT/UNMAP carry no backing claim */
	if (op->len < 8)
		return 0;
	/* Both endpoints: a MAP op's range is always exactly one
	 * VMA (every producer pairs it with its own vma_add /
	 * cow_split piece), so the first and last qword must both
	 * translate to the op's own span. A table that moved under
	 * the op (re-home, munmap, a later fixup) breaks one of the
	 * two — the refused-op signal. */
	lo = uml_nt_vma_translate(mm, op->va, 8);
	if (lo < 0)
		return 0;
	hi = uml_nt_vma_translate(mm, op->va + op->len - 8, 8);
	if (hi < 0)
		return 0;
	return (unsigned long long)lo == op->off &&
	       (unsigned long long)hi == op->off + op->len - 8;
}

int uml_nt_fault_munmap_views(const struct uml_nt_mm *mm,
			      unsigned long long s, unsigned long long e,
			      struct uml_nt_fault_op *ops, int max)
{
	int i, n = 0;

	if (mm == (const struct uml_nt_mm *)0 || s >= e)
		return 0;
	for (i = 0; i < mm->nvma; i++) {
		unsigned long long vs = mm->vma[i].start;
		unsigned long long ve = mm->vma[i].end;

		if (vs >= e || ve <= s)
			continue; /* disjoint */
		if (vs < s || ve > e)
			return -2; /* partial VMA — whole views only */
		if (n >= max)
			return -1;
		if (ops != (struct uml_nt_fault_op *)0) {
			ops[n].op = UML_NT_FOP_UNMAP;
			ops[n].prot = 0;
			ops[n].va = vs;
			ops[n].len = ve - vs;
			ops[n].off = 0;
		}
		n++;
	}
	return n;
}
