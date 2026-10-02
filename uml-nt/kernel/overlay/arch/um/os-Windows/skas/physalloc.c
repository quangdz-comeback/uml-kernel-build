// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/physalloc.c — guest physical run REFCOUNT layer
 * (M3.2 refcounts, M3.3 backend, M3.4 spans, D22 quarantine). See
 * physalloc.h for the model. Self-contained by design: compiled
 * as-is by the Linux CI unit test, which mocks the backend hooks.
 */
#include <physalloc.h>

#define RUNS(p) ((int)((p)->size >> UML_NT_PHYS_RUN_SHIFT))

/* Event hook (physalloc.h) — NULL in unit tests, pinned by main.c. */
uml_nt_phys_event_fn uml_nt_phys_event = (uml_nt_phys_event_fn)0;

static int run_index(struct uml_nt_phys *p, long long off)
{
	long long i;

	if (off < 0 || (off & (UML_NT_PHYS_RUN_SIZE - 1)) != 0)
		return -1;
	i = off >> UML_NT_PHYS_RUN_SHIFT;
	if (i >= RUNS(p))
		return -1;
	return (int)i;
}

int uml_nt_phys_init(struct uml_nt_phys *p, unsigned long long size)
{
	long long i, runs;

	if (size > (unsigned long long)UML_NT_PHYS_MAX_RUNS *
		   UML_NT_PHYS_RUN_SIZE)
		return -1;
	p->size = size;
	runs = (long long)(size >> UML_NT_PHYS_RUN_SHIFT);
	for (i = 0; i < runs; i++) {
		p->refs[i] = 0;
		p->pages[i] = (void *)0;
		p->span_len[i] = 0;
		p->span_back[i] = 0;
	}
	p->npark = 0;
	p->drop_owner = (const void *)0;
	return 0;
}

long long uml_nt_phys_alloc_span(struct uml_nt_phys *p, int nruns)
{
	void *pg = (void *)0;
	long long off;
	long long i;
	int k;

	if (nruns < 1 || nruns > UML_NT_PHYS_MAX_RUNS)
		return -1;
	off = uml_nt_phys_backend_alloc_span(&pg, nruns);
	if (off < 0)
		return -1;
	i = run_index(p, off);
	if (i < 0 || i + nruns > RUNS(p) || pg == (void *)0)
		goto reject;
	for (k = 0; k < nruns; k++) {
		if (p->refs[i + k] != 0) {
			/* Backend double-allocated: loud (the hook is
			 * the ONLY witness — the caller sees -ENOMEM). */
			if (uml_nt_phys_event !=
			    (uml_nt_phys_event_fn)0)
				uml_nt_phys_event("alloc-reject", off,
						  nruns, p->refs[i + k]);
			goto reject; /* backend double-allocated: loud */
		}
	}
	p->refs[i] = 1;
	p->pages[i] = pg;   /* the block's one handle lives on the owner */
	p->span_len[i] = (unsigned short)nruns;
	p->span_back[i] = 0;
	for (k = 1; k < nruns; k++) {
		p->refs[i + k] = 1;
		p->pages[i + k] = (void *)0;
		p->span_len[i + k] = (unsigned short)nruns;
		p->span_back[i + k] = (unsigned short)k;
	}
	return off;

reject:
	/* Give the block back — never leak backend memory on a bad
	 * handout (fail loud at the caller). */
	if (off >= 0)
		uml_nt_phys_backend_free(pg, nruns);
	return -1;
}

long long uml_nt_phys_alloc(struct uml_nt_phys *p)
{
	return uml_nt_phys_alloc_span(p, 1);
}

int uml_nt_phys_ref(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0 || p->refs[i] == 0)
		return -1;
	return ++p->refs[i];
}

/* D22: backend hand-back + table clear, shared by the immediate
 * drop (untagged owner) and the quarantine release (settle/spill). */
static void block_release(struct uml_nt_phys *p, int o)
{
	int n = p->span_len[o];
	int k;

	uml_nt_phys_backend_free(p->pages[o], n);
	if (uml_nt_phys_event != (uml_nt_phys_event_fn)0)
		uml_nt_phys_event("free",
				  (long long)o * UML_NT_PHYS_RUN_SIZE,
				  n, 0);
	for (k = 0; k < n; k++) {
		p->pages[o + k] = (void *)0;
		p->span_len[o + k] = 0;
		p->span_back[o + k] = 0;
	}
}

/* D22 quarantine: park a fully-dropped block for its owner's settle.
 * Ring full = spill the OLDEST entry (bounded memory; a degenerate
 * alias window, loud through the hook). */
static void block_park(struct uml_nt_phys *p, int o, const void *owner)
{
	int n = p->span_len[o];
	int k;

	if (p->npark == UML_NT_PHYS_PARK_MAX) {
		if (uml_nt_phys_event != (uml_nt_phys_event_fn)0)
			uml_nt_phys_event("park-spill",
					  p->park[0].off,
					  p->park[0].nruns, 0);
		block_release(p,
			      p->park[0].off >> UML_NT_PHYS_RUN_SHIFT);
		for (k = 1; k < p->npark; k++)
			p->park[k - 1] = p->park[k];
		p->npark--;
	}
	p->park[p->npark].off = (long long)o * UML_NT_PHYS_RUN_SIZE;
	p->park[p->npark].nruns = n;
	p->park[p->npark].owner = owner;
	p->npark++;
	if (uml_nt_phys_event != (uml_nt_phys_event_fn)0)
		uml_nt_phys_event("park",
				  (long long)o * UML_NT_PHYS_RUN_SIZE,
				  n, 0);
}

/* Drop one run to 0 and release its block when the LAST run of the
 * block does (D12: pieces of a COW-split span keep the block alive
 * independently of the owner run). D22: under a tagged drop-owner the
 * release PARKS — the dropping conn's pending plan UNMAP applies only
 * with its next reply, and a backend hand-back before that could hand
 * the SAME block to another conn's mapping (the free-while-mapped
 * alias). Untagged drops (outside any dispatch — no plan ops can be
 * pending) release immediately, the pre-D22 behavior. */
int uml_nt_phys_unref(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);
	int o, n, k;

	if (i < 0 || p->refs[i] == 0) {
		/* An unbalanced drop (no claim held) is the theft
		 * signal: the LAST legit owner loses the block when
		 * ITS drop lands. Loud through the hook. */
		if (uml_nt_phys_event != (uml_nt_phys_event_fn)0)
			uml_nt_phys_event("unref-refused", off, 1, 0);
		return -1;
	}
	if (--p->refs[i] != 0)
		return p->refs[i];

	o = i - p->span_back[i];
	n = p->span_len[o];
	for (k = 0; k < n; k++) {
		if (p->refs[o + k] != 0)
			return 0; /* block still referenced — keep it */
	}
	if (p->drop_owner != (const void *)0)
		block_park(p, o, p->drop_owner);
	else
		block_release(p, o);
	return 0;
}

void uml_nt_phys_settle(struct uml_nt_phys *p, const void *owner)
{
	int i, k;

	/* block_release keys off the OWNER run index; parks store byte
	 * offsets. Matching entries release in park order; the array
	 * compacts and the loop re-examines the shifted slot. */
	for (i = 0; i < p->npark; i++) {
		if (p->park[i].owner != owner)
			continue;
		block_release(p, p->park[i].off >> UML_NT_PHYS_RUN_SHIFT);
		for (k = i + 1; k < p->npark; k++)
			p->park[k - 1] = p->park[k];
		p->npark--;
		i--;
	}
}

int uml_nt_phys_parked(const struct uml_nt_phys *p)
{
	return p->npark;
}

void uml_nt_phys_set_drop_owner(struct uml_nt_phys *p, const void *owner)
{
	p->drop_owner = owner;
}

int uml_nt_phys_refs(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0)
		return -1;
	return p->refs[i];
}
