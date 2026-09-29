// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/physalloc.c — guest physical run REFCOUNT layer
 * (M3.2 refcounts, M3.3 backend, M3.4 spans). See physalloc.h for the
 * model. Self-contained by design: compiled as-is by the Linux CI unit
 * test, which mocks the backend hooks.
 */
#include <physalloc.h>

#define RUNS(p) ((int)((p)->size >> UML_NT_PHYS_RUN_SHIFT))

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
		if (p->refs[i + k] != 0)
			goto reject; /* backend double-allocated: loud */
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

/* Drop one run to 0 and free its block when the LAST run of the
 * block does (D12: pieces of a COW-split span keep the block alive
 * independently of the owner run). */
int uml_nt_phys_unref(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);
	int o, n, k;

	if (i < 0 || p->refs[i] == 0)
		return -1;
	if (--p->refs[i] != 0)
		return p->refs[i];

	o = i - p->span_back[i];
	n = p->span_len[o];
	for (k = 0; k < n; k++) {
		if (p->refs[o + k] != 0)
			return 0; /* block still referenced — keep it */
	}
	uml_nt_phys_backend_free(p->pages[o], n);
	for (k = 0; k < n; k++) {
		p->pages[o + k] = (void *)0;
		p->span_len[o + k] = 0;
		p->span_back[o + k] = 0;
	}
	return 0;
}

int uml_nt_phys_refs(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0)
		return -1;
	return p->refs[i];
}
