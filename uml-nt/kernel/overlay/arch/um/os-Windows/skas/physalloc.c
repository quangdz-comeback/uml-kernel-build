// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/physalloc.c — guest physical run REFCOUNT layer
 * (M3.2 refcounts, M3.3 backend). See physalloc.h for the model.
 * Self-contained by design: compiled as-is by the Linux CI unit test,
 * which mocks the backend hooks.
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
	}
	return 0;
}

long long uml_nt_phys_alloc(struct uml_nt_phys *p)
{
	void *pg = (void *)0;
	long long off = uml_nt_phys_backend_alloc(&pg);
	int i;

	if (off < 0)
		return -1;
	i = run_index(p, off);
	if (i < 0 || p->refs[i] != 0 || pg == (void *)0) {
		/* Backend handed out an out-of-range, misaligned or
		 * double-allocated run: give it back, fail loud. */
		if (off >= 0)
			uml_nt_phys_backend_free(pg);
		return -1;
	}
	p->refs[i] = 1;
	p->pages[i] = pg;
	return off;
}

int uml_nt_phys_ref(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0 || p->refs[i] == 0)
		return -1;
	return ++p->refs[i];
}

int uml_nt_phys_unref(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0 || p->refs[i] == 0)
		return -1;
	if (--p->refs[i] == 0) {
		uml_nt_phys_backend_free(p->pages[i]);
		p->pages[i] = (void *)0;
	}
	return p->refs[i];
}

int uml_nt_phys_refs(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0)
		return -1;
	return p->refs[i];
}
