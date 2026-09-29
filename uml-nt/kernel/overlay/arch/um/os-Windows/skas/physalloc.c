// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/physalloc.c — guest physical run allocator (M3.2).
 * See physalloc.h for the model (64K runs, refcounts for COW).
 * Self-contained by design: compiled as-is by the Linux CI unit test.
 */
#include <physalloc.h>

#define RUNS(p) ((int)((p)->size >> UML_NT_PHYS_RUN_SHIFT))

int uml_nt_phys_init(struct uml_nt_phys *p, unsigned long long size)
{
	long long i, runs;

	if (size > (unsigned long long)UML_NT_PHYS_MAX_RUNS *
		   UML_NT_PHYS_RUN_SIZE)
		return -1;
	p->size = size;
	runs = (long long)(size >> UML_NT_PHYS_RUN_SHIFT);
	for (i = 0; i < runs; i++)
		p->refs[i] = 0;
	return 0;
}

long long uml_nt_phys_alloc(struct uml_nt_phys *p)
{
	int i;

	for (i = 0; i < RUNS(p); i++) {
		if (p->refs[i] == 0) {
			p->refs[i] = 1;
			return (long long)i * (long long)UML_NT_PHYS_RUN_SIZE;
		}
	}
	return -1;
}

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
	return --p->refs[i];
}

int uml_nt_phys_refs(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0)
		return -1;
	return p->refs[i];
}
