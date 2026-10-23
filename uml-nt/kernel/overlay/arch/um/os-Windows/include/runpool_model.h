/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uml-nt: the backend run pool — the pure half.
 *
 * The phys backend hands every run span to the guest's buddy. The
 * exact span trim (5c96823/003dbb8) returns unused tails at RUN_ORDER
 * instead of stranding them, so the shared zone's free lists now mix
 * run-sized blocks with the kernel's own order-0 page cache. Under
 * load (the 13 MiB hwdb.bin mapping, referee 39986213745) order-4
 * handouts failed with 20 MiB free, and the login COW's single-run
 * request at ~5 MiB free killed the stub through the why='a' signal
 * storm (referees 39986204407/39986213745).
 *
 * The pool is a bounded best-fit cache of released run spans kept OUT
 * of the shared buddy until it is needed: the fault path reuses a run
 * without touching a fragmented free list, and the normal allocator's
 * failure path drains the pool back (skas/physbackend.c) so no memory
 * hides from the kernel. The bookkeeping lives here so the host test
 * (tests/test_runpool.c) runs the exact code the kernel ships.
 */
#ifndef UML_NT_RUNPOOL_MODEL_H
#define UML_NT_RUNPOOL_MODEL_H

/* Must equal physalloc.h's UML_NT_PHYS_RUN_SIZE (the test asserts). */
#define UML_NT_RUNPOOL_RUN 0x10000ull
#define UML_NT_RUNPOOL_ENTRIES 64

struct uml_nt_runpool_ent {
	unsigned long long off;
	unsigned int nruns;
};

struct uml_nt_runpool {
	struct uml_nt_runpool_ent ent[UML_NT_RUNPOOL_ENTRIES];
	int n;
	unsigned int runs;
	unsigned int max_runs;
	unsigned int max_entries;
	unsigned long long puts, gets, drains;
};

static inline void uml_nt_runpool_init(struct uml_nt_runpool *p,
				       unsigned int max_runs,
				       unsigned int max_entries)
{
	int i;

	for (i = 0; i < UML_NT_RUNPOOL_ENTRIES; i++)
		p->ent[i] = (struct uml_nt_runpool_ent){ 0, 0 };
	p->n = 0;
	p->runs = 0;
	p->puts = p->gets = p->drains = 0;
	p->max_runs = max_runs;
	if (max_entries > UML_NT_RUNPOOL_ENTRIES)
		max_entries = UML_NT_RUNPOOL_ENTRIES;
	p->max_entries = max_entries;
}

/* Offer a released span. 0 = pooled, -1 = refuse (over budget — the
 * caller must return it to the buddy; a refusal leaves the pool
 * untouched). */
static inline int uml_nt_runpool_put(struct uml_nt_runpool *p,
				     unsigned long long off,
				     unsigned int nruns)
{
	if (nruns == 0 || (off & (UML_NT_RUNPOOL_RUN - 1)) != 0)
		return -1;
	if (p->n >= (int)p->max_entries ||
	    p->runs + nruns > p->max_runs)
		return -1;
	p->ent[p->n].off = off;
	p->ent[p->n].nruns = nruns;
	p->n++;
	p->runs += nruns;
	p->puts++;
	return 0;
}

/* Best fit: the smallest pooled span that covers the ask. A larger
 * entry splits in place (front handed out, remainder stays). -1 when
 * no entry fits — the caller goes to the buddy. */
static inline long long uml_nt_runpool_get(struct uml_nt_runpool *p,
					   unsigned int nruns)
{
	int i, best = -1;
	unsigned int best_nruns = ~0u;
	unsigned long long off;

	if (nruns == 0)
		return -1;
	for (i = 0; i < p->n; i++) {
		if (p->ent[i].nruns >= nruns &&
		    p->ent[i].nruns < best_nruns) {
			best = i;
			best_nruns = p->ent[i].nruns;
		}
	}
	if (best < 0)
		return -1;
	off = p->ent[best].off;
	p->ent[best].off += (unsigned long long)nruns *
			    UML_NT_RUNPOOL_RUN;
	p->ent[best].nruns -= nruns;
	p->runs -= nruns;
	p->gets++;
	if (p->ent[best].nruns == 0) {
		for (i = best + 1; i < p->n; i++)
			p->ent[i - 1] = p->ent[i];
		p->n--;
	}
	return (long long)off;
}

/* Drain path: FIFO pop for the caller to hand back to the buddy. */
static inline int uml_nt_runpool_pop(struct uml_nt_runpool *p,
				     unsigned long long *off,
				     unsigned int *nruns)
{
	int i;

	if (p->n == 0)
		return 0;
	*off = p->ent[0].off;
	*nruns = p->ent[0].nruns;
	p->runs -= p->ent[0].nruns;
	p->drains += p->ent[0].nruns;
	for (i = 1; i < p->n; i++)
		p->ent[i - 1] = p->ent[i];
	p->n--;
	return 1;
}

static inline int uml_nt_runpool_peek(const struct uml_nt_runpool *p, int i,
				      struct uml_nt_runpool_ent *e)
{
	if (i < 0 || i >= p->n)
		return -1;
	*e = p->ent[i];
	return 0;
}

static inline unsigned int uml_nt_runpool_runs(const struct uml_nt_runpool *p)
{
	return p->runs;
}

static inline int uml_nt_runpool_entries(const struct uml_nt_runpool *p)
{
	return p->n;
}

#endif /* UML_NT_RUNPOOL_MODEL_H */
