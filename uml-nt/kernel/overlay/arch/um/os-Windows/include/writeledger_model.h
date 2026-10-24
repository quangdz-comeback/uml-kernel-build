/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uml-nt: the kernel->guest write ledger — the pure half.
 *
 * D28 follow-up (Shelley 148, writer identification for the RO text
 * rewrite): the [uawrite] funnel only covers guest->kernel READS; the
 * kernel->guest write path (copy_to_user / clear_user /
 * strncpy_from_user's direction) had no ledger, so a kernel write
 * landing in an image's RO run was invisible. The imgwatch fire
 * names the RUN, not the writer — and the writer may sit in ANOTHER
 * mm (the run was freed/re-handed across processes), so the ledger is
 * keyed by the SECTION RUN OFFSET, the hardware's assembly key, not
 * by VA. The ring keeps the newest 512 writes; the fire scans it for
 * the watched run.
 */
#ifndef UML_NT_WRITELEDGER_MODEL_H
#define UML_NT_WRITELEDGER_MODEL_H

#define UML_NT_WRITELEDGER_N 512

struct uml_nt_write_ent {
	unsigned long long run;	/* section run offset the write landed in */
	unsigned long long va;	/* guest VA the funnel was asked to write */
	unsigned long long len;
	unsigned long long nr;	/* the guest syscall in flight */
};

struct uml_nt_write_ledger {
	struct uml_nt_write_ent e[UML_NT_WRITELEDGER_N];
	unsigned int n;	/* monotonic put count; slot = n % N */
};

static inline void uml_nt_writeledger_init(struct uml_nt_write_ledger *l)
{
	l->n = 0;
}

/* len == 0 touches nothing — never a writer. */
static inline void uml_nt_writeledger_put(struct uml_nt_write_ledger *l,
					  unsigned long long run,
					  unsigned long long va,
					  unsigned long long len,
					  unsigned long long nr)
{
	struct uml_nt_write_ent *e;

	if (len == 0)
		return;
	e = &l->e[l->n % UML_NT_WRITELEDGER_N];
	e->run = run;
	e->va = va;
	e->len = len;
	e->nr = nr;
	l->n++;
}

/* Indices of the ledger entries whose run matches, NEWEST first,
 * capped at max. 0 = no write to this run in the ring. */
static inline int uml_nt_writeledger_find(const struct uml_nt_write_ledger *l,
					  unsigned long long run,
					  int *idx, int max)
{
	unsigned int have = (l->n < UML_NT_WRITELEDGER_N) ?
			    l->n : UML_NT_WRITELEDGER_N;
	unsigned int k;
	int found = 0;

	for (k = 0; k < have && found < max; k++) {
		unsigned int slot = (l->n - 1 - k) %
				    UML_NT_WRITELEDGER_N;

		if (l->e[slot].run == run)
			idx[found++] = (int)slot;
	}
	return found;
}

#endif /* UML_NT_WRITELEDGER_MODEL_H */
