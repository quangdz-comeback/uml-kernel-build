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

/* [alloc-alias] probe (physalloc.h) — NULL in unit tests, pinned by
 * main.c. */
uml_nt_alloc_alias_fn uml_nt_alloc_alias_probe =
	(uml_nt_alloc_alias_fn)0;

/* [zero] hook — pinned by main.c (the flat view), NULL in unit
 * tests (they mock the backend and own no physmem). */
uml_nt_phys_zero_fn uml_nt_phys_zero_hook = (uml_nt_phys_zero_fn)0;

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
		p->gen[i] = 0;
	}
	p->npark = 0;
	p->drop_owner = (const void *)0;
	p->epoch = 0;
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
						  nruns, p->refs[i + k],
						  (const void *)0);
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
	/* [gen] EVERY handout stamps the span's runs with ONE new
	 * epoch (table-global counter, assigned — not bumped — so a
	 * span whose runs carry DIFFERENT recycle histories still
	 * ends up uniform; the per-run bump false-positived on the
	 * span's own tail runs — referee 37109883909: task 1's heap
	 * VMA [0x67c00000,0x67c50000)@0x7200000 vs a tail run whose
	 * first life was younger). A claim recorded against an
	 * earlier epoch = stale translation (walker/funnel refuse);
	 * the first stamp makes every live run's epoch >= 1, so
	 * gen==0 stays the "unchecked claim" sentinel. */
	p->epoch++;
	for (k = 0; k < nruns; k++)
		p->gen[i + k] = p->epoch;
	/* THE ZERO-PAGE CONTRACT (M5.6a — the hunt's endgame): guest
	 * RAM is one pagefile-backed NT section; NtExtendSection does
	 * NOT zero the extension and the run recycling hands a freed
	 * run's bytes to the next owner verbatim. Linux's contract is
	 * that fresh anonymous memory reads as ZERO — glibc relies on
	 * it in writing: _int_calloc skips the memset for the
	 * freshly-sbrked portion of the top chunk ("clear only the
	 * bytes from non-freshly-sbrked memory"), so a recycled heap
	 * tail (a dead process's tcache bins, unit-file text — the
	 * "SYSTEMD_" signature) came back from calloc as LIVE
	 * POINTERS: systemd wrote through them and the arena tore.
	 * Every fresh-memory consumer (brk re-home tail, anon mmap,
	 * eager fork-seed dst, COW split dst) is then individually
	 * wrong; the class fix is the handout: a span leaves the
	 * allocator zeroed, like hardware. refs==0 is proven above,
	 * so the span is dead — zeroing cannot clobber a live owner. */
	if (uml_nt_phys_zero_hook != (uml_nt_phys_zero_fn)0)
		uml_nt_phys_zero_hook(off, nruns);
	/* [alloc-alias]: the table claims these runs were FREE — let
	 * the conn layer name any live VMA that never stopped
	 * translating into them (log-only; the handout stands). */
	if (uml_nt_alloc_alias_probe != (uml_nt_alloc_alias_fn)0)
		uml_nt_alloc_alias_probe(off, nruns);
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
static void block_release(struct uml_nt_phys *p, int o, const void *owner)
{
	int n = p->span_len[o];
	int k;

	uml_nt_phys_backend_free(p->pages[o], n);
	if (uml_nt_phys_event != (uml_nt_phys_event_fn)0)
		uml_nt_phys_event("free",
				  (long long)o * UML_NT_PHYS_RUN_SIZE,
				  n, 0, owner);
	for (k = 0; k < n; k++) {
		p->pages[o + k] = (void *)0;
		p->span_len[o + k] = 0;
		p->span_back[o + k] = 0;
		/* [gen] the released run KEEPS its epoch: while it
		 * sits free the refs==0 guard refuses access; the
		 * epoch moves only at the NEXT handout (the re-hand
		 * = the stale-claim signal). A release bump here
		 * would diverge a span's runs (partial releases of
		 * D12 pieces) — the false-positive class referee
		 * 37109883909 caught. */
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
					  p->park[0].nruns, 0,
					  p->park[0].owner);
		block_release(p,
			      p->park[0].off >> UML_NT_PHYS_RUN_SHIFT,
			      p->park[0].owner);
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
				  n, 0, owner);
}

/* Drop one run to 0 and release its block when the LAST run of the
 * block does (D12: pieces of a COW-split span keep the block alive
 * independently of the owner run). D22, REPAIRED per-conn (M5.6a
 * run 36987612985): a drop inside a dispatch parks under THE
 * DROPPING CONN (its pending plan UNMAP applies with its next
 * reply; its own serve-round settle frees the park after that) —
 * NOT under a table-global tag, which on a SHARED table mis-tagged
 * every sharer's drop inside a teardown window and let the dying
 * conn's settle release live conns' blocks early (the
 * free-while-mapped alias reborn — the heap-trasher ABRT family).
 * conn == NULL (outside any dispatch — no plan ops can be pending)
 * releases immediately. */
int uml_nt_phys_unref_for(struct uml_nt_phys *p, long long off,
			  const void *conn)
{
	int i = run_index(p, off);
	int o, n, k;

	if (i < 0 || p->refs[i] == 0) {
		/* An unbalanced drop (no claim held) is the theft
		 * signal: the LAST legit owner loses the block when
		 * ITS drop lands. Loud through the hook. */
		if (uml_nt_phys_event != (uml_nt_phys_event_fn)0)
			uml_nt_phys_event("unref-refused", off, 1, 0,
					  conn);
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
	if (conn != (const void *)0)
		block_park(p, o, conn);
	else
		block_release(p, o, (const void *)0);
	return 0;
}

int uml_nt_phys_unref(struct uml_nt_phys *p, long long off)
{
	return uml_nt_phys_unref_for(p, off, p->drop_owner);
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
		block_release(p, p->park[i].off >> UML_NT_PHYS_RUN_SHIFT,
			      owner);
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

/* WRITER-HUNT (M5.6a): see physalloc.h. The table is the truth —
 * refs>0 AND span_back continuity AND the span covering the last
 * touched run (padding runs belong to the backend block, not to the
 * span: writing them would be benign content-wise but the checker
 * refuses anyway — a fill that reaches padding is off by definition
 * and the loud failure points at the call site). */
int uml_nt_phys_block_check(const struct uml_nt_phys *p, long long off,
			    unsigned long long len)
{
	int first, last, own, k;

	if (len == 0)
		return 0;
	if (off < 0 || (unsigned long long)off > p->size ||
	    len > p->size - (unsigned long long)off)
		return -1;
	first = (int)(off >> UML_NT_PHYS_RUN_SHIFT);
	last = (int)((off + len - 1) >> UML_NT_PHYS_RUN_SHIFT);
	if (p->refs[first] == 0)
		return -1;
	own = first - (int)p->span_back[first];
	if (own < 0)
		return -1;
	for (k = first; k <= last; k++) {
		if (p->refs[k] == 0 || p->span_back[k] != k - own)
			return -1;
	}
	if (last - own >= (int)p->span_len[own])
		return -1;
	return 0;
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

/* [gen] (M5.6a map 121): the epoch of the run at off's LAST handout
 * — the value a VMA claim recorded at its own handout must still
 * carry. 0 = never handed / bad offset (and the VMA-claim
 * "unchecked" sentinel — a live run's epoch is never 0); a
 * released-but-not-re-handed run KEEPS its epoch (the refs==0
 * guard owns the free state, the epoch owns the re-hand). */
unsigned long long uml_nt_phys_gen(struct uml_nt_phys *p, long long off)
{
	int i = run_index(p, off);

	if (i < 0)
		return 0;
	return p->gen[i];
}
