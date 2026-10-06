// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/uaccess_walk.c — guest VA walker (D15). See
 * uaccess_walk.h. Self-contained by design: compiled as-is by the
 * Linux CI unit test (with vma.c + physalloc.c).
 *
 * No <string.h>: this file compiles BOTH freestanding in the kernel
 * (no host headers, D1) and in the unit test — the few byte ops are
 * spelled out here.
 */
#include <uaccess_walk.h>

#define UACC_PAGE 0x1000ull
#define UACC_PAGE_OFF(va) ((va) & (UACC_PAGE - 1))
#define UACC_RUN UML_NT_PHYS_RUN_SIZE

static void uacc_bcopy(char *dst, const char *src, unsigned long long n)
{
	while (n--)
		*dst++ = *src++;
}

static void uacc_bzero(char *dst, unsigned long long n)
{
	while (n--)
		*dst++ = 0;
}

static unsigned long long uacc_bstrnlen(const char *s,
					unsigned long long max)
{
	unsigned long long n = 0;

	while (n < max && s[n])
		n++;
	return n;
}

/* The write-fixup channel (see uaccess_walk.h): installed by the
 * syscall dispatch for one handler run. NULL fields = no fixup
 * channel (writes to COW-shared runs fault fail-safe). */
static struct uml_nt_uacc_sink uacc_sink;

unsigned long uml_nt_uacc_fixups;
/* M5.4 c3 (map 057): the last cow-fixup's coordinates (header comment).
 * Recorded at the fixup, logged by the conn layer's counter-delta. */
unsigned long long uml_nt_uacc_fixup_va;
unsigned long long uml_nt_uacc_fixup_page;
unsigned long long uml_nt_uacc_fixup_vma_start;
unsigned long long uml_nt_uacc_fixup_vma_end;
unsigned long long uml_nt_uacc_fixup_old_run;
unsigned long long uml_nt_uacc_fixup_new_run;

/* Sink peeks (see uaccess_walk.h) — the kernel-side EFAULT tracer
 * needs the channel's shape without being able to reach the static
 * state; exposing it through accessors keeps this file the only
 * owner of the static. */
struct uml_nt_phys *uml_nt_uacc_sink_phys(void)
{
	return uacc_sink.ph;
}

const struct uml_nt_fault_plan *uml_nt_uacc_sink_plan(void)
{
	return uacc_sink.plan;
}

/* Refusal telemetry (map 121 follow-up, run 37108542522): the
 * walker refuses SILENTLY (this file is log-free — 8350576), but
 * its refusals surface at the caller as errno, and the errno path
 * was indistinguishable from an fs-side EPERM. Pure globals: the
 * LAST refusal's coordinates + the boot-wide count; the kernel
 * side (uaccess.c, has os_info) logs the line and the conn layer
 * can delta the counter per serve round. */
unsigned long long uml_nt_uacc_refuses;
unsigned long long uml_nt_uacc_refuse_va;
unsigned long long uml_nt_uacc_refuse_claim_gen;
unsigned long long uml_nt_uacc_refuse_run_gen;
unsigned long uml_nt_uacc_refuse_kind; /* 0 = stolen-run refs,
					* 1 = generation mismatch */

struct uml_nt_uacc_sink uml_nt_uacc_set_sink(const struct uml_nt_uacc_sink *s)
{
	struct uml_nt_uacc_sink prev = uacc_sink;

	if (s != (const struct uml_nt_uacc_sink *)0)
		uacc_sink = *s;
	else {
		uacc_sink.ph = (struct uml_nt_phys *)0;
		uacc_sink.plan = (struct uml_nt_fault_plan *)0;
	}
	return prev;
}

/* Queue one stub op into the sink's plan (the dispatch streams ops
 * after the handler, retval parked — D16). -1 on plan overflow. */
static int uacc_plan_op(struct uml_nt_fault_plan *plan, unsigned op,
			unsigned prot, unsigned long long va,
			unsigned long long len, unsigned long long off)
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

/* Map 121 (đáp 122): the shared generation check for EVERY
 * translate site (byte walk, str walk, write ptr). refs==1 only
 * proves SOMEBODY holds the run — a stale VMA whose claim died
 * (freed + re-handed to the new owner, e.g. the heap/tcache) still
 * translates and still passes the refs guard; its access then
 * poisons the new owner's memory (the tcache-entries writer: two
 * independent rounds, nr=3 ret=0 + nr=318 ret=8, referee
 * 37105483388). The claim's recorded life must equal the run's
 * current life; gen==0 = unchecked claim (POC/bench paths keep
 * the old behavior). Returns 1 = STALE (the caller refuses, EFAULT
 * class), 0 = ok / unchecked / no table installed. */
static int uacc_gen_stale(const struct uml_nt_mm *mm,
			  unsigned long long va, unsigned long long off)
{
	struct uml_nt_vma *gv;

	if (uacc_sink.ph == (struct uml_nt_phys *)0)
		return 0; /* no table installed: unchecked */
	gv = uml_nt_vma_find((struct uml_nt_mm *)mm, va);
	if (gv == (struct uml_nt_vma *)0 || gv->gen == 0)
		return 0;
	if (gv->gen == (unsigned long long)
	    uml_nt_phys_gen(uacc_sink.ph,
			    (long long)(off & ~(UACC_RUN - 1))))
		return 0;
	uml_nt_uacc_refuses++;
	uml_nt_uacc_refuse_kind = 1;
	uml_nt_uacc_refuse_va = va;
	uml_nt_uacc_refuse_claim_gen = gv->gen;
	uml_nt_uacc_refuse_run_gen = (unsigned long long)
		uml_nt_phys_gen(uacc_sink.ph,
				(long long)(off & ~(UACC_RUN - 1)));
	return 1;
}

/* The stolen-run guard (map 049 item 2) with the same telemetry —
 * shared by the byte walk and the str walk. Returns 1 = refuse. */
static int uacc_refs_refuse(unsigned long long va,
			    unsigned long long off)
{
	if (uacc_sink.ph == (struct uml_nt_phys *)0 ||
	    uml_nt_phys_refs(uacc_sink.ph,
			     (long long)(off & ~(UACC_RUN - 1))) != 0)
		return 0;
	uml_nt_uacc_refuses++;
	uml_nt_uacc_refuse_kind = 0;
	uml_nt_uacc_refuse_va = va;
	uml_nt_uacc_refuse_claim_gen = 0;
	uml_nt_uacc_refuse_run_gen = (unsigned long long)
		uml_nt_phys_gen(uacc_sink.ph,
				(long long)(off & ~(UACC_RUN - 1)));
	return 1;
}

/* Flat pointer for the byte at `va` after making a kernel WRITE to
 * its page safe (hazard 3, review M3.8). Mirrors the COW branch of
 * uml_nt_mm_fault (fault.c) except the run copy is INLINE (the
 * kernel owns the flat view — the syscall streaming path has no
 * copy-directive step) and the ops queue into the SINK's plan.
 * Returns 0 on fault: wild page, read-only VMA, shared run without
 * a fixup channel, plan overflow, physmem exhaustion. */
char *uml_nt_uacc_write_ptr(const struct uml_nt_mm *mm, char *base,
			    unsigned long long va)
{
	struct uml_nt_vma *vma;
	unsigned long long page, run_start, old_run, new_run, s, e, mid_e,
			   span_base, byte_off;
	unsigned prot;

	page = va & ~(UACC_PAGE - 1);
	vma = uml_nt_vma_find((struct uml_nt_mm *)mm, page);
	if (vma == (struct uml_nt_vma *)0)
		return (char *)0;
	if (page < vma->start || page + UACC_PAGE > vma->end)
		return (char *)0; /* run-multiple VMAs: unreachable */

	/* A write needs a logically writable VMA — COW or not (the
	 * audit's prot check: never write a read-only mapping). */
	if (!uml_nt_prot_writable(vma->prot))
		return (char *)0;

	/* The run CONTAINING the page (VMA start is run-aligned, so
	 * guest run boundaries are page&~RUN-1; the refs table is per
	 * run — its section offset is the span base + the run delta). */
	run_start = page & ~(UACC_RUN - 1);
	old_run = vma->run_off + (run_start - vma->start);
	byte_off = vma->run_off + (va - vma->start);

	/* Map 121: the write funnel's stale-claim guard — the read()
	 * fill lands HERE for non-COW VMAs (direct flat write): a
	 * stale heap VMA over a re-handed run writes the NEW owner's
	 * memory (the tcache-entries writer, referee 37105483388). */
	if (uacc_gen_stale(mm, va, old_run))
		return (char *)0;

	if (!(vma->flags & UML_NT_VMA_COW))
		return base + byte_off; /* never shared: direct */

	/* COW VMA. The refs table is the ground truth (mm_clone marks
	 * BOTH sides; the mark bites only while refs > 1 — the
	 * fork-exited-child case reads writable at refs==1). Never
	 * write blind: no fixup channel (outside a handler) = fail
	 * safe — the shared run must not be written blind. */
	if (uacc_sink.ph == (struct uml_nt_phys *)0)
		return (char *)0;

	/* Last reference = effectively private (upstream fault path:
	 * "private page, restore write protection") — a direct write
	 * is safe; the stub's read-only view doesn't bind the kernel's
	 * flat view, and the guest's own write still faults into the
	 * normal COW machinery. ZERO references = a STOLEN run (an
	 * unbalanced drop freed the backing under this mm — map 049's
	 * run 0x28b0000 class): the buddy may re-home it to the next
	 * alloc, so writing it writes foreign memory. Refuse. */
	{
		int r = uml_nt_phys_refs(uacc_sink.ph,
					 (long long)old_run);

		if (r == 0)
			return (char *)0;
		if (r == 1)
			return base + byte_off;
	}

	if (uacc_sink.plan == (struct uml_nt_fault_plan *)0)
		return (char *)0;

	s = vma->start;
	e = vma->end;
	span_base = vma->run_off;
	prot = vma->prot;

	/* K3 starhost (oracle, referee 37137513174 decode): the ops
	 * below are the VIEW half of the tree move — queueing them is
	 * not optional. A plan overflow AFTER the copy+split left the
	 * stub's view stranded on the OLD run (a byte-identical COW
	 * twin): the guest's later writes landed on the twin while the
	 * table + the flat view said the new run — the half-landed
	 * store set behind the bin-desync aborts ("corrupted
	 * double-linked list" family). All-or-nothing: reserve the
	 * capacity FIRST — a full plan fails the write BEFORE anything
	 * moves (EFAULT at the caller: loud, retriable, never a
	 * stranded view). Op count mirrors the queue below. */
	{
		int need = 2; /* UNMAP + mid MAP */

		if (run_start > s)
			need++;
		if (run_start + UACC_RUN < e)
			need++;
		if (uacc_sink.plan->n_ops + need > UML_NT_FAULT_MAX_OPS)
			return (char *)0;
	}

	new_run = (unsigned long long)uml_nt_phys_alloc(uacc_sink.ph);
	if (new_run == (unsigned long long)-1)
		return (char *)0;
	/* The content copy is INLINE (kernel flat view): fresh run gets
	 * the shared run's bytes, then the caller's write lands on it. */
	uacc_bcopy(base + new_run, base + old_run, UACC_RUN);
	uml_nt_uacc_fixups++; /* the conn layer logs the delta */
	/* M5.4 c3 (map 057): record the fixup's coordinates for the
	 * conn layer's delta log — this file is PURE (no os_info; the
	 * Linux CI unit tests compile it standalone — the implicit
	 * os_info broke D5a run 36855226377). */
	uml_nt_uacc_fixup_va = va;
	uml_nt_uacc_fixup_page = page;
	uml_nt_uacc_fixup_vma_start = vma->start;
	uml_nt_uacc_fixup_vma_end = vma->end;
	uml_nt_uacc_fixup_old_run = old_run;
	uml_nt_uacc_fixup_new_run = new_run;

	if (uml_nt_vma_cow_split((struct uml_nt_mm *)mm, uacc_sink.ph, vma,
				 page, new_run) < 0) {
		uml_nt_phys_unref(uacc_sink.ph, (long long)new_run);
		return (char *)0; /* table full — loud at the caller */
	}

	/* Remap the stub's view: the VMA was ONE view over [s, e) —
	 * unmap it, map the pieces back (pre/post keep the shared run
	 * read-only, the fixed piece maps private writable). Same op
	 * shape as the fault path. */
	if (uacc_plan_op(uacc_sink.plan, UML_NT_FOP_UNMAP, 0, s, e - s,
			 0) < 0)
		return (char *)0;
	if (run_start > s &&
	    uacc_plan_op(uacc_sink.plan, UML_NT_FOP_MAP,
			 uml_nt_prot_readonly(prot), s, run_start - s,
			 span_base) < 0)
		return (char *)0;
	if (uacc_plan_op(uacc_sink.plan, UML_NT_FOP_MAP, prot, run_start,
			 UACC_RUN, new_run) < 0)
		return (char *)0;
	mid_e = run_start + UACC_RUN;
	if (mid_e < e &&
	    uacc_plan_op(uacc_sink.plan, UML_NT_FOP_MAP,
			 uml_nt_prot_readonly(prot), mid_e, e - mid_e,
			 span_base + (mid_e - s)) < 0)
		return (char *)0;

	return base + new_run + (va - run_start);
}

int uml_nt_uacc_walk(const struct uml_nt_mm *mm, char *base,
		     unsigned long long va, unsigned long long len,
		     char *buf, int op)
{
	/* Fail-safe (review M3.8): outside a syscall handler no mm is
	 * installed — every nonzero access faults (EFAULT class),
	 * never a translate() NULL deref. Zero length touches nothing
	 * (Linux: no-op). */
	if (mm == (const struct uml_nt_mm *)0 && len > 0)
		return -1;
	while (len) {
		unsigned long long chunk = UACC_PAGE - UACC_PAGE_OFF(va);
		char *w;
		long long off;

		if (chunk > len)
			chunk = len;
		off = uml_nt_vma_translate(mm, va, chunk);
		if (off < 0)
			return -1;
		/* Map 049 item 2 — ownership guard: a live VMA whose
		 * backing run the refcount table no longer counts is
		 * a STOLEN run (freed under this mm by an unbalanced
		 * drop). Kernel-side reads of it return foreign
		 * bytes; refuse (-EFAULT class). The sink's ph is the
		 * dispatching conn's own table; NULL outside a
		 * handler keeps the fail-safe default. */
		if (uacc_refs_refuse(va, (unsigned long long)off))
			return -1;
		/* Map 121 (đáp 122): generation check — the claim's
		 * recorded life must still match the run's current
		 * life (see uacc_gen_stale; the tcache-entries
		 * poison-writer class, referee 37105483388). gen==0 =
		 * unchecked claim (POC/bench paths). */
		if (uacc_gen_stale(mm, va, (unsigned long long)off))
			return -1;
		switch (op) {
		case UML_NT_UACC_FROM_GUEST:
			uacc_bcopy(buf, base + off, chunk);
			buf += chunk;
			break;
		case UML_NT_UACC_TO_GUEST:
			w = uml_nt_uacc_write_ptr(mm, base, va);
			if (w == (char *)0)
				return -1;
			uacc_bcopy(w, buf, chunk);
			buf += chunk;
			break;
		case UML_NT_UACC_ZERO_GUEST:
			w = uml_nt_uacc_write_ptr(mm, base, va);
			if (w == (char *)0)
				return -1;
			uacc_bzero(w, chunk);
			break;
		}
		va += chunk;
		len -= chunk;
	}
	return 0;
}

static long long uacc_str_walk(char *dst, const struct uml_nt_mm *mm,
			       char *base, unsigned long long va,
			       unsigned long long maxlen, int want_nul_incl)
{
	unsigned long long done = 0;

	/* No mm installed = fault class (strnlen_user → 0, strncpy →
	 * -1), same as an unmapped byte (fail-safe, review M3.8). */
	if (mm == (const struct uml_nt_mm *)0)
		return want_nul_incl ? 0 : -1;
	while (done < maxlen) {
		unsigned long long chunk = UACC_PAGE - UACC_PAGE_OFF(va);
		long long off, n;

		if (chunk > maxlen - done)
			chunk = maxlen - done;
		off = uml_nt_vma_translate(mm, va, chunk);
		if (off < 0)
			return want_nul_incl ? 0 : -1;
		/* Stolen run (map 049 item 2): same ownership guard as
		 * the byte walk — refuse the read. */
		if (uacc_refs_refuse(va, (unsigned long long)off))
			return want_nul_incl ? 0 : -1;
		/* Map 121: same generation guard as the byte walk (the
		 * str funnel reads through the same claim — see
		 * uacc_gen_stale). */
		if (uacc_gen_stale(mm, va, (unsigned long long)off))
			return want_nul_incl ? 0 : -1;
		n = (long long)uacc_bstrnlen(base + off, chunk);
		if (n < (long long)chunk) {
			/* NUL inside this chunk: copy it too, done. */
			if (dst)
				uacc_bcopy(dst + done, base + off,
					   (unsigned long long)n + 1);
			if (want_nul_incl)
				return done + n + 1; /* incl NUL */
			return done + n;
		}
		if (dst)
			uacc_bcopy(dst + done, base + off, chunk);
		done += chunk;
		va += chunk;
	}
	/* ran out without NUL: strnlen_user reports 0 (fault class),
	 * strncpy_from_user reports EFAULT (-1). */
	return want_nul_incl ? 0 : -1;
}

long long uml_nt_uacc_strncpy(char *dst, const struct uml_nt_mm *mm,
			      char *base, unsigned long long va,
			      unsigned long long maxlen)
{
	return uacc_str_walk(dst, mm, base, va, maxlen, 0);
}

long long uml_nt_uacc_strnlen(const struct uml_nt_mm *mm, char *base,
			      unsigned long long va,
			      unsigned long long maxlen)
{
	return uacc_str_walk((char *)0, mm, base, va, maxlen, 1);
}

/* K6 (M5.6a) uawrite full-buffer witness — see uaccess_walk.h.
 * Byte ops spelled out like the rest of this file: no <string.h>,
 * it compiles freestanding in the kernel AND in the unit test. */
unsigned long long uml_nt_uacc_fnv1a64(const void *buf, unsigned long n)
{
	const unsigned char *p = (const unsigned char *)buf;
	unsigned long long h = 0xcbf29ce484222325ull;
	unsigned long i;

	for (i = 0; i < n; i++) {
		h ^= p[i];
		h *= 0x100000001b3ull;
	}
	return h;
}

unsigned long long uml_nt_uacc_fnv_mix_nr(unsigned long long h,
					  unsigned long long nr)
{
	int i;

	for (i = 0; i < 8; i++) {
		h ^= (nr >> (8 * i)) & 0xff;
		h *= 0x100000001b3ull;
	}
	return h;
}

/* K6 (M5.6a, scrutiny fix) — the [uawrite] nr-context protocol;
 * see uaccess_walk.h. The state lives HERE (not uaccess.c, which
 * only reads it through nr_current) so the whole protocol compiles
 * into the Linux CI unit test: the tests drive the REAL functions
 * the dispatch (syscall.c), the switch boundary (stub_ctl.c
 * uml_nt_switch_trace) and the logger (uaccess.c) call. */
static unsigned long long uacc_nr;

unsigned long long uml_nt_uacc_nr_current(void)
{
	return uacc_nr;
}

/* Plain install, returns the PREVIOUS nr — the dispatch's exit
 * restore (out: in syscall.c): nested handler returns keep the
 * outer handler's nr installed (M4.2, set_mm/set_sink's twin). */
unsigned long long uml_nt_uacc_set_nr(unsigned long long nr)
{
	unsigned long long prev = uacc_nr;

	uacc_nr = nr;
	return prev;
}

/* Dispatch entry: stamp the conn's slot AND install the global in
 * one call — the slot (c->active_nr, kzalloc-init 0) is what the
 * stack-switch boundary re-arms from. */
unsigned long long uml_nt_uacc_nr_enter(unsigned long long *slot,
					unsigned long long nr)
{
	if (slot != 0)
		*slot = nr;
	return uml_nt_uacc_set_nr(nr);
}

/* The stack-switch boundary: install the incoming task's conn-
 * stamped nr — the nr of ITS in-flight handler (a task woken
 * inside its blocked wait4 keeps its own 61 even though an
 * intervening child exited through do_exit with 60/231 still in
 * the global, never unwound). NULL slot = conn-less or stale-
 * refused: install 0, the honest "no active handler" value.
 * Returns the value installed. */
unsigned long long uml_nt_uacc_nr_switch(const unsigned long long *slot)
{
	uacc_nr = (slot != 0) ? *slot : 0;
	return uacc_nr;
}

/* does [from, from+n) contain needle verbatim? */
static int uacc_has(const void *from, unsigned long n,
		    const char *nd, unsigned long nl)
{
	unsigned long i;

	if (nl == 0 || n < nl)
		return 0;
	for (i = 0; i + nl <= n; i++) {
		unsigned long j;

		for (j = 0; j < nl; j++)
			if (((const char *)from)[i + j] != nd[j])
				break;
		if (j == nl)
			return 1;
	}
	return 0;
}

int uml_nt_uacc_dump_gate(const void *from, unsigned long n,
			  unsigned long long va,
			  unsigned long long heap_start)
{
	static const char poison[] = "SYSTEMD_";
	static const char locale[] = "LANG=en_US.UTF-8";

	if (uacc_has(from, n, poison, sizeof(poison) - 1))
		return 1;
	if (uacc_has(from, n, locale, sizeof(locale) - 1))
		return 1;
	/* tcache-page dest: ANY overlap with [heap_start, +0x1000)
	 * (the small-mode dests, plus a bulk write starting inside).
	 * va+n guarded against wrap. */
	if (va < heap_start + 0x1000ull) {
		unsigned long long vend = (n > ~0ull - va) ?
					  ~0ull : va + n;

		if (vend > heap_start)
			return 1;
	}
	return 0;
}

/* K6 step 2 (M5.6a decision-tree step 2) — the [tcekey] syscall-park
 * witness's pure tcache-chain logic (see uaccess_walk.h for the glibc
 * contract). Compiled freestanding in the kernel AND in the unit
 * test; the guest reads arrive through the reader callback. */
unsigned long long uml_nt_tce_reveal(unsigned long long raw,
				      unsigned long long va)
{
	return raw ^ (va >> 12);
}

int uml_nt_tce_member_ok(unsigned long long va,
			 unsigned long long heap_start,
			 unsigned long long heap_end)
{
	return (va & 0xfull) == 0 && (va >> 48) == 0 &&
	       va >= heap_start && va < heap_end;
}

int uml_nt_tce_walk_bin(const struct uml_nt_tce_rd *rd,
			unsigned long long head,
			unsigned long long heap_start,
			unsigned long long heap_end, int bin,
			struct uml_nt_tce_bin *out)
{
	unsigned long long cur = head;
	int d;

	out->walked = 0;
	out->capped = 0;
	out->broke = 0;
	out->broke_va = 0;
	out->broke_next = 0;
	if (!uml_nt_tce_member_ok(cur, heap_start, heap_end)) {
		/* empty (0) or illegal head: no members to record; the
		 * caller's counts predicate turns any counts>0 (or a
		 * non-zero pair state) into the (c) flag. */
		out->broke = 1;
		out->broke_va = head;
		out->broke_next = head;
		return 0;
	}
	for (d = 0; d < UML_NT_TCE_DEPTH; d++) {
		unsigned long long nxt_raw, nxt;

		out->ch[d].va = cur;
		out->ch[d].bin = bin;
		out->ch[d].depth = d;
		if (rd->read(rd->ctx, cur, &nxt_raw, &out->ch[d].key,
			     &out->ch[d].size, &out->ch[d].run) < 0) {
			/* the member's own qwords are unreadable in the
			 * CURRENT view — the chain broke here. */
			out->walked = d;
			out->broke = 1;
			out->broke_va = cur;
			out->broke_next = 0;
			return 0;
		}
		out->walked = d + 1;
		nxt = uml_nt_tce_reveal(nxt_raw, cur);
		if (nxt == 0)
			return 0; /* clean chain end */
		if (!uml_nt_tce_member_ok(nxt, heap_start, heap_end)) {
			/* the missing-store fingerprint: the member's
			 * next is stale/garbage (poison text decodes
			 * out-of-heap/misaligned) — everything counts[]
			 * still claims below it is orphaned. */
			out->broke = 1;
			out->broke_va = cur;
			out->broke_next = nxt;
			return 0;
		}
		if (d + 1 == UML_NT_TCE_DEPTH) {
			out->capped = 1;
			return 0;
		}
		cur = nxt;
	}
	return 0;
}

int uml_nt_tce_find(const struct uml_nt_tce_snap *s,
		    unsigned long long va)
{
	int i;

	for (i = 0; i < s->n; i++)
		if (s->ch[i].va == va)
			return i;
	return -1;
}

unsigned long long uml_nt_tce_modal_key(const struct uml_nt_tce_snap *s,
					int *best)
{
	unsigned long long want = 0;
	int i, j, b = 0;

	for (i = 0; i < s->n; i++) {
		int cnt = 0;

		if (s->ch[i].key == 0)
			continue; /* no vote: pop marker / missing store */
		for (j = 0; j < s->n; j++)
			if (s->ch[j].key == s->ch[i].key)
				cnt++;
		if (cnt > b) {
			b = cnt;
			want = s->ch[i].key;
		}
	}
	*best = b;
	return want;
}

int uml_nt_tce_record(struct uml_nt_tce_snap *s,
		      const struct uml_nt_tce_chunk *ch)
{
	int i = uml_nt_tce_find(s, ch->va);

	if (i >= 0)
		return i; /* dup — the double-free shape */
	if (s->n >= UML_NT_TCE_MAX)
		return -2;
	s->ch[s->n++] = *ch;
	return -1;
}

int uml_nt_tce_key_stale(unsigned long long key,
			 unsigned long long want)
{
	return key != want;
}

int uml_nt_tce_counts_bad(unsigned int counts, int walked, int capped)
{
	if (capped)
		return 1; /* deeper than a healthy bin can ever be */
	return counts != (unsigned int)walked;
}

int uml_nt_tce_reentry_bad(int head_changed, int head_in_prev,
			   unsigned int counts, unsigned int prev_counts)
{
	return head_changed && head_in_prev && counts > prev_counts;
}
