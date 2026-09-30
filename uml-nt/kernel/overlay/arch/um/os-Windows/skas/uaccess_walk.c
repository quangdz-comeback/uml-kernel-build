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
	 * normal COW machinery. */
	if (uml_nt_phys_refs(uacc_sink.ph, (long long)old_run) <= 1)
		return base + byte_off;

	if (uacc_sink.plan == (struct uml_nt_fault_plan *)0)
		return (char *)0;

	s = vma->start;
	e = vma->end;
	span_base = vma->run_off;
	prot = vma->prot;

	new_run = (unsigned long long)uml_nt_phys_alloc(uacc_sink.ph);
	if (new_run == (unsigned long long)-1)
		return (char *)0;
	/* The content copy is INLINE (kernel flat view): fresh run gets
	 * the shared run's bytes, then the caller's write lands on it. */
	uacc_bcopy(base + new_run, base + old_run, UACC_RUN);
	uml_nt_uacc_fixups++; /* the conn layer logs the delta */

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
