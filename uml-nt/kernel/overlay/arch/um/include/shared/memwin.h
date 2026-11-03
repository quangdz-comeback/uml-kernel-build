/* SPDX-License-Identifier: GPL-2.0 */
/*
 * memwin.h — read the guest's memory at death, and say what it means.
 *
 * The silent-death record names a last trap PC, not the fault. What the guest
 * was ABOUT to do can still be read from the memory it was using: the return
 * address a `ret` would take is the qword at RSP, and a capget answer is only
 * real if the capability data is in the guest's buffer.
 *
 * The reading and the classification live here, once, with the reader and the
 * VMA lookup injected, so a host test can drive the SAME code with a fake view
 * — a valid qword, a garbage qword, and a page that cannot be read — instead of
 * a second copy of the logic. Production passes the real uaccess walk and the
 * real VMA table.
 */
#ifndef UML_NT_MEMWIN_H
#define UML_NT_MEMWIN_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <string.h>
#include <stdint.h>
typedef uint64_t __u64;
#endif

/* Reader contract: copy `len` bytes from guest VA `va`; 0 on success,
 * negative on failure. */
typedef int (*uml_nt_memwin_read_fn)(void *ctx, __u64 va, unsigned int len,
				     char *dst);

struct uml_nt_memwin_vma {
	int present;
	__u64 start, end;
	unsigned int prot, flags;
};

/* VMA lookup contract: fill `out` (present=0 when no VMA covers `va`). */
typedef void (*uml_nt_memwin_find_fn)(void *ctx, __u64 va,
				      struct uml_nt_memwin_vma *out);

static inline void uml_nt_memwin_zero(void *p, unsigned long n)
{
	unsigned char *b = (unsigned char *)p;

	while (n-- != 0)
		*b++ = 0;
}

struct uml_nt_memwin_stack {
	int readable;			/* 1 = the whole window was read */
	int err;			/* reader's failure code when !readable */
	__u64 lo;			/* rsp - 0x20 */
	__u64 q[8];			/* the window: q[4] is [rsp] */
	int retaddr_vma;		/* 1 = a VMA covers the return address */
	struct uml_nt_memwin_vma retaddr_where;
};

struct uml_nt_memwin_capdata {
	int attempted;			/* 0 = no capget round to read */
	int readable;
	int err;
	__u64 va;
	unsigned char b[24];
};

/*
 * Read the stack window around RSP. A page that cannot be read is reported
 * with its error code — never as a silent all-zero window.
 */
static inline void uml_nt_memwin_stack(uml_nt_memwin_read_fn rd, void *ctx,
				       uml_nt_memwin_find_fn find, void *fctx,
				       __u64 rsp,
				       struct uml_nt_memwin_stack *out)
{
	uml_nt_memwin_zero(out, sizeof(*out));
	if (rd == 0 || rsp < 0x20) {
		out->readable = 0;
		out->err = -1;
		return;
	}
	out->lo = rsp - 0x20;
	out->err = rd(ctx, out->lo, (unsigned int)sizeof(out->q),
		      (char *)out->q);
	out->readable = (out->err == 0);
	if (!out->readable)
		return;
	if (find != 0) {
		find(fctx, out->q[4], &out->retaddr_where);
		out->retaddr_vma = out->retaddr_where.present;
	}
}

/* Read the capability data the last capget round was asked to fill. */
static inline void uml_nt_memwin_capdata(uml_nt_memwin_read_fn rd, void *ctx,
					 int have_round, __u64 a1,
					 struct uml_nt_memwin_capdata *out)
{
	uml_nt_memwin_zero(out, sizeof(*out));
	if (!have_round || a1 == 0) {
		out->attempted = 0;
		return;
	}
	out->attempted = 1;
	out->va = a1;
	out->err = rd(ctx, a1, (unsigned int)sizeof(out->b), (char *)out->b);
	out->readable = (out->err == 0);
}

#endif /* UML_NT_MEMWIN_H */
