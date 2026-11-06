/* guestread.h — read guest memory WITHOUT touching the uaccess sink.
 *
 * S88 (report 387 §1): uml_nt_uacc_walk() drives the uaccess SINK, so calling it
 * from a syscall dispatch or an answer path clobbers the plan of the call in
 * flight — the M3.1 acceptance went red within one CI run. Diagnostics that want
 * to quote guest bytes need a door of their own: resolve the VA through the
 * conn's VMA table, then copy straight out of the run's backend page. Read-only,
 * no refcounts, no epochs, no sink, no plan.
 */
#ifndef _UML_NT_GUESTREAD_H
#define _UML_NT_GUESTREAD_H

#include <vma.h>
#include <physalloc.h>
#include <string.h>

/* 0 = bytes copied; -1 = no VMA covers the range; -2 = VMA but no backing page;
 * -3 = the VMA is not readable. */
static inline int uml_nt_gread(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			       unsigned long long va, void *dst,
			       unsigned long len)
{
	char *out = (char *)dst;
	unsigned long done = 0;

	if (mm == 0 || ph == 0 || len == 0)
		return -1;
	while (done < len) {
		struct uml_nt_vma *v = uml_nt_vma_find(mm, va + done);
		unsigned long long off;
		unsigned long idx, owner, chunk;

		if (v == 0 || v->start == v->end)
			return -1;
		if ((v->prot & (UML_NT_PAGE_READONLY | UML_NT_PAGE_READWRITE)) == 0)
			return -3;
		off = v->run_off + (va + done - v->start);
		idx = (unsigned long)(off / UML_NT_PHYS_RUN_SIZE);
		if (idx >= UML_NT_PHYS_MAX_RUNS)
			return -2;
		owner = idx - ph->span_back[idx];
		if (owner >= UML_NT_PHYS_MAX_RUNS || ph->pages[owner] == 0)
			return -2;
		/* chunk = to the end of the VMA, the request, or this run */
		chunk = (unsigned long)(v->end - (va + done));
		if (chunk > len - done)
			chunk = len - done;
		if (chunk > UML_NT_PHYS_RUN_SIZE -
				   (unsigned long)(off % UML_NT_PHYS_RUN_SIZE))
			chunk = UML_NT_PHYS_RUN_SIZE -
				(unsigned long)(off % UML_NT_PHYS_RUN_SIZE);
		/* pages[owner] is the span's ONE backend allocation: the byte
		 * offset inside it is off minus the owner run's own start. */
		memcpy(out + done,
		       (const char *)ph->pages[owner] +
			       (off - (unsigned long long)owner *
					      UML_NT_PHYS_RUN_SIZE),
		       chunk);
		done += chunk;
	}
	return 0;
}

#endif
