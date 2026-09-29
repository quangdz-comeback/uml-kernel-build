// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/fault.c — guest page-fault decision (M3.1).
 *
 * Why decide here and not in the caller: the decision (can this fault
 * be fixed by protecting/mapping a page, or is the guest wild?) is
 * pure logic over the allow table — unit-testable on Linux CI without
 * any NT machinery (HANDOFF §8: every pure-logic function gets a
 * Linux-side test). The VMA-tree walk this stand-in table emulates
 * arrives with the M3.2 VMA manager; the action codes and this
 * signature are its contract.
 *
 * Resume shape (the caller's job, see stub.c/kernel dispatch): the
 * stub re-executes the faulting instruction — the kernel-side protect
 * must be complete before the answer is published, there is no
 * "resume and hope".
 */
#include <fault.h>

int uml_nt_fault_decide(unsigned long long addr, unsigned type,
			const struct uml_nt_fault_range *allow, int n_allow,
			unsigned *action, unsigned *prot,
			unsigned long long *page)
{
	int i;

	*page = addr & ~(UML_NT_FAULT_PAGE_SIZE - 1);

	/* Protection we restore the page to. The M2 flat physmem view
	 * is RWX, so a protect to RW (or RXW for a DEP fault) always
	 * re-enables what the guest needs; the M3.2 VMA manager will
	 * consult the VMA's own protection instead of these blanket
	 * values (an exec fault on a non-exec VMA must stay fatal). */
	switch (type) {
	case UML_NT_FAULT_READ:
	case UML_NT_FAULT_WRITE:
		*prot = UML_NT_PAGE_READWRITE;
		break;
	case UML_NT_FAULT_EXEC:
		*prot = UML_NT_PAGE_EXECUTE_READWRITE;
		break;
	default:
		/* Unknown access class: the NT contract grew, or the
		 * record is garbage — never guess (fail loud). */
		*action = UML_NT_FAULT_ACTION_KILL;
		return -1;
	}

	for (i = 0; i < n_allow; i++) {
		if (*page >= allow[i].start &&
		    *page + UML_NT_FAULT_PAGE_SIZE <= allow[i].end) {
			*action = UML_NT_FAULT_ACTION_PROT;
			return 0;
		}
	}

	/* Outside every allowed range: a guest wild pointer. Upstream
	 * would deliver SIGSEGV (M4); killing the stub is the honest
	 * stand-in — the kernel observes the death and reports loud. */
	*action = UML_NT_FAULT_ACTION_KILL;
	return -1;
}
