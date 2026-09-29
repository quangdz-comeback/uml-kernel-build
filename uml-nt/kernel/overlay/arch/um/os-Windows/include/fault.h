/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fault.h — guest page-fault decision (M3.1), uml-nt.
 *
 * Upstream analogue: arch/um/mm handle_page_fault() + the VMA walk in
 * handle_mm_fault() — on Linux the host MMU deliver a SIGSEGV/SIGTRAP
 * and the kernel consults its VMA tree. On NT the stub's VEH delivers
 * STATUS_ACCESS_VIOLATION with the access class + faulting VA; this
 * module decides recoverable (map/protect the page, resume) vs fatal
 * (wild pointer — guest SIGSEGV semantics arrive in M4, kill for now).
 *
 * The decision is pure logic with NO kernel includes: the unit test
 * compiles fault.c standalone on Linux CI (same pattern as
 * scan_patch.c). The NT constants below are the win32 values — the
 * kernel build gets them from here, not windows.h (D1).
 */
#ifndef __UM_OS_WINDOWS_FAULT_H
#define __UM_OS_WINDOWS_FAULT_H

#define UML_NT_FAULT_PAGE_SIZE 0x1000ull

/* NT PAGE_* protection constants (winnt.h values, declared here
 * because the kernel ELF must not include windows.h — D1). */
#define UML_NT_PAGE_READWRITE         0x04u
#define UML_NT_PAGE_EXECUTE_READWRITE 0x40u

/* ExceptionInformation[0] access classes for STATUS_ACCESS_VIOLATION
 * (NT exception record contract; 8 = DEP — execute on non-exec page). */
#define UML_NT_FAULT_READ  0u
#define UML_NT_FAULT_WRITE 1u
#define UML_NT_FAULT_EXEC  8u

/* Actions (mirror UML_STUB_ACTION_* in stub_nt.h — fault.c compiles
 * standalone, test_fault.c asserts the mirroring). */
#define UML_NT_FAULT_ACTION_PROT 1u
#define UML_NT_FAULT_ACTION_KILL 2u

/* Address range [start, end) the kernel is willing to fix up. */
struct uml_nt_fault_range {
	unsigned long long start;
	unsigned long long end;
};

/*
 * Decide one guest page fault.
 *
 * Returns 0 and sets *action = UML_NT_FAULT_ACTION_PROT with *prot
 * (PAGE_*) and *page (faulting page base) when the fault is
 * recoverable; returns -1 and *action = KILL when it is fatal
 * (unknown access class, or page outside every allow range).
 */
int uml_nt_fault_decide(unsigned long long addr, unsigned type,
			const struct uml_nt_fault_range *allow, int n_allow,
			unsigned *action, unsigned *prot,
			unsigned long long *page);

#endif /* __UM_OS_WINDOWS_FAULT_H */
