/* Restoring a page's protection is a decision, not a constant —
 * Shelley 166.
 *
 * A write-dance borrows an execute page: something must fault on a
 * store into text, the kernel makes the page writable, the store
 * replays, and then the page has to go back. The old code put back
 * PAGE_READONLY, which is right for a data page and fatal for text: the
 * next FETCH faults, and because a fetch fault is delivered before the
 * CPU checks DR execute breakpoints, the fault looks exactly like "the
 * resume never reached guest code" (referee 40250825944: armed at the
 * resume target, no #DB, death cmd=3 = FAULT).
 *
 * The rule is upstream parity: the protection comes from the VMA, never
 * from what the dance assumed. Red-first in test_resume.c section 17.
 */
#ifndef _UML_NT_PROT_RESTORE_MODEL_H
#define _UML_NT_PROT_RESTORE_MODEL_H

#define UML_NT_PROT_RO   0x02u	/* PAGE_READONLY */
#define UML_NT_PROT_RW   0x04u	/* PAGE_READWRITE */
#define UML_NT_PROT_EXR  0x20u	/* PAGE_EXECUTE_READ */
#define UML_NT_PROT_EXW  0x40u	/* PAGE_EXECUTE_READWRITE */

/* The protection a page must end up with, given its VMA's prot. An
 * execute VMA gets its execute back; anything else keeps the read-only
 * shape the tripwire wants. A VMA that asks for execute *and* write is
 * honoured too — the point is that the VMA decides. */
static inline unsigned uml_nt_prot_restore(unsigned vma_prot)
{
	if (vma_prot & UML_NT_PROT_EXW)
		return UML_NT_PROT_EXW;
	if (vma_prot & UML_NT_PROT_EXR)
		return UML_NT_PROT_EXR;
	if (vma_prot & UML_NT_PROT_RW)
		return UML_NT_PROT_RW;
	return UML_NT_PROT_RO;
}

/* Does a protection actually allow instruction fetch? */
static inline int uml_nt_prot_executable(unsigned prot)
{
	return (prot & (UML_NT_PROT_EXR | UML_NT_PROT_EXW)) != 0;
}

#endif
