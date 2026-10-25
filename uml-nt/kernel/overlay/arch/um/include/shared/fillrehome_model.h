/* Must a file fill re-home its run before writing? — Shelley 161.
 *
 * A fill writes file bytes straight into physmem, bypassing every stub
 * view. That is fine for a run this mapping owns (refs == 1) and wrong
 * for one somebody else also maps: the sibling's content changes under
 * it. For an EXECUTABLE run it is worse than corruption — the other
 * conn's guest is executing bytes that a blocking kernel_read is
 * rewriting, and a 0f 05 restored in that window is a real host
 * syscall, i.e. the silent death we have been chasing.
 *
 * So: re-home whenever the run has more than one claim. exec_vma is
 * carried for the caller's log and for the future case where a code
 * page needs a stronger policy than data (it is the dangerous one, the
 * data page the quiet one), but the decision today is the refcount: a
 * run with a second claimer is never written in place.
 *
 * Pure logic; red-first host test in test_resume.c section 14.
 */
#ifndef _UML_NT_FILLREHOME_MODEL_H
#define _UML_NT_FILLREHOME_MODEL_H

static inline int uml_nt_fill_needs_rehome(int exec_vma, int refs)
{
	(void)exec_vma;
	return refs > 1;
}

#endif
