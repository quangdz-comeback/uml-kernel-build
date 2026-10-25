/* The DEATH-SITE discriminator — M5.6a (Shelley 159 ruling).
 *
 * A stub that dies with 0xC0000005 after publishing a perfectly sane
 * CONTEXT leaves exactly three shapes of evidence, and each one has a
 * different fix:
 *
 *   (i)   TRANSIT   the block no longer holds what the kernel answered
 *                   => the copy path (length, struct overlap, torn
 *                   write between publish and read). Never the guest.
 *   (ii)  STALE     the table calls the VA a hole while the stub's own
 *                   process still maps it => a range was released
 *                   while the guest still had rip inside it.
 *   (iii) JUMP      no table entry and no view either => the guest
 *                   really entered a hole; whoever computed the target
 *                   (a return value, an indirect jump) is the source.
 *   SANE            mapped in both places: the death is not geometry.
 *
 * Pure logic, host-tested red-first in test_resume.c section 12. The
 * kernel prints the verdict instead of leaving a reader to do the
 * arithmetic from three hex values at 3am.
 */
#ifndef _UML_NT_DEATHSIT_MODEL_H
#define _UML_NT_DEATHSIT_MODEL_H

enum {
	UML_NT_DS_TRANSIT = 0,
	UML_NT_DS_STALE = 1,
	UML_NT_DS_JUMP = 2,
	UML_NT_DS_SANE = 3,
};

/* ans_rip    = the rip the kernel froze before releasing the stub
 * shared_rip = the rip the shared block holds now
 * view_found = the per-conn view ledger has an entry covering it
 * stub_maps  = VirtualQueryEx says the stub process still maps it
 *
 * A differing answer is TRANSIT before anything else: no other branch
 * is even meaningful once the block and the kernel disagree. */
static inline int uml_nt_deathsit_verdict(unsigned long long ans_rip,
					  unsigned long long shared_rip,
					  int view_found, int stub_maps)
{
	if (ans_rip != shared_rip)
		return UML_NT_DS_TRANSIT;
	if (!view_found && stub_maps)
		return UML_NT_DS_STALE;
	if (!view_found)
		return UML_NT_DS_JUMP;
	return UML_NT_DS_SANE;
}

/* The jump-source test: did the guest land ON the value the kernel just
 * returned (or within `window` of it)? A death rip that equals a
 * syscall's return value is a call through a bogus address that a
 * syscall produced — e.g. an mmap result used as a code target. */
static inline int uml_nt_deathsit_near_retval(unsigned long long rip,
					      unsigned long long retval,
					      unsigned long long window)
{
	unsigned long long d = rip > retval ? rip - retval : retval - rip;

	return d <= window;
}

#endif
