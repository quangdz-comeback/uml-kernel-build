/* Grow the stack before the exception that needs it — Shelley 168.
 *
 * The death mechanism the [exc-ring] measured: rsp sits with 264..3900
 * bytes of COMMITTED page under it, the reservation below that run is a
 * hole, and the ntdll dispatcher builds its exception frame on the
 * thread's own stack. It writes into the hole, takes a second AV on a
 * thread whose handler is the one it is building, and the process dies
 * with zero handlers and no line — 0xC0000005, silently.
 *
 * Every exception pays that toll, including the ones our own instruments
 * raise (#DB, ud2). So the stack has to be grown ahead of the exception,
 * and the only place that can happen without a round trip is the ANSWER:
 * the kernel already has rsp for the conn and already owns the plan.
 *
 * Discipline unchanged (Shelley 154): only the run immediately below the
 * committed bottom, only inside the reservation, one run per answer, and
 * the floor is the RLIMIT one — beyond it, a clean SIGSEGV, never a
 * silent write. Pure decision logic, red-first in test_resume.c
 * section 18 (mutant: the old one-page window fails).
 */
#ifndef _UML_NT_STACKGROW_MODEL_H
#define _UML_NT_STACKGROW_MODEL_H

#define UML_NT_SG_HEADROOM 0x2000ull	/* 8 KiB of committed page wanted */
#define UML_NT_SG_RUN      0x10000ull	/* 64 KiB run */

/* 1 = precommit the run below `committed_bottom`, and *start says where.
 * 0 = enough headroom, or nothing to do. -1 = the next run would fall
 * below the reservation floor: not ours to grow (the ordinary fault path
 * turns that into a clean SIGSEGV). */
static inline int uml_nt_sg_precommit(unsigned long long top,
				      unsigned long long limit,
				      unsigned long long rsp,
				      unsigned long long committed_bottom,
				      unsigned long long run,
				      unsigned long long *start)
{
	if (top == 0 || limit == 0 || limit >= top)
		return 0;
	if (rsp == 0 || committed_bottom == 0 || rsp < committed_bottom)
		return 0;
	if (rsp >= top)
		return 0;
	if (rsp - committed_bottom >= UML_NT_SG_HEADROOM)
		return 0;
	if (committed_bottom <= limit)
		return -1;
	if (start != 0)
		*start = (committed_bottom >= run) ?
			committed_bottom - run : limit;
	if (*start < limit)
		*start = limit;
	return 1;
}

/* Shelley 273: commit AHEAD, not on demand. The guest stack cannot grow the
 * way a Linux stack does — delivering the growth fault needs to write below
 * the stack pointer, into the hole it is faulting on. So the kernel keeps a
 * fixed reserve of committed pages under the stack pointer at all times and
 * the fault path never has to find headroom at the worst possible moment.
 * Returns 1 while more is wanted, 0 when the reserve is deep enough, -1 at
 * the limit. */
static inline int uml_nt_sg_commit_ahead(unsigned long long top,
					 unsigned long long limit,
					 unsigned long long rsp,
					 unsigned long long committed_bottom,
					 unsigned long long run,
					 unsigned long long want,
					 unsigned long long *start)
{
	if (top == 0 || limit == 0 || limit >= top)
		return 0;
	if (rsp == 0 || committed_bottom == 0 || rsp < committed_bottom)
		return 0;
	if (rsp >= top)
		return 0;
	if (rsp - committed_bottom >= want)
		return 0;
	if (committed_bottom <= limit)
		return -1;
	if (start != 0)
		*start = (committed_bottom >= run) ? committed_bottom - run :
							    limit;
	if (start != 0 && *start < limit)
		*start = limit;
	return 1;
}

#endif
