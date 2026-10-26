/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The stub's VEH dispatch stack — pure model (unit-tested on Linux,
 * used verbatim by the Windows stub).
 *
 * Why this exists (Shelley 157): the VEH runs on whatever rsp the
 * faulting thread had. For a guest thread that is the GUEST's stack —
 * measured in referee 40149461755: sp=0x6085c6a8 inside the guest
 * stack while the thread's own TEB stack was [0x66b8dfc000,
 * 0x66b8e00000). If a dispatcher frame lands on a guest page that is
 * PROT_NONE / PAGE_GUARD, the dispatch itself faults, Windows cannot
 * push a handler frame and the process dies with the raw exception
 * code and NO handler running — the exact silent-death signature
 * (exit 0xC0000005, no record, no filter).
 *
 * The fix is structural: the outermost exception entry switches to a
 * stub-private buffer; nested entries keep using it (never switch
 * twice, never unwittingly return to the guest stack mid-dispatch).
 *
 * Invariants the tests pin down:
 *  - the private sp is 16-byte aligned and strictly inside the buffer
 *    with room for a full dispatch (shadow space + frames);
 *  - the FIRST entry records the guest sp and the LAST leave restores
 *    exactly that value (the CONTINUE_EXECUTION path returns to the
 *    faulting instruction, so the restore must be bit-exact);
 *  - a nested enter/leave never touches the saved guest sp;
 *  - a buffer too small to dispatch is refused (caller falls back to
 *    the old on-guest-stack behaviour rather than running off it).
 */
#ifndef UML_NT_VEH_MODEL_H
#define UML_NT_VEH_MODEL_H

#define UML_NT_VEH_MIN_SIZE	4096	/* one dispatch needs ~1-2 KiB */

struct uml_nt_veh_stack {
	unsigned long long buf;		/* buffer base */
	unsigned long long size;	/* buffer bytes */
	unsigned long long guest_sp;	/* saved at the outermost entry */
	unsigned long long sp;		/* where the body runs now */
	int depth;			/* 0 = on the guest stack */
};

/*
 * Decide entry. `sp_now` is the rsp at exception entry (read by the
 * caller — the model never reads registers itself).
 * Returns 0 = switched (use s->sp), 1 = nested (keep s->sp), -1 = refuse.
 */
static inline int uml_nt_veh_enter(struct uml_nt_veh_stack *s,
				   unsigned long long sp_now)
{
	if (s == NULL)
		return -1;
	if (s->depth > 0) {
		s->depth++;
		return 1;
	}
	if (s->buf == 0 || s->size < UML_NT_VEH_MIN_SIZE)
		return -1;
	s->sp = (s->buf + s->size - 16) & ~15ULL;	/* top, aligned */
	if (s->sp <= s->buf + UML_NT_VEH_MIN_SIZE)
		return -1;
	s->guest_sp = sp_now;
	s->depth = 1;
	return 0;
}

/*
 * Leave one level. Returns 0 when the guest stack must be restored
 * (outermost leave — *sp_out is the exact saved value), 1 while nested
 * (*sp_out = the private sp, unchanged), -1 if unbalanced.
 */
static inline int uml_nt_veh_leave(struct uml_nt_veh_stack *s,
				   unsigned long long *sp_out)
{
	if (s == NULL || s->depth <= 0)
		return -1;
	s->depth--;
	if (s->depth > 0) {
		*sp_out = s->sp;
		return 1;
	}
	*sp_out = s->guest_sp;
	return 0;
}

/* A record must not contradict itself (Shelley 188).
 *
 * XSTATE_BV names the components present; XCOMP_BV bit 63 says whether the
 * area is in compacted format. Intel SDM: components 5, 6 and 7 (opmask,
 * ZMM_Hi256, Hi16_ZMM) exist only in the compacted format — a record that
 * sets any of those BV bits while declaring standard format is invalid,
 * and handing it back to a context restore is a #GP inside the kernel's
 * own restore path: the thread dies with 0xC0000005 and no user-mode
 * handler ever runs, which is this hunt's signature to the letter.
 *
 * Referee 40396760752 measured exactly that pair on the dying conn:
 * ContextFlags=0x10005f (CONTEXT_XSTATE set), XSTATE_BV=0x37f, XCOMP_BV=0.
 *
 * So: before the record goes back, the standard-format area may only claim
 * standard-format components. Pure logic, red-first in section 23.
 */
#define UML_NT_XCOMP_COMPACTED	(1ull << 63)
#define UML_NT_XSTATE_AVX512	0x000000e0ull	/* bits 5, 6, 7 */

static inline unsigned long long uml_nt_xstate_mask(unsigned long long bv,
						    unsigned long long xcomp)
{
	if (xcomp & UML_NT_XCOMP_COMPACTED)
		return bv;	/* compacted: AVX-512 components are legal */
	return bv & ~UML_NT_XSTATE_AVX512;
}

static inline int uml_nt_xstate_inconsistent(unsigned long long bv,
					     unsigned long long xcomp)
{
	return (xcomp & UML_NT_XCOMP_COMPACTED) == 0 &&
	       (bv & UML_NT_XSTATE_AVX512) != 0;
}

#endif /* UML_NT_VEH_MODEL_H */
