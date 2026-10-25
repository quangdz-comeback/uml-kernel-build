/* One owner per debug slot, decided in ONE place — Shelley 164.
 *
 * Four hardware slots serve every hardware-breakpoint instrument the
 * kernel has, and each instrument used to take whatever slot it liked.
 * Three times that silently blinded a live measurement:
 *
 *   1. the write-slot pivot instrument took all four and zeroed
 *      dr_exec_mask, wiping the one-shot execute probe;
 *   2. the retired pivot-dr *handler* sat above the probe's handler in
 *      the dispatch chain and consumed its #DB round;
 *   3. the arena bin-head instrument rewrote dr_watch[2]/[3] every 64
 *      rounds and the tcache watch owned 0/1, so a probe on slot 2
 *      survived only if no tear-hunt instrument ran first.
 *
 * The rule that fixes the class: a slot has exactly one owner, a
 * higher-priority owner may evict a lower-priority one, and an owner
 * declared RETIRED can never reserve again (it keeps no slot and no
 * claim). Pure logic, host-tested red-first in test_resume.c section
 * 16 — the three incidents above are the regression cases.
 */
#ifndef _UML_NT_DRSLOT_MODEL_H
#define _UML_NT_DRSLOT_MODEL_H

#define UML_NT_DRS_SLOTS 4

enum uml_nt_drs_owner {
	UML_NT_DRS_FREE = 0,
	UML_NT_DRS_TCACHE = 1,
	UML_NT_DRS_ARENA = 2,
	UML_NT_DRS_WSLOT = 3,
	UML_NT_DRS_EXEC = 4,	/* the live one-shot execute probe */
};

struct uml_nt_drslots {
	unsigned char owner[UML_NT_DRS_SLOTS];	/* enum per slot */
	unsigned char retired;			/* bitmask of retired owners */
};

static inline void uml_nt_drs_init(struct uml_nt_drslots *s)
{
	int i;

	for (i = 0; i < UML_NT_DRS_SLOTS; i++)
		s->owner[i] = UML_NT_DRS_FREE;
	s->retired = 0;
}

static inline void uml_nt_drs_retire(struct uml_nt_drslots *s, unsigned owner)
{
	int i;

	s->retired |= (unsigned char)(1u << owner);
	for (i = 0; i < UML_NT_DRS_SLOTS; i++)
		if (s->owner[i] == owner)
			s->owner[i] = UML_NT_DRS_FREE;
}

static inline void uml_nt_drs_release(struct uml_nt_drslots *s, unsigned owner)
{
	int i;

	for (i = 0; i < UML_NT_DRS_SLOTS; i++)
		if (s->owner[i] == owner)
			s->owner[i] = UML_NT_DRS_FREE;
}

/* Reserve up to `want` slots for `owner`; fills out[] with slot indexes
 * and returns how many were granted. A retired owner gets nothing. A
 * live owner may evict slots held by STRICTLY lower-priority owners
 * (which is how the probe takes a slot back from a tear-hunt
 * instrument) but never a peer or a higher one. */
static inline int uml_nt_drs_reserve(struct uml_nt_drslots *s,
				     unsigned owner, int want, int *out)
{
	int i, n = 0;

	if (owner >= 8 || (s->retired & (1u << owner)))
		return 0;
	for (i = 0; i < UML_NT_DRS_SLOTS && n < want; i++)
		if (s->owner[i] == UML_NT_DRS_FREE) {
			s->owner[i] = (unsigned char)owner;
			out[n++] = i;
		}
	for (i = 0; i < UML_NT_DRS_SLOTS && n < want; i++) {
		unsigned char o = s->owner[i];

		if (o != UML_NT_DRS_FREE && o < owner &&
		    !(s->retired & (1u << o))) {
			s->owner[i] = (unsigned char)owner;
			out[n++] = i;
		}
	}
	return n;
}

static inline int uml_nt_drs_holds(const struct uml_nt_drslots *s, unsigned owner)
{
	int i, n = 0;

	for (i = 0; i < UML_NT_DRS_SLOTS; i++)
		if (s->owner[i] == owner)
			n++;
	return n;
}

#endif
