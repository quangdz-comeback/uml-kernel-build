/* What SHAPE is a garbage register? — Shelley 177.
 *
 * Two shapes keep appearing in the dying rounds and they may not have the
 * same source:
 *   - a u16 shifted into the top half (0x4802000000000000,
 *     0x4002000000000000): the low 48 bits are empty and only bits 48..63
 *     carry data — the signature of a 2-byte value written at +6 of an
 *     8-byte slot, i.e. a small store landing at the wrong offset;
 *   - a full-random 64-bit value (0x2fc6222fb3efde00, 0x57cb60ecc23ee700):
 *     every byte differs from anything the guest produced, which is a torn
 *     or uninitialised read rather than a misplaced 2-byte store.
 * Naming the shape per register is what separates them. Pure logic,
 * red-first in test_resume.c section 20.
 */
#ifndef _UML_NT_REGSHAPE_MODEL_H
#define _UML_NT_REGSHAPE_MODEL_H

enum uml_nt_regshape {
	UML_NT_REG_CLEAN = 0,
	UML_NT_REG_U16_HIGH = 1,	/* only bits 48..63 carry data */
	UML_NT_REG_FULL_RANDOM = 2,	/* high half set AND low bits set */
};

static inline int uml_nt_reg_shape(unsigned long long v)
{
	unsigned long long hi = v >> 48;

	if (hi == 0)
		return UML_NT_REG_CLEAN;
	/* u16-shape: the top 16 bits are non-zero and the lower 48 are
	 * all zero — exactly what a 2-byte store at +6 leaves behind. */
	if ((v & 0x0000ffffffffffffull) == 0)
		return UML_NT_REG_U16_HIGH;
	/* kernel addresses and guest addresses are clean by construction */
	if ((v >> 47) == 0x1ffffull || (v >> 47) == 0x0ffffull)
		return UML_NT_REG_CLEAN;
	return UML_NT_REG_FULL_RANDOM;
}

static inline const char *uml_nt_reg_shape_name(int s)
{
	switch (s) {
	case UML_NT_REG_U16_HIGH:
		return "u16<<48";
	case UML_NT_REG_FULL_RANDOM:
		return "full-random";
	default:
		return "clean";
	}
}

#endif
