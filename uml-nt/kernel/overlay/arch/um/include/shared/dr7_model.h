/* Dr7 as the stub must build it, and why it is a model — Shelley 163.
 *
 * The kernel arms hardware breakpoints through the shared block; the
 * STUB is the only side that can put them into a resume CONTEXT. Two
 * facts decide the encoding and neither belongs in asm or in a
 * context-restore branch:
 *
 *  - a slot with a VA gets Ln (bit 2*i) — no global exact-match, no
 *    Gd, no R/W or LEN bits for an EXECUTE breakpoint (R/W = 00), so
 *    a slot listed in dr_exec_mask contributes Ln ONLY;
 *  - every other armed slot is the v13 write watch: RW = 01, LEN = 10
 *    (8 bytes) at bits 16 + 4*i.
 *
 * The bug this encodes the fix for: the application of dr7 lived on one
 * resume branch, so the verbatim branch dropped every kernel watchpoint
 * (and the one-shot execute probe) — an instrument can only be trusted
 * if every resume carries it. Pure logic, host-tested red-first in
 * test_resume.c section 15.
 */
#ifndef _UML_NT_DR7_MODEL_H
#define _UML_NT_DR7_MODEL_H

static inline unsigned long long
uml_nt_dr7_build(unsigned exec_mask, unsigned long long dr0,
		 unsigned long long dr1, unsigned long long dr2,
		 unsigned long long dr3)
{
	unsigned long long w[4];
	unsigned long long dr7 = 0;
	int i;

	w[0] = dr0;
	w[1] = dr1;
	w[2] = dr2;
	w[3] = dr3;
	for (i = 0; i < 4; i++) {
		if (w[i] == 0)
			continue;
		dr7 |= 1ull << (2 * i);			/* Ln */
		if (!(exec_mask & (1u << i)))
			dr7 |= 0x9ull << (16 + 4 * i);	/* RW=01 LEN=10 */
	}
	return dr7;
}

#endif
