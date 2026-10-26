/* A run-backed MAP commits the WHOLE run — Shelley 171.
 *
 * Measured: the kernel's VMA claimed the stack run [0x60850000,0x60860000)
 * while VirtualQuery showed only [0x6085d000,0x60860000) committed. The
 * cause is the MAP op: a file view mapped with the kernel's content
 * length commits exactly that many pages, and the rest of the run never
 * exists for Windows. The ledger is run-granular everywhere (walkers,
 * translate, grow), so the fix is to make the MAP match the ledger — map
 * the whole run whenever the op is run-aligned — and NOT to clamp the
 * VMA to whatever the mapping happened to cover (that would break
 * run-granularity for every consumer).
 *
 * The charge is pagefile-backed: untouched pages cost no commit charge in
 * our phys pool, so mem=120M does not move.
 *
 * Red-first in test_resume.c section 19 (mutant: content length wins).
 */
#ifndef _UML_NT_MAPLEN_MODEL_H
#define _UML_NT_MAPLEN_MODEL_H

#define UML_NT_MAP_RUN 0x10000ull

/* The length to hand MapViewOfFileEx/commit for an op that wants
 * `op_len` bytes at section offset `off`. Run-aligned ops cover their
 * whole run; anything else keeps its exact shape (file segments and
 * partial views must not grow past what the file holds). */
static inline unsigned long long
uml_nt_map_len(unsigned long long op_len, unsigned long long off)
{
	if (UML_NT_MAP_RUN == 0)
		return op_len;
	if ((off & (UML_NT_MAP_RUN - 1)) != 0)
		return op_len;
	if (op_len == 0 || op_len >= UML_NT_MAP_RUN)
		return op_len;
	return UML_NT_MAP_RUN;
}

#endif
