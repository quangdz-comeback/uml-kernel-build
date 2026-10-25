/* When must the D20 sweep re-patch a run? — M5.6a (referee 40197441363).
 *
 * THE BUG THIS ENCODES: an unpatched guest `syscall` (0f 05) is a REAL
 * host syscall inside the stub — it leaves user mode through the
 * Windows kernel's own dispatch, so a VEH never sees it and the process
 * dies with a raw 0xC0000005 and no records. The death rip of the
 * password hunt is exactly one: libc+0xfce65 is the `syscall` of
 * __close_nocancel, and 0x601e0000-range sweeps of that very conn
 * reported "0 syscall(s) patched" while another conn's sweep of the
 * same library patched 526.
 *
 * The cause is a cache, not a decoder: the sweep skips any run whose
 * "already swept" bit is set, but the PHYSICAL RUNS ARE SHARED (the
 * read-only file cache) and a later file fill memcpy's pristine bytes
 * back over the patched ones. The bit then lies forever.
 *
 * So the question "must this run be swept" is a function of three
 * facts, and this is that function: pure, and host-tested red-first
 * (test_resume.c section 13).
 */
#ifndef _UML_NT_D20SWEEP_MODEL_H
#define _UML_NT_D20SWEEP_MODEL_H

/* exec_vma   : the VMA holding the run is executable (only code needs it)
 * swept_gen  : the run generation the last sweep patched (0 = never)
 * gen_now    : the run's generation now
 *
 * A different generation means the content was re-created (a file fill,
 * a COW copy, a re-home) and the patch went with the old bytes. Never
 * trust the bit across a generation change. */
static inline int uml_nt_sweep_needed(int exec_vma,
				      unsigned long long swept_gen,
				      unsigned long long gen_now)
{
	if (!exec_vma)
		return 0;
	if (swept_gen == 0)
		return 1;
	return swept_gen != gen_now;
}

#endif
