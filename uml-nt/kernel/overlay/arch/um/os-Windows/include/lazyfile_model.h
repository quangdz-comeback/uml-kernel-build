/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uml-nt: lazy (demand-paged) file-backed VMAs — the pure half.
 *
 * D27 (Shelley 2026-10-23, to-shelley/147): file-backed RO/EXEC VMAs
 * must demand-page like upstream Linux — the run is allocated and the
 * file bytes read at the FIRST fault, not eager-filled at mmap. The
 * referee case is udevd's 13 MiB hwdb.bin PROT_READ map: a binary
 * search trie touches a small subset of pages but the eager model
 * burns 11% of the 120 MiB budget on it before login. mmap_fill stays
 * eager for the exec ELF image (binfmt's execve contract) and for the
 * bytes a syscall itself touches; the sharing cache (b6785e3) is
 * untouched.
 *
 * The kernel side (skas/syscall.c) owns the region table, the file
 * reference and the read; this header owns the geometry both sides
 * must agree on, so the host test runs the exact code the kernel
 * ships. Run-aligned bases only: a non-aligned mapping keeps the
 * eager head-hole path (a 64K view cannot start below the mapping
 * without a negative file offset).
 */
#ifndef UML_NT_LAZYFILE_MODEL_H
#define UML_NT_LAZYFILE_MODEL_H

#define UML_NT_LAZYFILE_RUN_SHIFT 16
#define UML_NT_LAZYFILE_RUN (1ull << UML_NT_LAZYFILE_RUN_SHIFT)

/* Materialization window for a fault at `addr`: the run-aligned
 * [run_va, run_end) the stub view will cover, clamped to the region.
 * -1 = outside the region (or the region is not run-aligned). */
static inline int uml_nt_lazy_run_window(unsigned long long rstart,
					 unsigned long long rend,
					 unsigned long long addr,
					 unsigned long long *run_va,
					 unsigned long long *run_end)
{
	unsigned long long rv, re;

	if ((rstart & (UML_NT_LAZYFILE_RUN - 1)) != 0)
		return -1;
	if (addr < rstart || addr >= rend || rstart >= rend)
		return -1;
	rv = addr & ~(UML_NT_LAZYFILE_RUN - 1);
	if (rv < rstart)
		rv = rstart;
	re = rv + UML_NT_LAZYFILE_RUN;
	if (re > rend)
		re = rend;
	if (re <= rv)
		return -1;
	*run_va = rv;
	*run_end = re;
	return 0;
}

/* Bytes to read for the window: the region's file offset base plus
 * the VA delta, clamped at EOF. 0 = a hole beyond EOF (the run is
 * already zeroed by the caller). */
static inline unsigned long long
uml_nt_lazy_read_len(unsigned long long rstart,
		     unsigned long long foff_base,
		     unsigned long long fsize,
		     unsigned long long run_va,
		     unsigned long long run_len)
{
	unsigned long long foff, avail;

	if (run_va < rstart)
		return 0;
	foff = foff_base + (run_va - rstart);
	if (foff >= fsize)
		return 0;
	avail = fsize - foff;
	return (avail < run_len) ? avail : run_len;
}

#endif /* UML_NT_LAZYFILE_MODEL_H */
