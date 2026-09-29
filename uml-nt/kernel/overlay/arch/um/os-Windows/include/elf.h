/* SPDX-License-Identifier: GPL-2.0 */
/*
 * elf.h — guest ELF64 loader (M3.4), uml-nt.
 *
 * Upstream analogue: loading the guest init into a memfd and
 * execveat'ing it (arch/um os-Linux: the stub is execveat'd from a
 * memfd; later guest execve is the guest kernel's own job). On NT the
 * kernel-side loader plays BOTH roles for the POC: it parses an ELF64
 * image (the execveat(memfd) source), hands every PT_LOAD a contiguous
 * run span from the kernel page allocator (D11: guest pages ARE
 * kernel pages; D12: spans are buddy blocks), copies file bytes into
 * the section through the kernel's flat view, zero-fills the tails
 * (bss) and records one VMA per merged load region in the target mm.
 *
 * The SOURCE of the image bytes is the caller's problem: M3.4 uses the
 * launcher path (launcher.exe reads the file, hands a section in the
 * boot info — the kernel maps it read-only and parses from there);
 * from M3.5 on, rootfs blobs arrive through ubd. `image` is just
 * bytes.
 *
 * Geometry (vma.h contract): load regions expand outward to 64K-run
 * boundaries; segments sharing a run MERGE into one VMA (union of
 * protections) so every VMA stays a run-multiple backed by one
 * contiguous span.
 *
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI
 * (phys backend mocked).
 */
#ifndef __UM_OS_WINDOWS_ELF_H
#define __UM_OS_WINDOWS_ELF_H

#include <physalloc.h>
#include <vma.h>

/* Fixed load-region table: a real static binary has ~4 PT_LOADs
 * (separate-code RWX split); the cap exists so malformed inputs fail
 * loud instead of smearing. */
#define UML_NT_ELF_MAX_SEG 16

/* Error codes: distinct on purpose — native failures print the rc and
 * every bit of "which check fired" saves a CI round-trip. */
#define UML_NT_ELF_OK        0
#define UML_NT_ELF_TRUNC   (-1) /* image shorter than the headers claim */
#define UML_NT_ELF_MAGIC   (-2) /* not ELF / not 64-bit / not LE */
#define UML_NT_ELF_KIND    (-3) /* not ET_EXEC/ET_DYN, not EM_X86_64 */
#define UML_NT_ELF_PHDRS   (-4) /* phdr table out of bounds/shape */
#define UML_NT_ELF_VA      (-5) /* segment outside the guest VA span */
#define UML_NT_ELF_SEG     (-6) /* too many regions / bad segment */
#define UML_NT_ELF_NOMEM   (-7) /* phys backend exhausted */
#define UML_NT_ELF_MM      (-8) /* VMA table full / collision */

/* One merged, run-aligned load region: [start, end) guest VA backed
 * by the contiguous span at run_off with `prot` (NT PAGE_*). */
struct uml_nt_elf_seg {
	unsigned long long start, end;
	unsigned long long run_off;
	unsigned prot;
};

struct uml_nt_elf_image {
	unsigned long long entry;   /* guest entry VA (base added for DYN) */
	unsigned long long brk;     /* first free VA past the last region */
	unsigned long long stack_top; /* set by uml_nt_elf_stack_place */
	int nseg;
	struct uml_nt_elf_seg seg[UML_NT_ELF_MAX_SEG];
};

/*
 * Load `image` (len bytes) into `mm` (fresh — ET_DYN picks a first-fit
 * base above existing VMAs) backed by `ph` runs, copying bytes through
 * `section` (the kernel's flat physmem view; the unit test hands a
 * stand-in buffer). Zero-fills every region before copying PT_LOAD
 * file bytes (bss contract — even though the kernel backend zeroes
 * via __GFP_ZERO, the test's stand-in buffer does not).
 *
 * On failure the mm is left empty (VMAs added so far are removed and
 * their spans freed) — the caller fails loud.
 */
int uml_nt_elf_load(struct uml_nt_elf_image *out, struct uml_nt_mm *mm,
		    struct uml_nt_phys *ph, const void *image,
		    unsigned long long len, void *section);

/*
 * Place the guest stack: one fresh run immediately above the highest
 * region (the execve analogue — the stack belongs to the image being
 * loaded), VMA added RW, *top_out = first byte PAST the run (the
 * initial rsp). Returns UML_NT_ELF_OK or a failure code.
 */
int uml_nt_elf_stack_place(struct uml_nt_elf_image *img,
			   struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			   unsigned long long *top_out);

/*
 * Build the SysV x86-64 process-start block at the TOP of the stack
 * run (S3, the create_elf_tables analogue): argc, argv/envp pointer
 * vectors (NULL-terminated), auxv {AT_RANDOM, AT_PAGESZ, AT_NULL} and
 * the strings + 16 random bytes above them; rsp lands 16-aligned.
 * `dst` = the stack run through the flat view, `va_base` = the guest
 * VA of dst[0], `cap` = the run size, `rand16` = the AT_RANDOM bytes.
 * argv/envp are main()-style NULL-terminated (counted by walking to
 * the NULL). Returns the bytes used (rsp = stack_top - used) or -1
 * on overflow.
 * Pure logic — unit-tested (the binfmt passes bprm's argv/envp;
 * S3 passes argc=0).
 */
long long uml_nt_elf_stack_tables(void *dst, unsigned long long va_base,
				  unsigned long long cap, int argc,
				  const char *const *argv,
				  const char *const *envp,
				  const unsigned char *rand16);

#endif /* __UM_OS_WINDOWS_ELF_H */
