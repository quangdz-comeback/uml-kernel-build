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
	/* D20 cluster 1: what a dynamic starter needs to know about
	 * THIS image — the base it loaded at (0 for an ET_EXEC linked
	 * inside the window), the VA of its program header table as
	 * loaded (0 when no PT_LOAD covers e_phoff), and the phdr
	 * count. AT_PHDR/AT_PHNUM/AT_BASE feed from these. */
	unsigned long long base;
	unsigned long long phdr_va;
	unsigned long long phnum;
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
 * D20 cluster 1: the PT_INTERP path of `image` — 0 = none (static),
 * 1 = the absolute path copied into `out` (NUL-terminated, out_cap
 * checked), negative = a broken interp segment (bounds/NUL/absolute
 * violations). Pure logic — unit-tested.
 */
int uml_nt_elf_interp_path(const void *image, unsigned long long len,
			   char *out, unsigned out_cap);

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
 * D20 cluster 1: the auxv entries beyond the always-present
 * {AT_RANDOM, AT_PAGESZ, AT_NULL} — the set a dynamic starter
 * (ld.so/ld-musl) reads: it relocates itself from AT_BASE, walks the
 * MAIN program's phdrs from AT_PHDR, jumps to AT_ENTRY, and glibc
 * additionally takes the ids/AT_EXECFN. All plain values; execfn is
 * the plain filename string (copied into the strings area when
 * non-NULL).
 */
struct uml_nt_elf_auxv {
	unsigned long long at_base;  /* AT_BASE — interp load base, 0 static */
	unsigned long long at_entry; /* AT_ENTRY — the main program */
	unsigned long long at_phdr;  /* AT_PHDR — main phdr table VA */
	unsigned long long at_phnum; /* AT_PHNUM */
	const char *execfn;          /* AT_EXECFN string; NULL = omit */
	unsigned uid, euid, gid, egid;
	unsigned secure;             /* AT_SECURE */
};

/*
 * Build the SysV x86-64 process-start block at the TOP of the stack
 * run (S3, the create_elf_tables analogue): argc, argv/envp pointer
 * vectors (NULL-terminated), the full auxv (D20: {AT_PHDR, AT_PHENT,
 * AT_PHNUM, AT_BASE, AT_ENTRY, AT_UID, AT_EUID, AT_GID, AT_EGID,
 * AT_SECURE, AT_HWCAP, AT_CLKTCK, AT_EXECFN, AT_RANDOM, AT_PAGESZ,
 * AT_NULL}) and the strings + 16 random bytes above them; rsp lands
 * 16-aligned. `dst` = the stack run through the flat view, `va_base`
 * = the guest VA of dst[0], `cap` = the run size, `rand16` = the
 * AT_RANDOM bytes. argv/envp are main()-style NULL-terminated
 * (counted by walking to the NULL). `ax` = the D20 auxv fields
 * (pass a zeroed struct for the minimal static shape). Returns the
 * bytes used (rsp = stack_top - used) or -1 on overflow.
 * Pure logic — unit-tested (the binfmt passes bprm's argv/envp;
 * S3 passes argc=0).
 */
long long uml_nt_elf_stack_tables(void *dst, unsigned long long va_base,
				  unsigned long long cap, int argc,
				  const char *const *argv,
				  const char *const *envp,
				  const unsigned char *rand16,
				  const struct uml_nt_elf_auxv *ax);

/* argv+envp entries the stack block can hold (the tables' cap; shared
 * with the splitter's bounds check). */
#define UML_NT_ELF_MAX_STR 64

/*
 * Split the packed exec-string blob copy_strings left in the bprm
 * mm's stack pages (S4): argv[0..argc-1], envp[0..envc-1], then the
 * filename, all NUL-terminated with no gaps (copy_strings walks
 * backward from the stack top, so argv[0] is the lowest string and
 * the filename the highest). `blob`/`len` = the raw bytes; the out
 * arrays (caller-allocated, argc/envc entries at least) point INTO
 * the blob. 0 on success, -1 when the counts do not line up with the
 * blob (wrong argc/envc, truncated string) — fail loud, never guess.
 * Pure logic — unit-tested.
 */
int uml_nt_elf_split_args(unsigned char *blob, unsigned long long len,
			  int argc, int envc, const char **out_argv,
			  const char **out_envp);

#endif /* __UM_OS_WINDOWS_ELF_H */
