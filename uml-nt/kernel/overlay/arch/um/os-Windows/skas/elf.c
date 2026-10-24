// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/elf.c — guest ELF64 loader (M3.4). See elf.h for
 * the model: PT_LOAD segments → run-aligned (merged) regions → one
 * contiguous span each (D11/D12: buddy pages, dynamic offsets) → one
 * VMA per region; bytes copied through the caller's flat section view.
 *
 * Everything is bounds-checked against `len` and the guest VA span —
 * a malformed image fails with a distinct code, never by trusting a
 * field. All allocations roll back on failure (spans unref'd, mm left
 * untouched). This module is pure logic: the unit test compiles it
 * standalone (phys backend mocked) against hand-built and real
 * linker-produced ELFs.
 */
#include <elf.h>
#include <fault.h> /* UML_NT_STACK_RLIMIT (the Linux-shaped stack) */

/* ELF64 constants + the two on-disk structs we touch (naturally
 * aligned — sizes asserted below; no host headers, D1). */
#define EI_NIDENT 16
#define ET_EXEC   2
#define ET_DYN    3
#define EM_X86_64 62
#define PT_LOAD   1
#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	unsigned short e_type, e_machine;
	unsigned int e_version;
	unsigned long long e_entry, e_phoff, e_shoff;
	unsigned int e_flags;
	unsigned short e_ehsize, e_phentsize, e_phnum, e_shentsize,
		       e_shnum, e_shstrndx;
} elf_ehdr;

typedef struct {
	unsigned int p_type, p_flags;
	unsigned long long p_offset, p_vaddr, p_paddr, p_filesz,
			   p_memsz, p_align;
} elf_phdr;

_Static_assert(sizeof(elf_ehdr) == 64, "ELF64 ehdr layout");
_Static_assert(sizeof(elf_phdr) == 56, "ELF64 phdr layout");

#define RUN UML_NT_PHYS_RUN_SIZE

#define PT_INTERP 3

/* WRITER-HUNT (M5.6a): the fill-guard's last failure context (pure
 * file — no os_info here; binfmt.c logs these when a load fails with
 * UML_NT_ELF_FILL). Zeroed by every load entry. */
int uml_nt_elf_fill_region;
unsigned long long uml_nt_elf_fill_off, uml_nt_elf_fill_len;

/* FILL VERIFY (M5.6a writer-hunt follow-up): the loader's copy is
 * checked against the source image AFTER every PT_LOAD piece landed —
 * a mis-computed destination offset or an overlap between regions
 * would otherwise be baked into the imgwatch baseline and never seen.
 * Pure file: set the globals, binfmt.c logs them. Budgeted: the first
 * 1024 image loads (both images per exec count once each) — the
 * login-depth deaths sit at the END of a ~140-load boot. */
int uml_nt_elf_verify_bad;
int uml_nt_elf_verify_region;
unsigned long long uml_nt_elf_verify_off, uml_nt_elf_verify_file_off;
unsigned long long uml_nt_elf_verify_len, uml_nt_elf_verify_diff;
unsigned long long uml_nt_elf_verify_want, uml_nt_elf_verify_got;
static int uml_nt_elf_verify_left = 1024;

/*
 * D20 cluster 1: the PT_INTERP path of `image` — a dynamic binary
 * names its interpreter there. Returns 0 = none, 1 = the path copied
 * into `out` (NUL-terminated, must start with '/'), negative = a
 * broken segment (bounds/NUL violations — fail loud BEFORE
 * begin_new_exec, where the failure is still recoverable). Pure
 * logic — unit-tested.
 */
int uml_nt_elf_interp_path(const void *image, unsigned long long len,
			   char *out, unsigned out_cap)
{
	const unsigned char *img = image;
	const elf_ehdr *eh;
	const elf_phdr *phd;
	unsigned long long off, n, e_off, e_len;
	unsigned i;

	if (out_cap == 0)
		return -1;
	out[0] = '\0';
	if (len < sizeof(elf_ehdr) + sizeof(elf_phdr))
		return -1;
	eh = (const elf_ehdr *)img;
	if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' ||
	    eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F' ||
	    eh->e_ident[4] != 2 || eh->e_ident[5] != 1)
		return -1;
	if (eh->e_phentsize != sizeof(elf_phdr) || eh->e_phnum == 0 ||
	    eh->e_phnum == 0xffff)
		return -1;
	e_off = eh->e_phoff;
	e_len = (unsigned long long)eh->e_phnum * sizeof(elf_phdr);
	if (e_off > len || e_len > len - e_off)
		return -1;
	phd = (const elf_phdr *)(img + e_off);
	for (i = 0; i < eh->e_phnum; i++) {
		if (phd[i].p_type != PT_INTERP)
			continue;
		off = phd[i].p_offset;
		n = phd[i].p_filesz;
		if (n < 2 || off > len || n > len - off)
			return -1;
		if (img[off] != '/' || img[off + n - 1] != '\0')
			return -1;
		if (n > out_cap)
			return -1;
		__builtin_memcpy(out, img + off, n);
		return 1;
	}
	return 0;
}

static unsigned long long floor_run(unsigned long long va)
{
	return va & ~(RUN - 1);
}

static unsigned long long ceil_run(unsigned long long va)
{
	return (va + RUN - 1) & ~(RUN - 1);
}

/* NT PAGE_* from unioned p_flags — the single mapping used both per
 * segment and per merged region (merging ORs the FLAGS, then maps:
 * NT PAGE_* values are not a lattice — OR of 0x02|0x20 is no
 * protection). */
static unsigned prot_from_flags(unsigned f)
{
	if (f & PF_W)
		return (f & PF_X) ? 0x40u /* EXECUTE_READWRITE */
				  : 0x04u /* READWRITE */;
	if (f & PF_X)
		return (f & PF_R) ? 0x20u /* EXECUTE_READ */
				  : 0x10u /* EXECUTE */;
	if (f & PF_R)
		return 0x02u; /* READONLY */
	return 0x01u;     /* NOACCESS — broken segment, loud on touch */
}

/* Internal relative region (image-VA space), built sorted+merged. */
struct reg {
	unsigned long long rs, re;
	unsigned flags;
};

/* First-fit run-aligned [cur, cur+size) free of every VMA, scanning
 * up from the guest VA base (D11: nothing is assumed about where
 * earlier allocations landed — we ASK the mm). */
static unsigned long long find_free_base(const struct uml_nt_mm *mm,
					 unsigned long long size)
{
	unsigned long long cur = UML_NT_GUEST_VA_BASE;
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (size <= mm->vma[i].start - cur)
			return cur;
		if (mm->vma[i].end > cur)
			cur = ceil_run(mm->vma[i].end);
	}
	return cur;
}

static int overlaps_existing(const struct uml_nt_mm *mm,
			     unsigned long long s, unsigned long long e)
{
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (s < mm->vma[i].end && e > mm->vma[i].start)
			return 1;
	}
	return 0;
}

static void unref_region_span(struct uml_nt_phys *ph,
			      unsigned long long off,
			      unsigned long long len)
{
	unsigned long long r;

	for (r = 0; r < len; r += RUN)
		uml_nt_phys_unref(ph, (long long)(off + r));
}

int uml_nt_elf_load(struct uml_nt_elf_image *out, struct uml_nt_mm *mm,
		    struct uml_nt_phys *ph, const void *image,
		    unsigned long long len, void *section)
{
	const unsigned char *img = image;
	const elf_ehdr *eh;
	const elf_phdr *phd;
	struct reg regs[UML_NT_ELF_MAX_SEG];
	unsigned long long offs[UML_NT_ELF_MAX_SEG];
	unsigned long long base, span_end, e_off, e_len, entry;
	unsigned long long min_w_page = ~0ULL;
	int nreg = 0, i, j, phn;

	out->nseg = 0;
	out->entry = 0;
	out->brk = 0;
	out->base = 0;
	out->phdr_va = 0;
	out->phnum = 0;
	uml_nt_elf_verify_bad = 0;

	/* ---- header + phdr table validation (all bounds first) ---- */
	if (len < sizeof(elf_ehdr) + sizeof(elf_phdr))
		return UML_NT_ELF_TRUNC;
	eh = (const elf_ehdr *)img;
	if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' ||
	    eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F' ||
	    eh->e_ident[4] != 2 /* ELFCLASS64 */ ||
	    eh->e_ident[5] != 1 /* little-endian */)
		return UML_NT_ELF_MAGIC;
	if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN)
		return UML_NT_ELF_KIND;
	if (eh->e_machine != EM_X86_64)
		return UML_NT_ELF_KIND;
	if (eh->e_phentsize != sizeof(elf_phdr) || eh->e_phnum == 0 ||
	    eh->e_phnum == 0xffff /* PN_XNUM — extended count unsupported */)
		return UML_NT_ELF_PHDRS;
	phn = (int)eh->e_phnum;
	e_off = eh->e_phoff;
	e_len = (unsigned long long)phn * sizeof(elf_phdr);
	if (e_off > len || e_len > len - e_off)
		return UML_NT_ELF_PHDRS;
	phd = (const elf_phdr *)(img + e_off);

	/* ---- PT_LOADs → sorted, merged run-aligned regions ------- */
	for (i = 0; i < phn; i++) {
		const elf_phdr *p = &phd[i];
		unsigned long long rs, re;

		if (p->p_type != PT_LOAD || p->p_memsz == 0)
			continue;
		if (p->p_memsz < p->p_filesz)
			return UML_NT_ELF_SEG;
		if (p->p_offset > len ||
		    p->p_filesz > len - p->p_offset)
			return UML_NT_ELF_TRUNC;
		/* image-VA space (base added later); wrap-checked. */
		if (p->p_vaddr > (unsigned long long)-1 - p->p_memsz)
			return UML_NT_ELF_VA;
		rs = floor_run(p->p_vaddr);
		re = ceil_run(p->p_vaddr + p->p_memsz);
		/* IMGWATCH: first writable PAGE of the image — every
		 * run wholly below it is content-stable post-load. */
		if (p->p_flags & PF_W) {
			unsigned long long wp =
				p->p_vaddr & ~0xFFFULL;

			if (wp < min_w_page)
				min_w_page = wp;
		}

		for (j = 0; j < nreg; j++) {
			if (rs < regs[j].re && re > regs[j].rs) {
				/* overlap → merge (segments sharing a
				 * run must share one VMA + span) */
				if (rs < regs[j].rs)
					regs[j].rs = rs;
				if (re > regs[j].re)
					regs[j].re = re;
				regs[j].flags |= p->p_flags;
				goto merged;
			}
		}
		if (nreg >= UML_NT_ELF_MAX_SEG)
			return UML_NT_ELF_SEG;
		/* sorted insert (rs ascending) */
		for (j = nreg; j > 0 && rs < regs[j - 1].rs; j--)
			regs[j] = regs[j - 1];
		regs[j].rs = rs;
		regs[j].re = re;
		regs[j].flags = p->p_flags;
		nreg++;
merged:
		;
	}
	if (nreg == 0)
		return UML_NT_ELF_SEG;

	/* ---- base: ET_EXEC loads as linked; ET_DYN picks first-fit
	 * above the mm's existing VMAs (PIE analogue) -------------- */
	if (eh->e_type == ET_EXEC) {
		/* S3: real static binaries link at 0x400000 — BELOW the
		 * guest window (the stub can only back VAs inside
		 * [UML_NT_GUEST_VA_BASE, base+size): per-VMA views of
		 * the section). Shift the whole image into the window
		 * instead of failing the VA check — same arithmetic as
		 * the ET_DYN base, just a fixed one. Images already
		 * linked inside the window (the M3.4 probe guest) load
		 * exactly as before. */
		base = (regs[0].rs < UML_NT_GUEST_VA_BASE) ?
		       UML_NT_GUEST_VA_BASE : 0;
	} else {
		unsigned long long rel = regs[0].rs;
		unsigned long long size = regs[nreg - 1].re - rel;
		unsigned long long at = find_free_base(mm, size);

		base = at - rel;
	}

	/* ---- span containment + collision with existing VMAs ----- */
	span_end = UML_NT_GUEST_VA_BASE + ph->size;
	for (i = 0; i < nreg; i++) {
		unsigned long long s = regs[i].rs + base;
		unsigned long long e = regs[i].re + base;

		if (s < base || /* wrap */
		    s < UML_NT_GUEST_VA_BASE || e > span_end || e < s)
			return UML_NT_ELF_VA;
		if (overlaps_existing(mm, s, e))
			return UML_NT_ELF_MM;
	}

	/* ---- entry must land inside a region; brk past the last --- */
	entry = eh->e_entry + base;
	for (i = 0; i < nreg; i++) {
		if (entry >= regs[i].rs + base &&
		    entry < regs[i].re + base)
			break;
	}
	if (i == nreg || entry < base)
		return UML_NT_ELF_VA;

	/* ---- D20: where the phdr table landed (AT_PHDR) ---------- */
	out->base = base;
	out->phnum = (unsigned long long)phn;
	for (i = 0; i < phn; i++) {
		const elf_phdr *p = &phd[i];

		if (p->p_type != PT_LOAD || p->p_filesz == 0)
			continue;
		if (e_off >= p->p_offset &&
		    e_off + e_len <= p->p_offset + p->p_filesz) {
			out->phdr_va = base + p->p_vaddr +
				       (e_off - p->p_offset);
			break;
		}
	}

	/* ---- allocate the spans (contiguous blocks, D12) ----------
	 * If a multi-run merged region fails high-order buddy allocation
	 * (e.g. systemd-udevd's 22-run merged image requesting order 9
	 * under fragmentation), subdivide the region at the largest
	 * power-of-2 run count < nruns and retry down to 1-run pieces. */
	for (i = 0; i < nreg; i++) {
		int nruns = (int)((regs[i].re - regs[i].rs) / RUN);
		long long off = uml_nt_phys_alloc_span(ph, nruns);

		while (off < 0 && nruns > 1 && nreg < UML_NT_ELF_MAX_SEG) {
			int split = 1;
			unsigned long long mid;

			while ((split << 1) < nruns)
				split <<= 1;
			mid = regs[i].rs + (unsigned long long)split * RUN;
			for (j = nreg; j > i + 1; j--)
				regs[j] = regs[j - 1];
			regs[i + 1].rs = mid;
			regs[i + 1].re = regs[i].re;
			regs[i + 1].flags = regs[i].flags;
			regs[i].re = mid;
			nreg++;
			nruns = split;
			off = uml_nt_phys_alloc_span(ph, nruns);
		}
		if (off < 0) {
			for (j = 0; j < i; j++)
				unref_region_span(ph, offs[j],
						  regs[j].re - regs[j].rs);
			return UML_NT_ELF_NOMEM;
		}
		offs[i] = (unsigned long long)off;
	}

	/* ---- zero every region (bss contract), copy file bytes ----
	 * WRITER-HUNT (M5.6a): the loader's bulk fills — the memset
	 * and every segment memcpy below — must stay inside the
	 * region's allocated span. A crossing is the direct-write
	 * heap-trasher caught at the exec/loader phase: refuse (fail
	 * UML_NT_ELF_FILL), roll the spans back like every failure
	 * path, and park the context in the globals for the caller's
	 * log. */
	for (i = 0; i < nreg; i++) {
		if (uml_nt_phys_block_check(ph, (long long)offs[i],
					    regs[i].re - regs[i].rs) < 0) {
			uml_nt_elf_fill_region = i;
			uml_nt_elf_fill_off = offs[i];
			uml_nt_elf_fill_len =
				regs[i].re - regs[i].rs;
			for (j = 0; j < nreg; j++)
				unref_region_span(ph, offs[j],
						  regs[j].re - regs[j].rs);
			return UML_NT_ELF_FILL;
		}
		__builtin_memset((char *)section + offs[i], 0,
				 regs[i].re - regs[i].rs);
	}
	for (i = 0; i < phn; i++) {
		const elf_phdr *p = &phd[i];
		unsigned long long va, seg_end, copied = 0;
		int k;

		if (p->p_type != PT_LOAD || p->p_filesz == 0)
			continue;
		va = p->p_vaddr + base;
		seg_end = va + p->p_filesz;
		for (k = 0; k < nreg; k++) {
			unsigned long long rs = regs[k].rs + base;
			unsigned long long re = regs[k].re + base;
			unsigned long long cs = (va > rs) ? va : rs;
			unsigned long long ce = (seg_end < re) ? seg_end : re;

			if (cs >= ce)
				continue;
			__builtin_memcpy((char *)section + offs[k] + (cs - rs),
					 img + p->p_offset + (cs - va),
					 ce - cs);
			copied += ce - cs;
		}
		if (copied != p->p_filesz)
			goto fail_copy;
	}

	/* ---- FILL VERIFY (M5.6a writer-hunt follow-up): every PT_LOAD
	 * piece must still equal the source image now that all copies
	 * landed. A wrong destination offset or a region overlap makes
	 * the loaded text differ from the file BEFORE any guest runs —
	 * the imgwatch baseline would capture the damage and later
	 * comparisons would look clean. Budgeted; binfmt logs. */
	if (uml_nt_elf_verify_left > 0) {
		uml_nt_elf_verify_left--;
		uml_nt_elf_verify_bad = 0;
		for (i = 0; i < phn && !uml_nt_elf_verify_bad; i++) {
			const elf_phdr *p = &phd[i];
			unsigned long long va, seg_end;
			int k;

			if (p->p_type != PT_LOAD || p->p_filesz == 0)
				continue;
			va = p->p_vaddr + base;
			seg_end = va + p->p_filesz;
			for (k = 0; k < nreg; k++) {
				unsigned long long rs = regs[k].rs + base;
				unsigned long long re = regs[k].re + base;
				unsigned long long cs = (va > rs) ? va : rs;
				unsigned long long ce = (seg_end < re) ?
							seg_end : re;
				unsigned long long foff, d;

				if (cs >= ce)
					continue;
				foff = p->p_offset + (cs - va);
				if (__builtin_memcmp((char *)section +
						     offs[k] + (cs - rs),
						     img + foff,
						     ce - cs) == 0)
					continue;
				for (d = 0; d < ce - cs; d++)
					if (((const unsigned char *)section)
					    [offs[k] + (cs - rs) + d] !=
					    ((const unsigned char *)img)
					    [foff + d])
						break;
				uml_nt_elf_verify_bad = 1;
				uml_nt_elf_verify_region = k;
				uml_nt_elf_verify_off =
					offs[k] + (cs - rs);
				uml_nt_elf_verify_file_off = foff;
				uml_nt_elf_verify_len = ce - cs;
				uml_nt_elf_verify_diff = d;
				uml_nt_elf_verify_want =
					((const unsigned char *)img)
					[foff + d];
				uml_nt_elf_verify_got =
					((const unsigned char *)section)
					[offs[k] + (cs - rs) + d];
				break;
			}
		}
	}

	/* ---- publish out + one VMA per region (fresh, no COW) ---- */
	for (i = 0; i < nreg; i++) {
		unsigned long long ro_end =
			(min_w_page < regs[i].re) ? min_w_page : regs[i].re;

		out->seg[i].start = regs[i].rs + base;
		out->seg[i].end = regs[i].re + base;
		out->seg[i].run_off = offs[i];
		out->seg[i].prot = prot_from_flags(regs[i].flags);
		out->seg[i].ro_runs = (ro_end > regs[i].rs) ?
			(unsigned int)((ro_end - regs[i].rs) / RUN) : 0;
	}
	out->nseg = nreg;
	out->entry = entry;
	out->brk = regs[nreg - 1].re + base;
	for (i = 0; i < nreg; i++) {
		if (uml_nt_vma_add_gen(mm, out->seg[i].start,
				       out->seg[i].end,
				       out->seg[i].run_off,
				       out->seg[i].prot, 0,
				       (unsigned long long)uml_nt_phys_gen(
					       ph,
					       (long long)out->seg[i]
							       .run_off)) < 0) {
			/* roll back: partial adds out, spans freed */
			for (j = 0; j < i; j++)
				uml_nt_vma_del(mm, out->seg[j].start,
					       out->seg[j].end);
			for (j = 0; j < nreg; j++)
				unref_region_span(ph, offs[j],
						  regs[j].re - regs[j].rs);
			out->nseg = 0;
			return UML_NT_ELF_MM;
		}
	}
	return UML_NT_ELF_OK;

fail_copy:
	for (j = 0; j < nreg; j++)
		unref_region_span(ph, offs[j], regs[j].re - regs[j].rs);
	return UML_NT_ELF_SEG;
}

int uml_nt_elf_stack_place(struct uml_nt_elf_image *img,
			   struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			   unsigned long long *top_out)
{
	unsigned long long hi = UML_NT_GUEST_VA_BASE, va, off;
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (mm->vma[i].end > hi)
			hi = mm->vma[i].end;
	}
	va = ceil_run(hi);
	if (va < hi)
		return UML_NT_ELF_MM; /* wrapped — absurd image size */
	/* THE GAP (Shelley 154): the stack's reservation must be memory
	 * the process does NOT otherwise own, exactly like Linux where
	 * the stack lives far above every library. Our layout is
	 * compact — the interpreter ends right where the stack used to
	 * begin — and that adjacency is what let a deep stack excursion
	 * land on ld.so's own text instead of faulting. Leaving the
	 * reservation empty below the committed run makes an excursion
	 * a real fault, which uml_nt_stack_grow() then commits. */
	va += UML_NT_STACK_RLIMIT;
	if (va < hi + UML_NT_STACK_RLIMIT)
		return UML_NT_ELF_MM; /* wrapped */
	off = uml_nt_phys_alloc_span(ph, 1);
	if (off < 0)
		return UML_NT_ELF_NOMEM;
	if (uml_nt_vma_add_gen(mm, va, va + RUN, (unsigned long long)off,
			       0x04u /* READWRITE */, 0,
			       (unsigned long long)uml_nt_phys_gen(ph,
								   off)) < 0) {
		uml_nt_phys_unref(ph, off);
		return UML_NT_ELF_MM;
	}
	*top_out = va + RUN;
	img->stack_top = va + RUN;
	/* THE LINUX-SHAPED STACK (fault.h): the committed run above is
	 * only the TOP of the stack. The reservation below it is
	 * RLIMIT_STACK (8 MiB) and is committed lazily by
	 * uml_nt_stack_grow() — reservation is NOT commitment, so
	 * mem=120M is untouched. On Linux the stack VMA already spans
	 * the whole reservation and grows on fault; the shape is what
	 * matters (a stack excursion of a few hundred KiB is ordinary),
	 * and the 64 KiB-only shape is exactly what turned the dynamic
	 * linker's XSAVE save area into a write over ld.so's text. */
	mm->stack_top = va + RUN;
	mm->stack_limit = (mm->stack_top > UML_NT_STACK_RLIMIT) ?
		mm->stack_top - UML_NT_STACK_RLIMIT : UML_NT_GUEST_VA_BASE;
	if (mm->stack_limit < UML_NT_GUEST_VA_BASE)
		mm->stack_limit = UML_NT_GUEST_VA_BASE;
	/* top - RLIMIT is exactly the gap's start: the whole reservation
	 * below the committed run is unmapped until a fault grows it. */
	mm->stack_limit = ceil_run(mm->stack_limit);
	if (mm->stack_limit + UML_NT_STACK_RLIMIT < mm->stack_top)
		mm->stack_limit = mm->stack_top - UML_NT_STACK_RLIMIT;
	return UML_NT_ELF_OK;
}

/* ---- S3: the SysV x86-64 process-start stack ----------------------- */

/* auxv tags (asm-generic/auxvec.h / the x86-64 ABI). */
#define AT_NULL   0
#define AT_PHDR   3
#define AT_PHENT  4
#define AT_PHNUM  5
#define AT_PAGESZ 6
#define AT_BASE   7
#define AT_ENTRY  9
#define AT_UID    11
#define AT_EUID   12
#define AT_GID    13
#define AT_EGID   14
#define AT_HWCAP  16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_RANDOM 25
#define AT_EXECFN 31

/* D20 cluster 1: 16 pairs — the full set a dynamic starter reads. */
#define UML_NT_ELF_AUXV_PAIRS 16

/* Build the initial user stack block at the TOP of the stack run —
 * the exact layout _start expects at rsp (SysV x86-64 ABI / binfmt_elf
 * create_elf_tables analogue):
 *
 *   rsp+0       argc
 *   rsp+8..     argv[0..argc-1] pointers, NULL
 *               envp[0..n-1] pointers, NULL
 *               auxv: AT_PHDR/AT_PHENT/AT_PHNUM/AT_BASE/AT_ENTRY/
 *                     AT_UID/AT_EUID/AT_GID/AT_EGID/AT_SECURE/
 *                     AT_HWCAP/AT_CLKTCK/AT_EXECFN/AT_RANDOM/
 *                     AT_PAGESZ/AT_NULL (D20)
 *   ...pad 16-align...
 *   strings: argv bytes, envp bytes, execfn, 16 AT_RANDOM bytes
 *   top
 *
 * `dst` is the stack run through the kernel's flat view, `va_base`
 * the guest VA of dst[0], `cap` the run size. rand16 is the 16
 * AT_RANDOM bytes (get_random_bytes at the caller; the tables stay
 * pure for unit tests). `ax` carries the D20 fields (the interp
 * base, the main program's entry/phdrs, ids — a zeroed struct for
 * the minimal static shape). Returns the bytes used — rsp =
 * stack_top - used, 16-aligned — or -1 on overflow (loud, never
 * truncate).
 *
 * The S3 init reads none of this (argc=0 is passed); the layout is
 * the real ABI from day one so S4 (busybox argv) only wires bprm
 * strings in. */
long long uml_nt_elf_stack_tables(void *dst, unsigned long long va_base,
				  unsigned long long cap, int argc,
				  const char *const *argv,
				  const char *const *envp,
				  const unsigned char *rand16,
				  const struct uml_nt_elf_auxv *ax)
{
	unsigned long long o = cap; /* top-down cursor in dst[] */
	unsigned long long str_va[UML_NT_ELF_MAX_STR];
	unsigned long long rnd_va, execfn_va = 0, vec, i;
	int nenv = 0, n;

	if (argc < 0 || argc > UML_NT_ELF_MAX_STR)
		return -1;
	while (envp != 0 && envp[nenv] != 0) {
		if (nenv >= UML_NT_ELF_MAX_STR - argc)
			return -1;
		nenv++;
	}

	/* strings, top-down */
	for (i = 0; i < (unsigned)argc; i++) {
		n = __builtin_strlen(argv[i]) + 1;
		if ((unsigned long long)n > o)
			return -1;
		o -= n;
		__builtin_memcpy((char *)dst + o, argv[i], n);
		str_va[i] = va_base + o;
	}
	for (i = 0; i < (unsigned)nenv; i++) {
		n = __builtin_strlen(envp[i]) + 1;
		if ((unsigned long long)n > o)
			return -1;
		o -= n;
		__builtin_memcpy((char *)dst + o, envp[i], n);
		str_va[argc + i] = va_base + o;
	}
	if (ax != 0 && ax->execfn != 0) {
		n = __builtin_strlen(ax->execfn) + 1;
		if ((unsigned long long)n > o)
			return -1;
		o -= n;
		__builtin_memcpy((char *)dst + o, ax->execfn, n);
		execfn_va = va_base + o;
	}
	if (o < 16)
		return -1;
	o -= 16;
	if (rand16 != 0)
		__builtin_memcpy((char *)dst + o, rand16, 16);
	else
		__builtin_memset((char *)dst + o, 0, 16);
	rnd_va = va_base + o;

	/* vectors: argc + (argc+1 argv) + (nenv+1 envp) + auxv pairs */
	vec = (1 + (unsigned)argc + 1 + (unsigned)nenv + 1 +
	       2 * UML_NT_ELF_AUXV_PAIRS) * 8;
	if (vec > o)
		return -1;
	o -= vec;
	/* rsp must be 16-aligned — vec is slot-count*8, NOT always a
	 * 16-multiple (argc=0: 41 slots), so align AFTER. */
	o &= ~(unsigned long long)15;

	{
		unsigned long long *v = (unsigned long long *)
			((char *)dst + o);

		i = 0;
		v[i++] = (unsigned long long)argc;
		for (n = 0; n < argc; n++)
			v[i++] = str_va[n];
		v[i++] = 0; /* argv NULL */
		for (n = 0; n < nenv; n++)
			v[i++] = str_va[argc + n];
		v[i++] = 0; /* envp NULL */
		v[i++] = AT_PHDR;
		v[i++] = (ax != 0) ? ax->at_phdr : 0;
		v[i++] = AT_PHENT;
		v[i++] = sizeof(elf_phdr); /* 56 */
		v[i++] = AT_PHNUM;
		v[i++] = (ax != 0) ? ax->at_phnum : 0;
		v[i++] = AT_BASE;
		v[i++] = (ax != 0) ? ax->at_base : 0;
		v[i++] = AT_ENTRY;
		v[i++] = (ax != 0) ? ax->at_entry : 0;
		v[i++] = AT_UID;
		v[i++] = (ax != 0) ? ax->uid : 0;
		v[i++] = AT_EUID;
		v[i++] = (ax != 0) ? ax->euid : 0;
		v[i++] = AT_GID;
		v[i++] = (ax != 0) ? ax->gid : 0;
		v[i++] = AT_EGID;
		v[i++] = (ax != 0) ? ax->egid : 0;
		v[i++] = AT_SECURE;
		v[i++] = (ax != 0) ? ax->secure : 0;
		v[i++] = AT_HWCAP;
		v[i++] = 0; /* no features advertised */
		v[i++] = AT_CLKTCK;
		v[i++] = 100;
		v[i++] = AT_EXECFN;
		v[i++] = execfn_va;
		v[i++] = AT_RANDOM;
		v[i++] = rnd_va;
		v[i++] = AT_PAGESZ;
		v[i++] = 4096;
		v[i++] = AT_NULL;
		v[i++] = 0;
	}

	return (long long)(cap - o);
}
