/* test_elf.c — unit tests for the M3.4 guest ELF loader (skas/elf.c):
 * header validation, region merging, ET_DYN base selection, error
 * codes, rollback, stack placement — plus the REAL linker-produced
 * probe guest (guest-init.elf, path in argv[1]) loaded for keeps:
 * its .text must survive the load byte-exact and patch to exactly the
 * expected number of syscall sites (the CI contract depends on it).
 *
 * Compiled with the overlay files as-is on Linux CI (same pattern as
 * test_mm.sh): elf.c + vma.c + physalloc.c + the mocked backend.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fault.h>
#include <vma.h>
#include <physalloc.h>
#include <elf.h>
#include <stub_nt.h>

static int fails;

/* scan_patch.c (compiled into the kernel; the real-guest test sweeps
 * its loaded text — the same contract the kernel probe relies on) */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off);

#define CHECK(cond) do { if (!(cond)) { \
	fails++; \
	printf("FAIL %d: %s\n", __LINE__, #cond); \
} } while (0)

#define RUN  UML_NT_PHYS_RUN_SIZE
#define RAM  UML_NT_GUEST_VA_BASE
/* Guest span the loader enforces (the launcher's mem= default:
 * 128 MiB) — big enough for the real probe guest at 0x62000000. */
#define SPAN 0x8000000ull

/* the two checks D11 leans on: the phys geometry base and the stub
 * protocol span base must never drift apart */
_Static_assert(UML_NT_GUEST_VA_BASE == UML_STUB_RAM_BASE,
	       "guest VA base drift between physalloc.h and stub_nt.h");

/* ---- backend mock (same block-granular buddy as test_mm.c) ------- */

#define MOCK_RUNS 16
#define MOCK_BASE (1ull << 20)
static unsigned char mock_taken[MOCK_RUNS];

static void mock_reset(void)
{
	memset(mock_taken, 0, sizeof(mock_taken));
}

static int mock_need(int nruns)
{
	int k;

	for (k = 0; (1 << k) < nruns; k++)
		;
	return 1 << k;
}

long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	int i, j, need = mock_need(nruns);

	for (i = 0; i + need <= MOCK_RUNS; i++) {
		int ok = 1;

		for (j = 0; j < need; j++) {
			if (mock_taken[i + j]) {
				ok = 0;
				i += j;
				break;
			}
		}
		if (!ok)
			continue;
		for (j = 0; j < need; j++)
			mock_taken[i + j] = 1;
		*page_out = &mock_taken[i];
		return MOCK_BASE + (long long)i * RUN;
	}
	return -1;
}

void uml_nt_phys_backend_free(void *page, int nruns)
{
	int i = (int)((char *)page - (char *)mock_taken);
	int j, need = mock_need(nruns);

	for (j = 0; j < need; j++)
		if (i + j >= 0 && i + j < MOCK_RUNS)
			mock_taken[i + j] = 0;
}

/* ---- synthetic ELF builder ---------------------------------------- */

typedef struct {
	unsigned char e_ident[16];
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

static unsigned char img[16384];
static unsigned char sec[32 * RUN]; /* stand-in flat physmem view */
static int nph;

static elf_ehdr *mk_ehdr(unsigned type, unsigned long long entry)
{
	elf_ehdr *eh;

	memset(img, 0, sizeof(img));
	memset(sec, 0xAA, sizeof(sec)); /* poison: the loader must zero */
	nph = 0;
	eh = (elf_ehdr *)img;
	memcpy(eh->e_ident, "\x7f" "ELF", 4);
	eh->e_ident[4] = 2; /* 64-bit */
	eh->e_ident[5] = 1; /* LE */
	eh->e_type = type;
	eh->e_machine = 62;
	eh->e_version = 1;
	eh->e_entry = entry;
	eh->e_phoff = sizeof(elf_ehdr);
	eh->e_phentsize = sizeof(elf_phdr);
	return eh;
}

static elf_phdr *add_phdr(unsigned flags, unsigned long long off,
			  unsigned long long vaddr,
			  unsigned long long filesz,
			  unsigned long long memsz)
{
	elf_ehdr *eh = (elf_ehdr *)img;
	elf_phdr *p = (elf_phdr *)(img + sizeof(elf_ehdr) +
				   nph * sizeof(elf_phdr));

	p->p_type = 1; /* PT_LOAD */
	p->p_flags = flags;
	p->p_offset = off;
	p->p_vaddr = vaddr;
	p->p_paddr = vaddr;
	p->p_filesz = filesz;
	p->p_memsz = memsz;
	p->p_align = RUN;
	/* file bytes: recognizable per segment */
	memset(img + off, 0x10 + nph, filesz);
	eh->e_phnum = ++nph;
	return p;
}

static void test_exec_basic(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	elf_ehdr *eh;
	int rc;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);
	eh = mk_ehdr(2 /* ET_EXEC */, 0x62000010ull);
	/* RX text: 1 page of file bytes, at a run-aligned VA */
	add_phdr(5 /* R|X */, 0x400, 0x62000000ull, 0x1000, 0x1000);
	/* RW data: 16 file bytes + 0xf0 of bss */
	add_phdr(6 /* R|W */, 0x1400, 0x62010000ull, 0x10, 0x100);
	eh->e_entry = 0x62000010ull;

	rc = uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec);
	CHECK(rc == UML_NT_ELF_OK);
	CHECK(out.nseg == 2);
	CHECK(out.entry == 0x62000010ull);
	CHECK(out.brk == 0x62020000ull);
	/* region 1: EXECUTE_READ, one run, mock's first block */
	CHECK(out.seg[0].start == 0x62000000ull);
	CHECK(out.seg[0].end == 0x62010000ull);
	CHECK(out.seg[0].prot == 0x20u);
	CHECK(out.seg[0].run_off == (unsigned long long)MOCK_BASE);
	/* region 2: READWRITE */
	CHECK(out.seg[1].start == 0x62010000ull);
	CHECK(out.seg[1].end == 0x62020000ull);
	CHECK(out.seg[1].prot == 0x04u);
	CHECK(out.seg[1].run_off == (unsigned long long)MOCK_BASE + RUN);
	/* file bytes landed at the right section offsets */
	CHECK(sec[MOCK_BASE + 0x10] == 0x10);
	CHECK(sec[MOCK_BASE + 0xfff] == 0x10);
	/* bss zero-filled (the 0xAA poison is gone) */
	CHECK(sec[MOCK_BASE + RUN + 0x10] == 0);
	CHECK(sec[MOCK_BASE + RUN + 0xff] == 0);
	/* VMAs: findable with the right prots */
	CHECK(mm.nvma == 2);
	CHECK(uml_nt_vma_find(&mm, 0x62008000ull) == &mm.vma[0]);
	CHECK(mm.vma[0].prot == 0x20u);
	CHECK(uml_nt_vma_find(&mm, 0x62018000ull) == &mm.vma[1]);
	CHECK(mm.vma[1].prot == 0x04u);
}

/* Two segments inside ONE run merge into a single region (one VMA,
 * one span) — the union of the flag bits maps the protection. */
static void test_merge(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	elf_ehdr *eh;
	int rc;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);
	eh = mk_ehdr(2, 0x62000000ull);
	add_phdr(5 /* R|X */, 0x400, 0x62000000ull, 0x800, 0x800);
	add_phdr(4 /* R */, 0xc00, 0x62000800ull, 0x800, 0x800);
	eh->e_entry = 0x62000000ull;

	rc = uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec);
	CHECK(rc == UML_NT_ELF_OK);
	CHECK(out.nseg == 1);
	CHECK(out.seg[0].start == 0x62000000ull);
	CHECK(out.seg[0].end == 0x62010000ull);
	CHECK(out.seg[0].prot == 0x20u); /* R|X union */
	/* both segments' bytes at their exact deltas */
	CHECK(sec[MOCK_BASE + 0x000] == 0x10);
	CHECK(sec[MOCK_BASE + 0x7ff] == 0x10);
	CHECK(sec[MOCK_BASE + 0x800] == 0x11);
	CHECK(sec[MOCK_BASE + 0xfff] == 0x11);
	CHECK(mm.nvma == 1);
}

/* ET_DYN: first-fit base above the mm's existing VMAs; entry/brk
 * follow the base; a second load stacks above the first. */
static void test_dyn(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	elf_ehdr *eh;
	int rc;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);
	eh = mk_ehdr(3 /* ET_DYN */, 0x2040ull);
	add_phdr(5, 0x400, 0x2000ull, 0x1000, 0x1000);
	add_phdr(6, 0x1400, 0x12000ull, 0x10, 0x100);
	eh->e_entry = 0x2040ull;

	rc = uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec);
	CHECK(rc == UML_NT_ELF_OK);
	/* fresh mm → base = the span base */
	CHECK(out.seg[0].start == RAM);
	CHECK(out.seg[1].start == RAM + 0x10000ull);
	CHECK(out.entry == RAM + 0x2040ull);
	CHECK(out.brk == RAM + 0x20000ull);

	/* second DYN load in the same mm: placed above the first */
	eh = mk_ehdr(3, 0x2040ull);
	add_phdr(5, 0x400, 0x2000ull, 0x1000, 0x1000);
	eh->e_entry = 0x2040ull;
	rc = uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec);
	CHECK(rc == UML_NT_ELF_OK);
	CHECK(out.seg[0].start == RAM + 0x20000ull);
	CHECK(out.entry == RAM + 0x22040ull);
	CHECK(mm.nvma == 3);
}

/* Malformed images fail with distinct codes — never by trusting a
 * field. */
static void test_errors(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	elf_ehdr *eh;

#define LOAD() uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec)
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);

	eh = mk_ehdr(2, 0x62000010ull);
	add_phdr(5, 0x400, 0x62000000ull, 0x1000, 0x1000);
	eh->e_entry = 0x62000010ull;

	/* truncated: image shorter than the phdr table claims */
	CHECK(LOAD() == UML_NT_ELF_OK); /* sanity: the base image loads */
	eh->e_phoff = 0x2000; /* == len: no room for the table */
	CHECK(LOAD() == UML_NT_ELF_PHDRS);
	eh->e_phoff = sizeof(elf_ehdr);

	eh->e_ident[0] = 0x7e;
	CHECK(LOAD() == UML_NT_ELF_MAGIC);
	eh->e_ident[0] = 0x7f;
	eh->e_ident[4] = 1; /* 32-bit class */
	CHECK(LOAD() == UML_NT_ELF_MAGIC);
	eh->e_ident[4] = 2;
	eh->e_ident[5] = 2; /* big-endian */
	CHECK(LOAD() == UML_NT_ELF_MAGIC);
	eh->e_ident[5] = 1;

	eh->e_type = 1; /* ET_REL */
	CHECK(LOAD() == UML_NT_ELF_KIND);
	eh->e_type = 2;
	eh->e_machine = 3; /* x86 32-bit */
	CHECK(LOAD() == UML_NT_ELF_KIND);
	eh->e_machine = 62;

	eh->e_phnum = 0;
	CHECK(LOAD() == UML_NT_ELF_PHDRS);
	eh->e_phnum = 0xffff; /* PN_XNUM unsupported */
	CHECK(LOAD() == UML_NT_ELF_PHDRS);
	eh->e_phnum = 1;

	/* segment file range past the image end (memsz kept >= filesz
	 * so the TRUNC check, not the SEG check, fires) */
	((elf_phdr *)(img + eh->e_phoff))->p_filesz = 0x2000;
	((elf_phdr *)(img + eh->e_phoff))->p_memsz = 0x2000;
	CHECK(LOAD() == UML_NT_ELF_TRUNC);
	((elf_phdr *)(img + eh->e_phoff))->p_filesz = 0x1000;
	((elf_phdr *)(img + eh->e_phoff))->p_memsz = 0x1000;

	/* memsz < filesz */
	((elf_phdr *)(img + eh->e_phoff))->p_memsz = 0x10;
	CHECK(LOAD() == UML_NT_ELF_SEG);
	((elf_phdr *)(img + eh->e_phoff))->p_memsz = 0x1000;

	/* VA outside the guest span (span = [RAM, RAM + SPAN)) */
	((elf_phdr *)(img + eh->e_phoff))->p_vaddr = RAM + SPAN;
	CHECK(LOAD() == UML_NT_ELF_VA);
	((elf_phdr *)(img + eh->e_phoff))->p_vaddr = 0x62000000ull;

	/* entry outside every region (fresh mm: the sanity load's VMA
	 * would collide first — overlap is checked before entry) */
	uml_nt_mm_init(&mm);
	eh->e_entry = 0x99900000ull;
	CHECK(LOAD() == UML_NT_ELF_VA);
	eh->e_entry = 0x62000010ull;

	/* collision with an existing VMA (ET_EXEC loads as linked —
	 * the VMA sits ON the image's first region) */
	CHECK(uml_nt_vma_add(&mm, 0x62000000ull, 0x62010000ull,
			     MOCK_BASE, UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(LOAD() == UML_NT_ELF_MM);
#undef LOAD
}

/* Failure paths roll back: spans freed, mm untouched. */
static void test_rollback(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	elf_ehdr *eh;
	unsigned long long va;
	int i, rc;

	/* fill the VMA table to 63 of 64 slots, out of the ELF's way */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);
	for (i = 0; i < 63; i++) {
		va = RAM + (unsigned long long)i * RUN;
		CHECK(uml_nt_vma_add(&mm, va, va + RUN,
				     MOCK_BASE + (long long)i * RUN,
				     UML_NT_PAGE_READWRITE, 0) == 0);
	}
	eh = mk_ehdr(2, 0x62000010ull);
	add_phdr(5, 0x400, 0x62000000ull, 0x1000, 0x1000);
	add_phdr(6, 0x1400, 0x62010000ull, 0x10, 0x100);
	eh->e_entry = 0x62000010ull;

	rc = uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec);
	CHECK(rc == UML_NT_ELF_MM); /* second add blows the table */
	CHECK(mm.nvma == 63);       /* the first add rolled back */
	/* spans freed: the mock pool is empty again */
	for (i = 0; i < MOCK_RUNS; i++)
		CHECK(!mock_taken[i]);
}

/* Stack placement: one run above the highest region, RW, top past
 * the run. */
static void test_stack(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	elf_ehdr *eh;
	unsigned long long top;
	int rc;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);
	eh = mk_ehdr(2, 0x62000010ull);
	add_phdr(5, 0x400, 0x62000000ull, 0x1000, 0x1000);
	eh->e_entry = 0x62000010ull;
	CHECK(uml_nt_elf_load(&out, &mm, &ph, img, 0x2000, sec) ==
	      UML_NT_ELF_OK);

	rc = uml_nt_elf_stack_place(&out, &mm, &ph, &top);
	CHECK(rc == UML_NT_ELF_OK);
	CHECK(top == 0x62020000ull);
	CHECK(out.stack_top == top);
	CHECK(mm.nvma == 2);
	CHECK(uml_nt_vma_find(&mm, 0x62010000ull) == &mm.vma[1]);
	CHECK(mm.vma[1].prot == 0x04u);
	CHECK(mm.vma[1].end == top);

	/* a second placement stacks above the first */
	rc = uml_nt_elf_stack_place(&out, &mm, &ph, &top);
	CHECK(rc == UML_NT_ELF_OK);
	CHECK(top == 0x62030000ull);
}

/* The REAL probe guest (built by test_elf.sh with clang+lld, same
 * recipe as the CI kernel job): layout as linked, bytes intact, and
 * the patch scan finds EVERY syscall site — a lost one is a guest
 * stuck on a real `syscall` instruction. */
static void test_real_guest(const char *path)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_elf_image out;
	FILE *f;
	unsigned long len, patched;
	int rc, i, text_seg = -1;

	f = fopen(path, "rb");
	if (f == NULL) {
		printf("SKIP real guest (%s)\n", path);
		return;
	}
	len = fread(img, 1, sizeof(img), f);
	fclose(f);
	if (len == 0 || len == sizeof(img)) {
		CHECK(!"real guest unreadable");
		return;
	}

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, SPAN) == 0);
	uml_nt_mm_init(&mm);
	rc = uml_nt_elf_load(&out, &mm, &ph, img, len, sec);
	if (rc != UML_NT_ELF_OK) {
		printf("FAIL real guest load rc=%d\n", rc);
		fails++;
		return;
	}
	CHECK(out.nseg == 3); /* lld separate-code: R, RX, RW */
	if (out.nseg != 3) {
		printf("FAIL real guest nseg=%d\n", out.nseg);
		fails++;
		return;
	}
	CHECK(mm.nvma == 3);
	/* inside the guest span, 64K regions */
	for (i = 0; i < out.nseg; i++) {
		CHECK(out.seg[i].start % RUN == 0);
		CHECK(out.seg[i].end % RUN == 0);
		CHECK(out.seg[i].start >= RAM);
		CHECK(out.seg[i].end <= RAM + ph.size);
	}
	/* prots: rodata R, text R|X, data RW */
	CHECK(out.seg[0].prot == 0x02u);
	CHECK(out.seg[1].prot == 0x20u);
	CHECK(out.seg[2].prot == 0x04u);
	/* entry in the text region */
	CHECK(out.entry >= out.seg[1].start &&
	      out.entry < out.seg[1].end);
	text_seg = 1;

	/* the loaded text is byte-exact with the file's segment bytes */
	{
		const elf_ehdr *eh = (const elf_ehdr *)img;
		const elf_phdr *p = (const elf_phdr *)
			(img + eh->e_phoff);
		unsigned long long off = out.seg[text_seg].run_off +
			(p[text_seg].p_vaddr - out.seg[text_seg].start);

		CHECK(memcmp(sec + off, img + p[text_seg].p_offset,
			     p[text_seg].p_filesz) == 0);
	}

	/* the patch sweep eats every syscall site — init.S has 31
	 * (M3.4 ten: hi, fault1, fault2, guard0, fork, child write,
	 * child exit, parent write, parent exit, fail; M3.7 adds 21:
	 * wait4, getpid, getppid, set_tid, sigprocmask, 2 markers,
	 * brk x2, marker, mmap, marker, munmap, mmap-fixed, 2
	 * markers, exit + 5 fail paths) */
	patched = uml_nt_patch_syscalls(
		sec + out.seg[text_seg].run_off,
		out.seg[text_seg].end - out.seg[text_seg].start, 0);
	CHECK(patched == 31);
	printf("real guest: %d region(s), entry 0x%llx, %lu patched\n",
	       out.nseg, out.entry, patched);
}

int main(int argc, char **argv)
{
	test_exec_basic();
	test_merge();
	test_dyn();
	test_errors();
	test_rollback();
	test_stack();
	if (argc > 1)
		test_real_guest(argv[1]);

	if (fails) {
		printf("test_elf: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_elf: all ok\n");
	return 0;
}
