/* test_uaccess.c — unit tests for the M3.7 uaccess walker (D15):
 * uml_nt_uacc_walk + strncpy/strnlen over the per-conn VMA tree.
 * Pure logic: compiles uaccess_walk.c + vma.c + physalloc.c as-is
 * on the host; the phys backend is mocked (same pattern as
 * test_mm.c — the walker never calls it, but vma.c links it).
 *
 * Model: guest VA [0x60000000, +len) with a "flat view" = the mock
 * base buffer; a byte at guest VA v lives at base + (v - RAM).
 */
#include <stdio.h>
#include <string.h>
#include <vma.h>
#include <fault.h>
#include <uaccess_walk.h>

static int fails;

#define CHECK(cond) do { if (!(cond)) { \
	fails++; \
	printf("FAIL %d: %s\n", __LINE__, #cond); \
} } while (0)

#define RAM  0x60000000ull
#define RUN  UML_NT_PHYS_RUN_SIZE
/* flat view buffer: 8 runs of guest RAM behind base 0 */
static unsigned char flat[8 * RUN];

/* Backend mock: block-granular buddy (test_elf pattern) — the COW
 * fixups ALLOCATE runs, so the mock must hand out real blocks. */
#define MOCK_RUNS 8
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
		return (long long)i * RUN;
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

static void fill_pattern(unsigned char *b, unsigned long n)
{
	unsigned long i;

	for (i = 0; i < n; i++)
		b[i] = (unsigned char)(i * 7 + 3);
}

static void test_cow_fixup(void);
static void test_stolen_run(void);
static void test_gen_stale(void);
static void test_uaw_helpers(void);
static void test_uaw_nr_context(void);
static void test_tce_helpers(void);

int main(void)
{
	struct uml_nt_mm mm;
	char buf[128];
	unsigned i;

	/* Two VMAs with a gap between them: A [RAM, +2 runs), B
	 * [RAM + 3 runs, +1 run). Both backed by identity offsets
	 * (never COW-copied — the walker is address arithmetic). */
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + 2 * RUN, 0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM + 3 * RUN, RAM + 4 * RUN, 3 * RUN,
			     UML_NT_PAGE_READWRITE, 0) == 0);

	/* from_guest: straight copy inside one VMA, page-crossing. */
	fill_pattern(flat, sizeof(flat));
	memset(buf, 0, sizeof(buf));
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM + 4090, 100, buf,
			       UML_NT_UACC_FROM_GUEST) == 0);
	CHECK(memcmp(buf, flat + 4090, 100) == 0);

	/* to_guest: writes land in the flat view (both pages). */
	memset(buf, 0x5a, sizeof(buf));
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM + 8180, 100, buf,
			       UML_NT_UACC_TO_GUEST) == 0);
	for (i = 0; i < 100; i++)
		CHECK(flat[8180 + i] == 0x5a);

	/* zero_guest: memset through the tree. */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM + 100, 4096, NULL,
			       UML_NT_UACC_ZERO_GUEST) == 0);
	for (i = 0; i < 4096; i++)
		CHECK(flat[100 + i] == 0);

	/* The gap between the VMAs is unmapped: -1. */
	memset(buf, 0, sizeof(buf));
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM + 2 * RUN, 16, buf,
			       UML_NT_UACC_FROM_GUEST) < 0);

	/* Crossing a VMA end = -1 (translate contract). */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat,
			       RAM + 2 * RUN - 8, 16, buf,
			       UML_NT_UACC_FROM_GUEST) < 0);

	/* Past the last VMA = -1. */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM + 4 * RUN, 1, buf,
			       UML_NT_UACC_FROM_GUEST) < 0);

	/* No mm installed (uacc_mm NULL upstream) — walker with an
	 * empty mm faults everything. */
	{
		struct uml_nt_mm empty;

		uml_nt_mm_init(&empty);
		CHECK(uml_nt_uacc_walk(&empty, (char *)flat, RAM, 4, buf,
				       UML_NT_UACC_FROM_GUEST) < 0);
	}

	/* M3.8 review regression: mm == NULL (outside a syscall
	 * handler) must fail SAFE — EFAULT class for copies, 0 for
	 * strnlen — never a translate() NULL deref. Zero length
	 * touches nothing (Linux: no-op). */
	CHECK(uml_nt_uacc_walk((const struct uml_nt_mm *)0, (char *)flat,
			       RAM, 4, buf, UML_NT_UACC_FROM_GUEST) < 0);
	CHECK(uml_nt_uacc_walk((const struct uml_nt_mm *)0, (char *)flat,
			       RAM, 0, buf, UML_NT_UACC_FROM_GUEST) == 0);
	CHECK(uml_nt_uacc_walk((const struct uml_nt_mm *)0, (char *)flat,
			       RAM, 4, buf, UML_NT_UACC_TO_GUEST) < 0);
	CHECK(uml_nt_uacc_walk((const struct uml_nt_mm *)0, (char *)flat,
			       RAM, 4, buf, UML_NT_UACC_ZERO_GUEST) < 0);
	CHECK(uml_nt_uacc_strnlen((const struct uml_nt_mm *)0,
				  (char *)flat, RAM, 64) == 0);
	CHECK(uml_nt_uacc_strncpy(buf, (const struct uml_nt_mm *)0,
				  (char *)flat, RAM, 64) < 0);

	/* strncpy_from_user: NUL terminated inside the VMA. */
	memcpy(flat + RUN, "hello", 6);
	CHECK(uml_nt_uacc_strncpy(buf, &mm, (char *)flat, RAM + RUN,
				  sizeof(buf)) == 5);
	CHECK(strcmp(buf, "hello") == 0);

	/* strnlen_user: length INCLUDING the NUL. */
	CHECK(uml_nt_uacc_strnlen(&mm, (char *)flat, RAM + RUN,
				  64) == 6);

	/* Unterminated within maxlen = -1 (strncpy) / 0 (strnlen). */
	memset(flat + RUN, 7, 128);
	CHECK(uml_nt_uacc_strncpy(buf, &mm, (char *)flat, RAM + RUN,
				  64) < 0);
	CHECK(uml_nt_uacc_strnlen(&mm, (char *)flat, RAM + RUN,
				  64) == 0);

	/* String crossing the page boundary mid-copy. */
	memset(flat + RUN + 4090, 'x', 10);
	flat[RUN + 4096] = 0; /* NUL on the next page */
	CHECK(uml_nt_uacc_strnlen(&mm, (char *)flat, RAM + RUN + 4090,
				  64) == 7);

	/* Unmapped string = -1 / 0. */
	CHECK(uml_nt_uacc_strncpy(buf, &mm, (char *)flat, RAM + 2 * RUN,
				  64) < 0);

	/* Hazard 3: the write fixups (COW surgery + remap ops + the
	 * audit's prot check). */
	test_cow_fixup();

	/* Map 049 item 2: the stolen-run ownership guard. */
	test_stolen_run();

	/* Map 121 (đáp 122): the per-run generation (stale claim)
	 * guard. */
	test_gen_stale();

	/* K6 (M5.6a): the [uawrite] full-buffer witness's pure
	 * helpers — FNV-1a 64 over the whole source buffer, the nr
	 * mix, and the [uawrite-dump] gate. */
	test_uaw_helpers();

	/* K6 scrutiny fix: the [uawrite] nr-context protocol — the
	 * resumed-parent attribution (a do_exit'd child never
	 * unwinds the dispatch; the switch boundary must re-arm the
	 * parent's own nr). */
	test_uaw_nr_context();

	/* K6 step 2: the [tcekey] syscall-park witness's pure tcache
	 * chain logic — reveal / chain walk / dup detect / counts. */
	test_tce_helpers();

	if (fails) {
		printf("test_uaccess: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_uaccess: OK\n");
	return 0;
}

/* Hazard 3 (review M3.8): WRITE paths must never touch a COW-shared
 * run directly, and never write a read-only VMA. The fixup copies
 * the run private INLINE (old content preserved for the sharer),
 * splits the writer's VMA and queues the stub remap ops. */
static void test_cow_fixup(void)
{
	struct uml_nt_mm parent, child;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	struct uml_nt_uacc_sink sink;
	char buf[64];
	unsigned i, pattern_at;
	long long parent_off, new_off;

	/* Parent: one writable run, populated through the phys API so
	 * the mock's bookkeeping stays consistent. */
	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 4 * RUN) == 0);
	uml_nt_mm_init(&parent);
	parent_off = uml_nt_phys_alloc(&ph);
	CHECK(parent_off == 0); /* mock hands run 0 first */
	CHECK(uml_nt_vma_add(&parent, RAM, RAM + RUN,
			     (unsigned long long)parent_off,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	pattern_at = (unsigned)parent_off;
	fill_pattern(flat + pattern_at, RUN);

	/* fork: child shares every run (COW, refs=2). rsp=0 is in no
	 * VMA — no eager stack copy. */
	uml_nt_mm_init(&child);
	CHECK(uml_nt_mm_clone(&child, &parent, &ph, 0) == 0);
	CHECK(uml_nt_phys_refs(&ph, parent_off) == 2);
	CHECK(child.vma[0].flags & UML_NT_VMA_COW);

	/* The dispatch installs the sink; the plan starts reset (the
	 * syscall handler contract). */
	memset(&plan, 0, sizeof(plan));
	sink.ph = &ph;
	sink.plan = &plan;
	uml_nt_uacc_set_sink(&sink);

	/* CHILD writes 64 bytes into the shared run: surgery, not a
	 * direct write. */
	memset(buf, 0x5a, sizeof(buf));
	CHECK(uml_nt_uacc_walk(&child, (char *)flat, RAM + 0x2000, 64,
			       buf, UML_NT_UACC_TO_GUEST) == 0);
	CHECK(uml_nt_uacc_fixups == 1); /* the fixup counter moved */

	/* the SHARER's copy is untouched (the whole point) */
	for (i = 0; i < 64; i++)
		CHECK(flat[pattern_at + 0x2000 + i] ==
		      (unsigned char)((0x2000 + i) * 7 + 3));
	/* the writer's piece: private run, COW gone, old content kept
	 * + new bytes on top */
	CHECK(plan.n_ops == 2); /* UNMAP span + MAP piece */
	CHECK(plan.ops[0].op == UML_NT_FOP_UNMAP);
	CHECK(plan.ops[0].va == RAM && plan.ops[0].len == RUN);
	CHECK(plan.ops[1].op == UML_NT_FOP_MAP);
	CHECK(plan.ops[1].prot == UML_NT_PAGE_READWRITE);
	CHECK(plan.ops[1].va == RAM && plan.ops[1].len == RUN);
	new_off = (long long)plan.ops[1].off;
	CHECK(new_off != parent_off);
	CHECK(uml_nt_phys_refs(&ph, (long long)new_off) == 1);
	CHECK(uml_nt_phys_refs(&ph, parent_off) == 1); /* child gave up
							* its claim */
	for (i = 0; i < 0x2000; i++)
		CHECK(flat[new_off + i] == flat[pattern_at + i]);
	for (i = 0; i < 64; i++)
		CHECK(flat[new_off + 0x2000 + i] == 0x5a);
	CHECK(!(child.vma[0].flags & UML_NT_VMA_COW));
	CHECK(child.vma[0].run_off == (unsigned long long)new_off);
	/* the parent's VMA still claims the old run, COW intact */
	CHECK(parent.vma[0].flags & UML_NT_VMA_COW);
	CHECK(parent.vma[0].run_off == (unsigned long long)parent_off);

	/* Second write, same (now private) run: direct, NO new ops, NO
	 * new fixup. */
	memset(buf, 0xa5, 8);
	CHECK(uml_nt_uacc_walk(&child, (char *)flat, RAM + 0x3000, 8,
			       buf, UML_NT_UACC_TO_GUEST) == 0);
	CHECK(plan.n_ops == 2);
	CHECK(uml_nt_uacc_fixups == 1);
	for (i = 0; i < 8; i++)
		CHECK(flat[new_off + 0x3000 + i] == 0xa5);

	/* clear_user on the child: private now, direct, no fixup. */
	CHECK(uml_nt_uacc_walk(&child, (char *)flat, RAM + 0x4000, 16,
			       NULL, UML_NT_UACC_ZERO_GUEST) == 0);
	CHECK(plan.n_ops == 2);
	CHECK(uml_nt_uacc_fixups == 1);
	for (i = 0; i < 16; i++)
		CHECK(flat[new_off + 0x4000 + i] == 0);

	/* PARENT writes its own (now last-ref) run: direct — refs==1
	 * means private-in-effect (upstream "private page" branch).
	 * No surgery: the run is not shared anymore. */
	memset(buf, 0x77, 8);
	CHECK(uml_nt_uacc_walk(&parent, (char *)flat, RAM + 0x100, 8,
			       buf, UML_NT_UACC_TO_GUEST) == 0);
	CHECK(plan.n_ops == 2);
	CHECK(uml_nt_uacc_fixups == 1);
	for (i = 0; i < 8; i++)
		CHECK(flat[pattern_at + 0x100 + i] == 0x77);

	/* Read-only VMA: -EFAULT class, nothing written (the audit's
	 * prot check — was a silent write before the fix). */
	{
		struct uml_nt_mm ro;
		struct uml_nt_phys ph2;

		mock_reset();
		CHECK(uml_nt_phys_init(&ph2, 4 * RUN) == 0);
		uml_nt_mm_init(&ro);
		CHECK(uml_nt_vma_add(&ro, RAM, RAM + RUN, 0,
				     UML_NT_PAGE_READONLY, 0) == 0);
		fill_pattern(flat, RUN);
		memset(buf, 0x5a, 8);
		CHECK(uml_nt_uacc_walk(&ro, (char *)flat, RAM + 16, 8,
				       buf, UML_NT_UACC_TO_GUEST) < 0);
		for (i = 0; i < 8; i++)
			CHECK(flat[16 + i] !=
			      0x5a); /* pattern byte intact */
	}

	/* No sink installed (outside a handler): COW-shared write
	 * faults fail-safe instead of corrupting the sharer. */
	{
		struct uml_nt_mm p2, c2;
		struct uml_nt_phys ph3;
		long long off3;

		mock_reset();
		CHECK(uml_nt_phys_init(&ph3, 4 * RUN) == 0);
		uml_nt_mm_init(&p2);
		off3 = uml_nt_phys_alloc(&ph3);
		CHECK(off3 == 0);
		CHECK(uml_nt_vma_add(&p2, RAM, RAM + RUN,
				     (unsigned long long)off3,
				     UML_NT_PAGE_READWRITE, 0) == 0);
		fill_pattern(flat + off3, RUN);
		uml_nt_mm_init(&c2);
		CHECK(uml_nt_mm_clone(&c2, &p2, &ph3, 0) == 0);
		uml_nt_uacc_set_sink(NULL); /* no channel */
		memset(buf, 0x5a, 8);
		CHECK(uml_nt_uacc_walk(&c2, (char *)flat, RAM + 16, 8,
				       buf, UML_NT_UACC_TO_GUEST) < 0);
		for (i = 0; i < 8; i++)
			CHECK(flat[off3 + 16 + i] != 0x5a); /* sharer
							     * intact */
	}
	/* The fail-safe paths (RO VMA, no sink) never surgery. */
	CHECK(uml_nt_uacc_fixups == 1);
	uml_nt_uacc_set_sink(NULL);
}

/* Map 049 item 2: a live VMA whose run the refcount table no longer
 * counts = a STOLEN run (an unbalanced drop freed the backing under
 * this mm — the run 0x28b0000 double-claim class). The walker must
 * refuse reads AND writes of it (kernel-side accesses would return/
 * plant foreign bytes) instead of translating into nobody's memory. */
static void test_stolen_run(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	struct uml_nt_uacc_sink sink;
	char buf[32];

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 4 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_vma_add(&mm, RAM, RAM + RUN, 0,
			     UML_NT_PAGE_READWRITE, 0) == 0);
	fill_pattern(flat, RUN);

	memset(&plan, 0, sizeof(plan));
	sink.ph = &ph;
	sink.plan = &plan;
	uml_nt_uacc_set_sink(&sink);

	/* healthy: the read + the str walk serve normally */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 16, buf,
			       UML_NT_UACC_FROM_GUEST) == 0);
	CHECK(uml_nt_uacc_strnlen(&mm, (char *)flat, RAM, 64) == 0);

	/* THEFT: drop the mm's own claim behind its back — the table
	 * says 0 while the VMA lives (the unref-refused [phys] event
	 * would fire for any FURTHER drop kernel-side). */
	CHECK(uml_nt_phys_unref(&ph, 0) == 0);
	CHECK(uml_nt_phys_refs(&ph, 0) == 0);

	/* reads refuse (-EFAULT / fault-class), the flat bytes stay */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 16, buf,
			       UML_NT_UACC_FROM_GUEST) < 0);
	CHECK(uml_nt_uacc_strnlen(&mm, (char *)flat, RAM, 64) == 0);
	CHECK(uml_nt_uacc_strncpy(buf, &mm, (char *)flat, RAM, 32) < 0);

	/* writes refuse, nothing lands */
	memset(buf, 0x5a, sizeof(buf));
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 16, buf,
			       UML_NT_UACC_TO_GUEST) < 0);
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 16, NULL,
			       UML_NT_UACC_ZERO_GUEST) < 0);
	CHECK(flat[0] == (unsigned char)3); /* pattern byte intact */

	uml_nt_uacc_set_sink(NULL);
}

/* Map 121 (đáp 122): a VMA claim recorded at its handout must stop
 * translating when the run is freed + re-handed — the stale-
 * translation class: the kernel read-fill (read() into a heap
 * buffer, TO_GUEST -> write_ptr direct) poured bytes into the NEW
 * owner's tcache entries through the OLD claim (referee
 * 37105483388). After the re-hand refs==1 (the new owner), so the
 * refs guard passes and ONLY the generation catches it: refuse
 * (EFAULT class), nothing lands. A re-added claim at the current
 * life serves again; gen==0 claims stay unchecked (the POC/bench
 * contract). */
static void test_gen_stale(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	struct uml_nt_uacc_sink sink;
	char buf[32];
	unsigned long long gen0;
	unsigned long long r0 = uml_nt_uacc_refuses;

	mock_reset();
	CHECK(uml_nt_phys_init(&ph, 4 * RUN) == 0);
	uml_nt_mm_init(&mm);
	CHECK(uml_nt_phys_alloc(&ph) == 0); /* run 0 — first life */
	gen0 = (unsigned long long)uml_nt_phys_gen(&ph, 0);
	CHECK(gen0 == 1);
	CHECK(uml_nt_vma_add_gen(&mm, RAM, RAM + RUN, 0,
				 UML_NT_PAGE_READWRITE, 0, gen0) == 0);
	fill_pattern(flat, RUN);

	memset(&plan, 0, sizeof(plan));
	sink.ph = &ph;
	sink.plan = &plan;
	uml_nt_uacc_set_sink(&sink);

	/* healthy at the recorded life: read + write serve */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 16, buf,
			       UML_NT_UACC_FROM_GUEST) == 0);
	memset(buf, 0x5a, 8);
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 8, buf,
			       UML_NT_UACC_TO_GUEST) == 0);
	CHECK(flat[0] == 0x5a);

	/* free + re-hand behind the claim's back: the mock hands the
	 * SAME run again (first-fit) — refs==1 (the new owner), so
	 * the refs guard passes; ONLY the generation refuses. The
	 * re-hand stamps a NEW epoch (2) on the run. */
	CHECK(uml_nt_phys_unref(&ph, 0) == 0);
	CHECK(uml_nt_phys_alloc(&ph) == 0);
	CHECK(uml_nt_phys_refs(&ph, 0) == 1);
	fill_pattern(flat, RUN); /* the new owner's live content */

	/* read-fill through the stale claim refuses — nothing lands
	 * in the new owner's memory (the tcache stays clean). */
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 16, buf,
			       UML_NT_UACC_FROM_GUEST) < 0);
	memset(buf, 0x5a, sizeof(buf));
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 8, buf,
			       UML_NT_UACC_TO_GUEST) < 0);
	CHECK(flat[0] == (unsigned char)3); /* owner byte intact */
	CHECK(uml_nt_uacc_strncpy(buf, &mm, (char *)flat, RAM,
				  32) < 0);

	/* the refusals named themselves (map 121 telemetry): 3 gen
	 * refusals — byte-read walk + write walk + str walk — at
	 * va=RAM, claim epoch 1 vs the run's current epoch 2. */
	CHECK(uml_nt_uacc_refuses - r0 == 3);
	CHECK(uml_nt_uacc_refuse_kind == 1);
	CHECK(uml_nt_uacc_refuse_va == RAM);
	CHECK(uml_nt_uacc_refuse_claim_gen == 1);
	CHECK(uml_nt_uacc_refuse_run_gen == 2);

	/* re-claim at the CURRENT life: serves again — the write
	 * lands at the right destination (the re-handed run). */
	CHECK(uml_nt_vma_del(&mm, RAM, RAM + RUN) == 0);
	CHECK(uml_nt_vma_add_gen(&mm, RAM, RAM + RUN, 0,
				 UML_NT_PAGE_READWRITE, 0,
				 (unsigned long long)uml_nt_phys_gen(&ph,
								     0)) == 0);
	memset(buf, 0x5a, 8);
	CHECK(uml_nt_uacc_walk(&mm, (char *)flat, RAM, 8, buf,
			       UML_NT_UACC_TO_GUEST) == 0);
	CHECK(flat[0] == 0x5a);

	/* gen == 0 claims stay unchecked (the POC/bench contract):
	 * a live run behind a gen-0 VMA serves as it always did. */
	{
		struct uml_nt_mm bench;

		uml_nt_mm_init(&bench);
		CHECK(uml_nt_vma_add(&bench, RAM, RAM + RUN, 0,
				     UML_NT_PAGE_READWRITE, 0) == 0);
		CHECK(uml_nt_uacc_walk(&bench, (char *)flat, RAM, 8,
				       buf,
				       UML_NT_UACC_FROM_GUEST) == 0);
	}

	uml_nt_uacc_set_sink(NULL);
}

/* K6 (M5.6a): the [uawrite] full-buffer witness (uaccess.c's
 * logging) leans on three pure helpers — fnv1a64 over the WHOLE
 * copy source, an 8-byte mix of the current syscall nr, and the
 * dump gate (needle SYSTEMD_ / LANG=en_US.UTF-8 anywhere in the
 * buffer, or a dest overlapping the tcache page). The baseline
 * ledger only printed q0/q1 (first 16B) and dl13 proved the
 * poison text can hide mid-buffer — these make the hash verifiable
 * offline and the gate exactly as narrow as designed. */
static void test_uaw_helpers(void)
{
	char buf[64];
	unsigned long long hs = 0x67d00000ull;
	unsigned long long h;

	/* FNV-1a 64 reference vectors (the canonical test set). */
	CHECK(uml_nt_uacc_fnv1a64("", 0) ==
	      0xcbf29ce484222325ull);
	CHECK(uml_nt_uacc_fnv1a64("a", 1) ==
	      0xaf63dc4c8601ec8cull);
	CHECK(uml_nt_uacc_fnv1a64("foobar", 6) ==
	      0x85944171f73967e8ull);

	/* the nr mix: deterministic, and a different nr on the same
	 * buffer yields a different final hash (the [uawrite] line's
	 * fnv= is buffer+nr — round attribution without cross-
	 * correlating c->last_nr). */
	h = uml_nt_uacc_fnv1a64("foobar", 6);
	CHECK(uml_nt_uacc_fnv_mix_nr(h, 0) ==
	      uml_nt_uacc_fnv_mix_nr(h, 0));
	CHECK(uml_nt_uacc_fnv_mix_nr(h, 1) !=
	      uml_nt_uacc_fnv_mix_nr(h, 0));

	/* needle gate fires mid-buffer, beyond q0/q1's 16B window */
	memset(buf, 'x', sizeof(buf));
	memcpy(buf + 31, "SYSTEMD_", 8);
	CHECK(uml_nt_uacc_dump_gate(buf, sizeof(buf), 0, hs) == 1);
	memset(buf, 'x', sizeof(buf));
	memcpy(buf + 20, "LANG=en_US.UTF-8", 16);
	CHECK(uml_nt_uacc_dump_gate(buf, sizeof(buf), 0, hs) == 1);

	/* unrelated text with a dest outside the tcache page: no */
	memset(buf, 'y', sizeof(buf));
	CHECK(uml_nt_uacc_dump_gate(buf, sizeof(buf),
				   hs + 0x2000, hs) == 0);

	/* buffer too short to hold the needle: no false hit */
	CHECK(uml_nt_uacc_dump_gate("SYSTE", 5, hs + 0x2000, hs) == 0);

	/* tcache-page dest (the gate's third arm) fires on plain
	 * bytes; a dest past the page does not. */
	memset(buf, 'z', 16);
	CHECK(uml_nt_uacc_dump_gate(buf, 16, hs + 0x40, hs) == 1);
	CHECK(uml_nt_uacc_dump_gate(buf, 16, hs + 0x1000, hs) == 0);

	/* dest straddling the tcache-page edge still counts (any
	 * overlap — the small bulk writes may start inside). */
	CHECK(uml_nt_uacc_dump_gate(buf, 16, hs + 0xff8, hs) == 1);
}

/* K6 scrutiny fix: the [uawrite] nr-context protocol — the
 * resumed-parent attribution bug. The global nr was installed/
 * restored ONLY at dispatch entry/exit, so a parent blocked in
 * wait4 (61) that resumed after the child's exit/exit_group went
 * through do_exit — which never unwinds the dispatch — hashed and
 * reported the child's 60/231 on its own rusage writeback. The
 * fix stamps the nr per conn at entry and re-arms it at the
 * stack-switch boundary (mm/sink's twin, stub_ctl.c). This drives
 * the REAL protocol: the exact functions syscall.c's dispatch,
 * stub_ctl.c's uml_nt_switch_trace and uaccess.c's logger call. */
static void test_uaw_nr_context(void)
{
	/* two conn slots (kzalloc-init 0, like c->active_nr) */
	unsigned long long parent_nr = 0, child_nr = 0;
	unsigned long long prev_parent, prev_child;

	/* boot: conn-less switch-in (kthread / stale-refused) re-arms
	 * 0 — the honest "no active handler" attribution. */
	CHECK(uml_nt_uacc_nr_current() == 0);
	CHECK(uml_nt_uacc_nr_switch(NULL) == 0);
	CHECK(uml_nt_uacc_nr_current() == 0);

	/* THE BUG TIMELINE. Parent's wait4 dispatch: entry stamps its
	 * conn slot AND installs the global (prev = boot state 0). */
	prev_parent = uml_nt_uacc_nr_enter(&parent_nr, 61);
	CHECK(prev_parent == 0);
	CHECK(parent_nr == 61);
	CHECK(uml_nt_uacc_nr_current() == 61);

	/* schedule() switches to the child BEFORE its dispatch: the
	 * boundary re-arm reads the child's still-zero slot, then the
	 * child's own exit_group dispatch entry installs 231. */
	CHECK(uml_nt_uacc_nr_switch(&child_nr) == 0);
	prev_child = uml_nt_uacc_nr_enter(&child_nr, 231);
	CHECK(prev_child == 0);
	CHECK(uml_nt_uacc_nr_current() == 231);

	/* the child exits through do_exit: NO exit restore runs (the
	 * dispatch never unwinds) — the global still names 231. */
	CHECK(uml_nt_uacc_nr_current() == 231);

	/* the stack switch back to the parent re-arms the parent's
	 * OWN nr: the resumed wait4 rusage writeback hashes/reports
	 * 61, not the dead child's 231. */
	CHECK(uml_nt_uacc_nr_switch(&parent_nr) == 61);
	CHECK(uml_nt_uacc_nr_current() == 61);

	/* the resumed parent's handler finally returns: its exit
	 * restore (out: in syscall.c) unwinds to the PRE-DISPATCH
	 * global it saved at entry — nesting stays intact. */
	CHECK(uml_nt_uacc_set_nr(prev_parent) == 61);
	CHECK(uml_nt_uacc_nr_current() == 0);

	/* ORDINARY NESTED RETURN (M4.2, no do_exit involved): the
	 * outer dispatch stamps 61, a nested dispatch on another conn
	 * stamps 231, and the nested exit's local prev + set_nr
	 * restores the OUTER's 61 — the slots stay per-conn. */
	prev_parent = uml_nt_uacc_nr_enter(&parent_nr, 61);
	CHECK(prev_parent == 0);
	prev_child = uml_nt_uacc_nr_enter(&child_nr, 231);
	CHECK(prev_child == 61);
	CHECK(uml_nt_uacc_nr_current() == 231);
	CHECK(uml_nt_uacc_set_nr(prev_child) == 231);
	CHECK(uml_nt_uacc_nr_current() == 61);
	CHECK(child_nr == 231);
	CHECK(parent_nr == 61);
	CHECK(uml_nt_uacc_set_nr(prev_parent) == 61);
	CHECK(uml_nt_uacc_nr_current() == 0);

	/* teardown: no state leaks into the other tests. */
	(void)uml_nt_uacc_set_nr(0);
}

/* K6 step 2 (M5.6a decision-tree step 2): the [tcekey] syscall-park
 * witness's PURE tcache-chain logic — the safe-linked reveal, the
 * per-bin walk (clean end / broken next / depth cap), the snapshot
 * record with dup detect, and the three fire predicates. Drives the
 * REAL functions stub_ctl.c's snapshotter calls (same pattern as
 * test_uaw_nr_context); the guest reads are mocked through the
 * per-qword reader callback (va -> qword/run, the kernel's one
 * translate per qword — a COW-piece boundary between the member's
 * size hdr and its data/key no longer rejects the member). */
#define TCE_HS 0x67d00000ull
#define TCE_HE 0x67d80000ull
#define TCE_TC (TCE_HS + 0x10ull) /* the tcache ptr glibc stores in e->key */
#define TCE_RUNX 0x3300000ull
#define TCE_RUNY 0x5600000ull

/* a COW-piece/VMA boundary INSIDE the heap: chunks below it are
 * backed by one piece (run RUNX), chunks at/above it by another
 * (RUNY). A member whose DATA va sits exactly at the boundary
 * has its size header in the piece BELOW — the scrutiny-blocker
 * shape (the reader's window [va-8, va+16) straddles pieces). */
#define TCE_PB 0x67d01000ull

static unsigned long long tce_piece_run(unsigned long long va)
{
	return va < TCE_PB ? TCE_RUNX : TCE_RUNY;
}

static struct {
	unsigned long long va, next_raw, key, size;
} tce_tab[512];
static int tce_ntab;

static void tce_reset(void)
{
	tce_ntab = 0;
}

/* add a chunk whose DECODED next is `next` (0 = chain end): the
 * stored raw = PROTECT_PTR(pos, ptr) = (va>>12) ^ ptr, which for
 * the end member (NULL ptr) is exactly va>>12 — glibc's shape. */
static void tce_put(unsigned long long va, unsigned long long next,
		    unsigned long long key, unsigned long long size)
{
	tce_tab[tce_ntab].va = va;
	tce_tab[tce_ntab].next_raw = (va >> 12) ^ next;
	tce_tab[tce_ntab].key = key;
	tce_tab[tce_ntab].size = size;
	tce_ntab++;
}

static int tce_rd(void *ctx, unsigned long long va,
		  unsigned long long *qword, unsigned long long *run)
{
	int i;

	(void)ctx;
	/* translate-granularity model, per qword: a read crossing a
	 * piece boundary is REFUSED (uml_nt_vma_translate rejects
	 * multi-VMA buffers) — but each member qword sits whole in
	 * one piece, so a member AT the boundary reads fine (the
	 * old single 24B window crossed and was refused). */
	if (va < TCE_PB && va + 8 > TCE_PB)
		return -1;
	for (i = 0; i < tce_ntab; i++) {
		if (tce_tab[i].va == va) { /* the DATA qword: e->next */
			*qword = tce_tab[i].next_raw;
			*run = tce_piece_run(va);
			return 0;
		}
		if (tce_tab[i].va - 8 == va) { /* the size hdr */
			*qword = tce_tab[i].size;
			*run = tce_piece_run(va);
			return 0;
		}
		if (tce_tab[i].va + 8 == va) { /* e->key */
			*qword = tce_tab[i].key;
			*run = tce_piece_run(va);
			return 0;
		}
	}
	return -1;
}

static void test_tce_helpers(void)
{
	struct uml_nt_tce_rd rd = { tce_rd, 0 };
	struct uml_nt_tce_bin wb;
	struct uml_nt_tce_snap snap;
	unsigned long long A = 0x67d005e0ull, B = 0x67d00a10ull;
	unsigned long long C = 0x67d02010ull, X = 0x67d02b90ull;
	struct uml_nt_tce_chunk c;
	int i;

	/* reveal = the PROTECT_PTR inverse, keyed by the member's OWN
	 * va (map-053); the dl13 poison qword decodes out-of-heap. */
	CHECK(uml_nt_tce_reveal(0x5f444d4554535953ull, A) ==
	      (0x5f444d4554535953ull ^ (A >> 12)));
	CHECK(uml_nt_tce_reveal((A >> 12) ^ B, A) == B);

	/* member gate: 16-aligned, top-16 clear, inside the heap. */
	CHECK(uml_nt_tce_member_ok(A, TCE_HS, TCE_HE) == 1);
	CHECK(uml_nt_tce_member_ok(A + 8, TCE_HS, TCE_HE) == 0);
	CHECK(uml_nt_tce_member_ok(TCE_HS - 0x10, TCE_HS, TCE_HE) == 0);
	CHECK(uml_nt_tce_member_ok(TCE_HE, TCE_HS, TCE_HE) == 0);
	CHECK(uml_nt_tce_member_ok(0x5f444d4554535953ull, TCE_HS,
				   TCE_HE) == 0);

	/* clean 3-chain A->B->C->end, counts==3: walked==3, no break,
	 * no cap; per-chunk key/size/run recorded from the reader. */
	tce_reset();
	tce_put(A, B, TCE_TC, 0x91);
	tce_put(B, C, TCE_TC, 0xa1);
	tce_put(C, 0, TCE_TC, 0xb1);
	CHECK(uml_nt_tce_walk_bin(&rd, A, TCE_HS, TCE_HE, 2, &wb) == 0);
	CHECK(wb.walked == 3);
	CHECK(wb.broke == 0);
	CHECK(wb.capped == 0);
	CHECK(wb.ch[0].va == A && wb.ch[1].va == B && wb.ch[2].va == C);
	CHECK(wb.ch[0].bin == 2 && wb.ch[2].depth == 2);
	CHECK(wb.ch[0].key == TCE_TC && wb.ch[2].key == TCE_TC);
	CHECK(wb.ch[1].size == 0xa1 && wb.ch[2].run == TCE_RUNY);
	CHECK(uml_nt_tce_counts_bad(3, wb.walked, wb.capped) == 0);

	/* BOUNDARY MEMBER (scrutiny blocker 1): a chunk whose DATA
	 * va sits exactly at the COW-piece/VMA boundary TCE_PB —
	 * its size header lives in the piece BELOW, its data/key
	 * in the piece ABOVE. The chain M1 -> M2 -> end must record
	 * BOTH members: a member at a piece boundary is ordinary
	 * memory, and rejecting it reads as a FALSE break at the
	 * head (FALSE COUNT-MISMATCH, no key/run row for it). */
	tce_reset();
	tce_put(0x67d00fe0ull, TCE_PB, TCE_TC, 0xb1); /* M1 below */
	tce_put(TCE_PB, 0, TCE_TC, 0xc1);              /* M2 AT it */
	CHECK(uml_nt_tce_walk_bin(&rd, 0x67d00fe0ull, TCE_HS, TCE_HE,
				 6, &wb) == 0);
	CHECK(wb.walked == 2);
	CHECK(wb.broke == 0);
	CHECK(wb.capped == 0);
	CHECK(wb.ch[1].va == TCE_PB);
	CHECK(wb.ch[1].size == 0xc1); /* the header, piece below */
	CHECK(wb.ch[1].key == TCE_TC);
	CHECK(wb.ch[1].run == TCE_RUNY); /* backing = the DATA qword */
	CHECK(wb.ch[0].run == TCE_RUNX);
	CHECK(uml_nt_tce_counts_bad(2, wb.walked, wb.capped) == 0);

	/* THE KNOWN TEAR (insert store #1 lost): the new head's next
	 * holds stale content (the dl13 poison text), the chain
	 * breaks at the head while counts sits above it. */
	tce_reset();
	tce_put(A, B, TCE_TC, 0x91); /* overwritten below */
	tce_tab[0].next_raw = 0x5f444d4554535953ull; /* stale "SYSTEMD_" */
	tce_put(B, 0, TCE_TC, 0xa1);
	CHECK(uml_nt_tce_walk_bin(&rd, A, TCE_HS, TCE_HE, 5, &wb) == 0);
	CHECK(wb.walked == 1);
	CHECK(wb.broke == 1);
	CHECK(wb.broke_va == A);
	CHECK(wb.broke_next ==
	      (0x5f444d4554535953ull ^ (A >> 12)));
	CHECK(uml_nt_tce_member_ok(wb.broke_next, TCE_HS, TCE_HE) == 0);
	CHECK(uml_nt_tce_counts_bad(3, wb.walked, wb.capped) == 1);

	/* cycle A->A: the walk caps at UML_NT_TCE_DEPTH and the
	 * snapshot record flags the second listing (dup = the
	 * double-free shape). */
	tce_reset();
	tce_put(A, A, TCE_TC, 0x91);
	CHECK(uml_nt_tce_walk_bin(&rd, A, TCE_HS, TCE_HE, 0, &wb) == 0);
	CHECK(wb.walked == UML_NT_TCE_DEPTH);
	CHECK(wb.capped == 1);
	memset(&snap, 0, sizeof(snap));
	c = wb.ch[0];
	CHECK(uml_nt_tce_record(&snap, &c) == -1); /* fresh */
	CHECK(snap.n == 1);
	for (i = 1; i < wb.walked; i++) {
		c = wb.ch[i];
		CHECK(uml_nt_tce_record(&snap, &c) == 0); /* dup at idx 0 */
	}

	/* cross-bin dup: a chunk may only be listed in ONE bin (its
	 * size class fixes the bin) — a second listing anywhere is
	 * the same dup shape. */
	memset(&snap, 0, sizeof(snap));
	c.va = A;
	c.key = TCE_TC;
	c.size = 0x91;
	c.run = TCE_RUNX;
	c.bin = 1;
	c.depth = 0;
	snap.ch[0] = c;
	snap.n = 1;
	c.bin = 3;
	c.depth = 0;
	CHECK(uml_nt_tce_record(&snap, &c) == 0);

	/* find: the prev-park diff base (run-change attribution). */
	CHECK(uml_nt_tce_find(&snap, A) == 0);
	CHECK(uml_nt_tce_find(&snap, X) == -1);

	/* the modal key = the learned tcache_key: glibc 2.34+ stores
	 * a RANDOM per-boot value in e->key (older stores the tcache
	 * ptr) — the majority vote names either; NULL keys never
	 * vote (the pop marker / the missing store). */
	memset(&snap, 0, sizeof(snap));
	for (i = 0; i < 4; i++) {
		snap.ch[i].va = A + (unsigned long long)i * 0x20;
		snap.ch[i].key = (i == 3) ? 0xdeadbeefull : 0x1234ull;
	}
	snap.n = 4;
	{
		int best = 0;

		CHECK(uml_nt_tce_modal_key(&snap, &best) == 0x1234ull);
		CHECK(best == 3); /* 3 agreeing, the 0xdeadbeef minority */
	}
	memset(&snap, 0, sizeof(snap));
	snap.ch[0].va = A;
	snap.ch[0].key = 0;
	snap.n = 1;
	{
		int best = 7;

		CHECK(uml_nt_tce_modal_key(&snap, &best) == 0);
		CHECK(best == 0); /* no non-NULL key carries a vote */
	}

	/* snapshot full: honest -2, no corruption of the record. */
	memset(&snap, 0, sizeof(snap));
	snap.n = UML_NT_TCE_MAX;
	CHECK(uml_nt_tce_record(&snap, &c) == -2);
	CHECK(snap.n == UML_NT_TCE_MAX);

	/* FULL-TCACHE CAPACITY (scrutiny blocker 2): 64 bins x 7
	 * members = 448 — every one must record. The old 128 cap
	 * silently dropped 320 of them and the later checks never
	 * saw them (walk summaries said walked=7 while the
	 * snapshot held less than half). Drives the real walk +
	 * record path, one chain per bin. */
	memset(&snap, 0, sizeof(snap));
	tce_reset();
	{
		int b2, m;
		unsigned long long base = 0x67d40000ull;

		for (b2 = 0; b2 < 64; b2++)
			for (m = 0; m < 7; m++) {
				unsigned long long va = base +
					((unsigned long long)(b2 * 7 + m))
					* 0x20ull;

				tce_put(va, m < 6 ? va + 0x20 : 0,
					TCE_TC, 0x90);
			}
		for (b2 = 0; b2 < 64; b2++) {
			CHECK(uml_nt_tce_walk_bin(&rd, base +
				  (unsigned long long)b2 * 7 * 0x20ull,
				  TCE_HS, TCE_HE, b2, &wb) == 0);
			CHECK(wb.walked == 7);
			CHECK(wb.broke == 0);
			CHECK(wb.capped == 0);
			for (m = 0; m < wb.walked; m++)
				CHECK(uml_nt_tce_record(&snap,
							&wb.ch[m]) == -1);
		}
		CHECK(snap.n == 448);
		/* the 449th: the honest -2 the census/flag trunc
		 * disclosure carries — never a silent drop. */
		c.va = base + 448ull * 0x20ull;
		c.key = TCE_TC;
		c.size = 0x90;
		c.run = TCE_RUNY;
		c.bin = 0;
		c.depth = 0;
		CHECK(uml_nt_tce_record(&snap, &c) == -2);
		CHECK(snap.n == 448);
	}

	/* the stale-key predicate: listed chunk with e->key != the
	 * tcache ptr = glibc's dup-check blinded. */
	CHECK(uml_nt_tce_key_stale(0, TCE_TC) == 1);
	CHECK(uml_nt_tce_key_stale(0x67d01111ull, TCE_TC) == 1);
	CHECK(uml_nt_tce_key_stale(TCE_TC, TCE_TC) == 0);

	/* the head-re-entry predicate: new head ALREADY listed at the
	 * previous park, and counts ROSE — a legit pop+re-push cycle
	 * can never raise the count (the dup insert can: nothing was
	 * popped). */
	CHECK(uml_nt_tce_reentry_bad(1, 1, 3, 2) == 1); /* dup insert */
	CHECK(uml_nt_tce_reentry_bad(1, 1, 2, 2) == 0); /* flat: legit */
	CHECK(uml_nt_tce_reentry_bad(1, 1, 2, 3) == 0); /* net pops */
	CHECK(uml_nt_tce_reentry_bad(1, 0, 3, 2) == 0); /* fresh head */
	CHECK(uml_nt_tce_reentry_bad(0, 1, 3, 2) == 0); /* same head */

	/* counts predicate: any walked/counts divergence at a quiescent
	 * park is the tear, including the cap (a healthy bin holds
	 * <= 7; the cap is 8). */
	CHECK(uml_nt_tce_counts_bad(2, 3, 0) == 1);
	CHECK(uml_nt_tce_counts_bad(4, 0, 0) == 1); /* NULL head */
	CHECK(uml_nt_tce_counts_bad(0, 1, 0) == 1); /* count 0, listed */
	CHECK(uml_nt_tce_counts_bad(8, 8, 1) == 1); /* cap always bad */
	CHECK(uml_nt_tce_counts_bad(7, 7, 0) == 0);
}
