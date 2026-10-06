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
