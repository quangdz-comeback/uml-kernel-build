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
#include <uaccess_walk.h>

static int fails;

#define CHECK(cond) do { if (!(cond)) { \
	fails++; \
	printf("FAIL %d: %s\n", __LINE__, #cond); \
} } while (0)

#define RAM  0x60000000ull
#define RUN  UML_NT_PHYS_RUN_SIZE
/* flat view buffer: 4 runs of guest RAM behind base 0 */
static unsigned char flat[4 * RUN];

/* Backend mock: the walker never allocates, but vma.c (linked for
 * uml_nt_vma_translate) references the phys backend symbols. */
long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	(void)page_out;
	(void)nruns;
	return -1;
}

void uml_nt_phys_backend_free(void *page, int nruns)
{
	(void)page;
	(void)nruns;
}

static void fill_pattern(unsigned char *b, unsigned long n)
{
	unsigned long i;

	for (i = 0; i < n; i++)
		b[i] = (unsigned char)(i * 7 + 3);
}

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

	if (fails) {
		printf("test_uaccess: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_uaccess: OK\n");
	return 0;
}
