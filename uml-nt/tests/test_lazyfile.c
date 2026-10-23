/* The lazy file-backed VMA model (M5.6a D27): the run materialization
 * window + the file read clamp. Compiled on the host from the shared
 * header as-is.
 *
 * D27 (Shelley): file-backed RO/EXEC VMAs must demand-page like
 * upstream — the run is allocated and the file bytes read at the
 * first fault, not eager-filled at mmap. The 13 MiB hwdb.bin map
 * (udevd, PROT_READ) is the referee case: it is read sparsely through
 * a binary-search trie and must not cost 11% of a 120 MiB budget.
 */
#include <stdio.h>
#include "lazyfile_model.h"

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
	} } while (0)

#define RUN UML_NT_LAZYFILE_RUN
#define R0 0x60ad0000ull			/* run-aligned mapping base */
#define REND (R0 + 4 * RUN)			/* 4 runs */

int main(void)
{
	unsigned long long va, end;

	CHECK(RUN == 0x10000ull);

	/* 1. a fault at the mapping base materializes its run */
	CHECK(uml_nt_lazy_run_window(R0, REND, R0, &va, &end) == 0);
	CHECK(va == R0 && end == R0 + RUN);
	/* 2. a page inside the run: same window (page granularity
	 *    collapses to the 64K run) */
	CHECK(uml_nt_lazy_run_window(R0, REND, R0 + 0x2345, &va, &end) == 0);
	CHECK(va == R0 && end == R0 + RUN);
	/* 3. the last run: a fault near its end clamps to the region
	 *    end, never past it (the MAP op length is the view) */
	CHECK(uml_nt_lazy_run_window(R0, REND, REND - 1, &va, &end) == 0);
	CHECK(va == REND - RUN && end == REND);
	/* 4. outside the region is not ours (mm_fault keeps the kill) */
	CHECK(uml_nt_lazy_run_window(R0, REND, R0 - 1, &va, &end) == -1);
	CHECK(uml_nt_lazy_run_window(R0, REND, REND, &va, &end) == -1);
	/* 5. a region whose base is NOT run-aligned is refused: the
	 *    section view needs a 64K-aligned window and the head hole
	 *    would need a negative file offset — such mappings stay
	 *    eager (the registration only takes run-aligned bases) */
	CHECK(uml_nt_lazy_run_window(R0 + 0x1000, REND, R0 + 0x2000,
				     &va, &end) == -1);
	/* 6. a region ending mid-run (file size not run-rounded)
	 *    clamps the last window */
	CHECK(uml_nt_lazy_run_window(R0, R0 + RUN + 0x8000,
				     R0 + RUN + 0x7000, &va, &end) == 0);
	CHECK(va == R0 + RUN && end == R0 + RUN + 0x8000);

	/* 7. the file read: offset maps VA->file, EOF clamps, holes
	 *    read zero (len 0) */
	CHECK(uml_nt_lazy_read_len(R0, 0, 4 * RUN, R0, RUN) == RUN);
	CHECK(uml_nt_lazy_read_len(R0, 0, 100, R0, RUN) == 100);
	CHECK(uml_nt_lazy_read_len(R0, 0, RUN + 10, R0 + RUN, RUN) == 10);
	CHECK(uml_nt_lazy_read_len(R0, 0, RUN, R0 + RUN, RUN) == 0);
	/* 8. a region mapped at a file offset (off != 0 shapes):
	 *    the read starts at foff_base */
	CHECK(uml_nt_lazy_read_len(R0, 0x2000, 0x10000, R0, RUN) ==
	      0x10000 - 0x2000);
	CHECK(uml_nt_lazy_read_len(R0, 0x2000, 0x10000, R0 + RUN, RUN) == 0);

	if (fails) {
		fprintf(stderr, "test_lazyfile: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_lazyfile: all ok\n");
	return 0;
}
