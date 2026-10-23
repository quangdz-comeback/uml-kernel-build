/* The backend run pool (M5.6a K8 slice): the pure half.
 *
 * Root-cause target (referees 39986204407 / 39986213745, why='a'):
 * the phys backend allocates every run span straight from the shared
 * buddy. Since 5c96823's exact span trim the tails return to the
 * buddy as order-0 pages (003dbb8 lifted them to order 4), and the
 * kernel's own page cache/slab then scatter the orders — the 13 MiB
 * hwdb.bin mapping already failed order-4 handouts with 20 MiB free
 * and the login COW killed the stub at ~5 MiB free. The pool keeps
 * recently released run spans OUT of the buddy until a bounded cap and
 * hands them straight back, so the fault-path COW never depends on a
 * fragmented free list; under real pressure the pool drains back to
 * the buddy and the normal allocator retries.
 *
 * This model is the bookkeeping the kernel side (physbackend.c) wraps
 * with pages: put/get/pop over run-aligned section offsets. Compiled
 * on the host with no kernel types.
 */
#include <stdio.h>
#include <string.h>
#include "runpool_model.h"

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
	} } while (0)

#define R UML_NT_RUNPOOL_RUN
#define O(i) ((unsigned long long)(i) * R)

int main(void)
{
	struct uml_nt_runpool p;
	struct uml_nt_runpool_ent e;
	unsigned long long off;
	unsigned int nruns;
	int k;

	/* geometry: the model's run must be the phys layer's 64 KiB */
	CHECK(R == 0x10000ull);

	/* 1. exact round trip */
	uml_nt_runpool_init(&p, 64, 8);
	CHECK(uml_nt_runpool_put(&p, O(3), 2) == 0);
	CHECK(uml_nt_runpool_runs(&p) == 2);
	CHECK(uml_nt_runpool_entries(&p) == 1);
	CHECK(uml_nt_runpool_get(&p, 2) == (long long)O(3));
	CHECK(uml_nt_runpool_runs(&p) == 0);
	CHECK(uml_nt_runpool_entries(&p) == 0);
	CHECK(uml_nt_runpool_get(&p, 1) == -1);

	/* 2. best fit: the smallest entry that fits wins, so a 1-run COW
	 *    does not eat the only 4-run block */
	uml_nt_runpool_init(&p, 64, 8);
	CHECK(uml_nt_runpool_put(&p, O(0), 4) == 0);
	CHECK(uml_nt_runpool_put(&p, O(8), 1) == 0);
	CHECK(uml_nt_runpool_get(&p, 1) == (long long)O(8));
	CHECK(uml_nt_runpool_runs(&p) == 4);
	/* a 2-run ask still fits the 4-run entry and SPLITS it */
	CHECK(uml_nt_runpool_get(&p, 2) == (long long)O(0));
	CHECK(uml_nt_runpool_runs(&p) == 2);
	CHECK(uml_nt_runpool_entries(&p) == 1);
	CHECK(uml_nt_runpool_get(&p, 2) == (long long)O(2));
	CHECK(uml_nt_runpool_runs(&p) == 0);
	/* an ask larger than every entry refuses (the caller drains) */
	uml_nt_runpool_init(&p, 64, 8);
	CHECK(uml_nt_runpool_put(&p, O(0), 3) == 0);
	CHECK(uml_nt_runpool_get(&p, 4) == -1);
	CHECK(uml_nt_runpool_runs(&p) == 3);

	/* 3. caps: both the run budget and the entry table bound it;
	 *    a refused put must leave the pool unchanged (the caller
	 *    falls back to the buddy) */
	uml_nt_runpool_init(&p, 4, 2);
	CHECK(uml_nt_runpool_put(&p, O(0), 2) == 0);
	CHECK(uml_nt_runpool_put(&p, O(2), 2) == 0);
	CHECK(uml_nt_runpool_put(&p, O(4), 1) == -1); /* run cap */
	CHECK(uml_nt_runpool_runs(&p) == 4);
	CHECK(uml_nt_runpool_entries(&p) == 2);
	CHECK(uml_nt_runpool_put(&p, O(5), 1) == -1); /* entry cap */
	CHECK(uml_nt_runpool_runs(&p) == 4);
	uml_nt_runpool_init(&p, 64, 2);
	CHECK(uml_nt_runpool_put(&p, O(0), 1) == 0);
	CHECK(uml_nt_runpool_put(&p, O(1), 1) == 0);
	CHECK(uml_nt_runpool_put(&p, O(2), 1) == -1); /* entries full */

	/* 4. pop empties the pool entry by entry for the drain path */
	uml_nt_runpool_init(&p, 64, 8);
	CHECK(uml_nt_runpool_put(&p, O(0), 1) == 0);
	CHECK(uml_nt_runpool_put(&p, O(2), 3) == 0);
	k = 0;
	while (uml_nt_runpool_pop(&p, &off, &nruns)) {
		CHECK(off == (k ? O(2) : O(0)));
		CHECK(nruns == (k ? 3u : 1u));
		k++;
	}
	CHECK(k == 2);
	CHECK(uml_nt_runpool_pop(&p, &off, &nruns) == 0);
	CHECK(uml_nt_runpool_runs(&p) == 0);
	CHECK(uml_nt_runpool_entries(&p) == 0);

	/* 5. split remainder stays run-aligned and ordered (defensive
	 *    against an off-by-one handing out a misaligned COW dst) */
	uml_nt_runpool_init(&p, 64, 8);
	CHECK(uml_nt_runpool_put(&p, O(7), 5) == 0);
	CHECK(uml_nt_runpool_get(&p, 3) == (long long)O(7));
	CHECK(uml_nt_runpool_entries(&p) == 1);
	CHECK(uml_nt_runpool_peek(&p, 0, &e) == 0);
	CHECK(e.off == O(10));
	CHECK(e.nruns == 2);

	/* 6. counters: puts/gets are diagnostic (the census prints them) */
	uml_nt_runpool_init(&p, 64, 8);
	CHECK(uml_nt_runpool_put(&p, O(0), 1) == 0);
	(void)uml_nt_runpool_get(&p, 1);
	CHECK(p.puts == 1);
	CHECK(p.gets == 1);

	if (fails) {
		fprintf(stderr, "test_runpool: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_runpool: all ok\n");
	return 0;
}
