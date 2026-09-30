/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_bench.c — unit test for skas/bench_stats.c (M4.1).
 *
 * The benchmark's numbers are only as trustworthy as the math that
 * summarizes them: sort, percentile ranks, mean/eps — asserted here
 * against hand-computed expectations and an insertion-sort oracle,
 * on the host (Linux CI), on the same source the freestanding
 * kernel ships.
 */
#include <stdio.h>
#include <string.h>
#include "bench.h"

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { \
		printf("FAIL- %d: %s\n", __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void test_sort(void)
{
	{
		unsigned a[] = { 3, 1, 2 };

		uml_nt_u32_sort(a, 3);
		CHECK(a[0] == 1 && a[1] == 2 && a[2] == 3);
	}
	{
		unsigned a[] = { 5, 4, 3, 2, 1 };

		uml_nt_u32_sort(a, 5);
		CHECK(a[0] == 1 && a[1] == 2 && a[2] == 3 && a[3] == 4 &&
		      a[4] == 5);
	}
	{
		unsigned a[] = { 7, 7, 7, 7 };

		uml_nt_u32_sort(a, 4);
		CHECK(a[0] == 7 && a[3] == 7);
	}
	{
		unsigned a[] = { 9 };

		uml_nt_u32_sort(a, 1);
		CHECK(a[0] == 9);
		uml_nt_u32_sort(a, 0); /* n == 0 and n == 1: no-op */
		uml_nt_u32_sort(NULL, 0);
	}
	{
		/* 257 pseudo-random values against an insertion-sort
		 * oracle (odd size on purpose — off-by-one in the
		 * heap drain shows at the tail). */
		unsigned a[257], b[257];
		unsigned long long i, j;
		unsigned x = 12345;

		for (i = 0; i < 257; i++) {
			x = x * 1103515245u + 12345u;
			a[i] = x >> 16;
			b[i] = a[i];
		}
		for (i = 1; i < 257; i++) {
			unsigned v = b[i];

			for (j = i; j > 0 && b[j - 1] > v; j--)
				b[j] = b[j - 1];
			b[j] = v;
		}
		uml_nt_u32_sort(a, 257);
		CHECK(memcmp(a, b, sizeof(a)) == 0);
	}
}

static void test_summarize(void)
{
	struct uml_nt_bench_summary out;
	unsigned s[] = { 40, 10, 30, 20 };

	/* sorted {10,20,30,40}: p50 = a[4/2] = 30, p99 = a[4*99/100]
	 * = a[3] = 40 (nearest-below rank, bench.h contract). */
	uml_nt_bench_summarize(s, 4, 4, 100, &out);
	CHECK(out.rounds == 4);
	CHECK(out.dropped == 0);
	CHECK(out.total_ns == 100);
	CHECK(out.mean_ns == 25);
	CHECK(out.eps == 4u * 1000000000ULL / 100);
	CHECK(out.min_ns == 10);
	CHECK(out.max_ns == 40);
	CHECK(out.p50_ns == 30);
	CHECK(out.p99_ns == 40);
	/* in-place sort happened (the caller may reuse the array) */
	CHECK(s[0] == 10 && s[3] == 40);

	/* dropped rounds: the window outlived the sample cap */
	{
		unsigned s3[] = { 1, 3 };

		uml_nt_bench_summarize(s3, 2, 5, 10, &out);
		CHECK(out.dropped == 3);
		CHECK(out.mean_ns == 2);
	}

	/* degenerate guards: no samples, zero total (never divide
	 * by zero), NULL out */
	{
		unsigned s2[] = { 5 };

		uml_nt_bench_summarize(s2, 0, 0, 0, &out);
		CHECK(out.mean_ns == 0 && out.eps == 0);
		CHECK(out.p50_ns == 0 && out.p99_ns == 0);
		uml_nt_bench_summarize(NULL, 0, 3, 30, &out);
		CHECK(out.rounds == 3 && out.mean_ns == 10);
		CHECK(out.eps == 3u * 1000000000ULL / 30);
		uml_nt_bench_summarize(s2, 1, 1, 0, &out);
		CHECK(out.eps == 0 && out.mean_ns == 0);
		uml_nt_bench_summarize(s2, 1, 1, 5, NULL); /* no crash */
	}
}

int main(void)
{
	test_sort();
	test_summarize();

	if (fails) {
		printf("FAIL- test_bench: %d check(s)\n", fails);
		return 1;
	}
	printf("ok  - test_bench: sort + percentile/mean/eps math\n");
	return 0;
}
