// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/bench_stats.c — pure benchmark math (M4.1).
 *
 * Deliberately include-free: the unit test (tests/test_bench.c) and
 * the kernel build compile this same file — the freestanding kernel
 * and the host test harness must agree on every formula (a drifting
 * percentile would silently move the M4 numbers). stddef.h is NOT
 * available here: the kernel build is -nostdinc without the compiler
 * include dir, so NULL is spelled locally (found on the first real
 * kernel build).
 */
#include <bench.h>

#define BENCH_NULL ((void *)0)

void uml_nt_u32_sort(unsigned *a, unsigned long long n)
{
	/* Heapsort — O(1) memory, no recursion, no library. n ≤ 8192
	 * and called once per benchmark run: performance is a
	 * non-issue, correctness and freestanding-ness are not. */
	unsigned long long start, i, child;
	unsigned tmp;

	if (n < 2)
		return;
	/* build max-heap */
	for (start = n / 2; start-- > 0;) {
		for (i = start; (child = 2 * i + 1) < n;) {
			if (child + 1 < n && a[child + 1] > a[child])
				child++;
			if (a[i] >= a[child])
				break;
			tmp = a[i];
			a[i] = a[child];
			a[child] = tmp;
			i = child;
		}
	}
	/* drain */
	for (start = n - 1; start > 0; start--) {
		tmp = a[0];
		a[0] = a[start];
		a[start] = tmp;
		for (i = 0; (child = 2 * i + 1) < start;) {
			if (child + 1 < start && a[child + 1] > a[child])
				child++;
			if (a[i] >= a[child])
				break;
			tmp = a[i];
			a[i] = a[child];
			a[child] = tmp;
			i = child;
		}
	}
}

void uml_nt_bench_summarize(unsigned *samples, unsigned long long n_samples,
			    unsigned long long rounds,
			    unsigned long long total_ns,
			    struct uml_nt_bench_summary *out)
{
	if (out == BENCH_NULL)
		return;
	out->rounds = rounds;
	out->dropped = rounds > n_samples ? rounds - n_samples : 0;
	out->total_ns = total_ns;
	out->mean_ns = rounds ? total_ns / rounds : 0;
	out->eps = total_ns ? rounds * 1000000000ULL / total_ns : 0;

	if (samples == BENCH_NULL || n_samples == 0) {
		out->p50_ns = 0;
		out->p99_ns = 0;
		out->min_ns = 0;
		out->max_ns = 0;
		return;
	}
	uml_nt_u32_sort(samples, n_samples);
	out->min_ns = samples[0];
	out->max_ns = samples[n_samples - 1];
	/* nearest-below rank: p50 = a[n/2], p99 = a[n*99/100] —
	 * deterministic and unit-asserted (tests/test_bench.c). */
	out->p50_ns = samples[n_samples / 2];
	out->p99_ns = samples[n_samples * 99u / 100u];
}
