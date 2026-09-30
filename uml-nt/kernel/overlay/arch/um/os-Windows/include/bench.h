/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bench.h — M4.1 syscall RTT benchmark, clean path.
 *
 * M3.9 measured the observed syscall RTT (~60–100µs) WITH the per-
 * round trace on — an upper bound distorted by console logging. This
 * benchmark is the clean counterpart: the guest runs a tight getpid
 * loop (the cheapest dispatch round — pure bookkeeping, no VFS, no
 * stub ops) between two console markers the KERNEL side recognizes
 * in the write handler (UMLNT-BENCH-BEGIN / UMLNT-BENCH-END — no
 * protocol change); the serving userspace() loop timestamps every
 * round wake-to-wake (os_nsecs/QPC) and prints ONE summary line at
 * END. No per-round logging exists on the path, so the measurement
 * is clean by construction, not by log filtering.
 *
 * The guest additionally prints its own rdtsc total for the same
 * loop: cycles/syscall is frequency-independent, and cycles ÷ the
 * kernel's total_ns yields the effective TSC frequency as a
 * cross-check.
 *
 * Split for testability: bench_stats.c holds the pure math (sort +
 * percentiles + summary, no kernel includes — unit-tested on Linux
 * CI); bench.c holds the window state and the os_nsecs sampling.
 * Both the header and bench_stats.c compile freestanding anywhere.
 */
#ifndef __UM_OS_WINDOWS_BENCH_H
#define __UM_OS_WINDOWS_BENCH_H

/* Sample cap: the bench guest (guest/bench.c) runs fewer rounds than
 * this, so percentiles cover the whole window; a longer run keeps
 * its first cap samples and reports `dropped` honestly. */
#define UML_NT_BENCH_MAX_SAMPLES 8192u

struct uml_nt_bench_summary {
	unsigned long long rounds;   /* deltas recorded under the window */
	unsigned long long dropped;  /* rounds past the sample cap */
	unsigned long long total_ns; /* sum of all recorded deltas */
	unsigned long long eps;      /* rounds * 1e9 / total_ns */
	unsigned long long mean_ns;
	unsigned p50_ns, p99_ns;
	unsigned min_ns, max_ns;
};

/* ---- pure (skas/bench_stats.c, unit-tested: tests/test_bench.c) ----- */

/* In-place heapsort, ascending. Stable enough for percentiles (equal
 * keys are interchangeable in a latency distribution). */
void uml_nt_u32_sort(unsigned *a, unsigned long long n);

/* Full summary from samples + the window counters. Sorts `samples`
 * in place, computes p50/p99/min/max from it (nearest-below index:
 * p50 = samples[n/2], p99 = samples[n*99/100]) and mean/eps from
 * rounds/total_ns (eps 0 when total_ns is 0 — never divides by
 * zero). `dropped` = rounds - n_samples. */
void uml_nt_bench_summarize(unsigned *samples, unsigned long long n_samples,
			    unsigned long long rounds,
			    unsigned long long total_ns,
			    struct uml_nt_bench_summary *out);

/* ---- kernel side (skas/bench.c) ------------------------------------- */

/* Timestamp one userspace() loop round (call right after pump_conn,
 * every round, window on or off): one os_nsecs() call, the delta
 * from the previous round is recorded only while the window is open.
 * The delta spans serve + stub resume + guest code + VEH + publish +
 * kernel wake = the full syscall RTT as the guest experiences it. */
void uml_nt_bench_sample(void);

/* The write handler calls this on every console write (after the
 * guest buffer is translated): the exact marker lines open/close the
 * window. END prints the summary line "BENCH-KERNEL: ..." — the CI
 * gate's contract. */
void uml_nt_bench_write_marker(const char *kbuf, unsigned long len);

#endif /* __UM_OS_WINDOWS_BENCH_H */
