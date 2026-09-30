// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/bench.c — M4.1 syscall RTT benchmark, kernel side.
 *
 * The window: the guest bench (init=/bin/bench) brackets a tight
 * getpid loop with console writes of UMLNT-BENCH-BEGIN / END; the
 * write handler (skas/syscall.c sys_write) forwards every console
 * write here after translation, so the markers need no protocol
 * change and no new syscall. While the window is open, the serving
 * userspace() loop (skas/process.c) timestamps each round and the
 * delta from the previous round — serve + stub resume + guest code +
 * VEH + publish + kernel wake, i.e. the full RTT the guest sees —
 * is recorded. Nothing logs per round; END prints exactly one
 * summary line ("BENCH-KERNEL: ...", the CI gate contract).
 *
 * Not a D-decision: this is a measurement instrument (a cmdline-
 * free, marker-triggered window), not an architectural surface —
 * recorded in STATUS/RESULTS per loop protocol §5.
 */
#include <os.h>
#include <internal.h>
#include <bench.h>

static int bench_on;
/* Skip the delta of the round that OPENED the window (it covers the
 * marker write's own serve, not a getpid round) — see sample(). */
static int bench_skip;

static unsigned samples[UML_NT_BENCH_MAX_SAMPLES];
static unsigned long long n_samples;
static unsigned long long rounds, total_ns;
static unsigned long long t_prev;

void uml_nt_bench_sample(void)
{
	unsigned long long t = os_nsecs();

	if (bench_on && t_prev != 0) {
		unsigned long long d = t - t_prev;

		if (bench_skip) {
			bench_skip = 0;
		} else {
			total_ns += d;
			rounds++;
			if (n_samples < UML_NT_BENCH_MAX_SAMPLES)
				samples[n_samples++] =
					d > 0xffffffffULL ?
						0xffffffffU :
						(unsigned)d;
		}
	}
	t_prev = t;
}

static void bench_begin(void)
{
	bench_on = 1;
	bench_skip = 1;
	n_samples = 0;
	rounds = 0;
	total_ns = 0;
	/* No ack line: the marker itself is on the console, the
	 * window is silent until END (per-round noise is exactly
	 * what this benchmark exists to avoid). */
}

static void bench_end(void)
{
	struct uml_nt_bench_summary s;

	bench_on = 0;
	if (rounds == 0) {
		os_info("BENCH-KERNEL: no rounds recorded — window never "
			"sampled (userspace() loop not instrumented?)\n");
		return;
	}
	uml_nt_bench_summarize(samples, n_samples, rounds, total_ns, &s);
	os_info("BENCH-KERNEL: rounds=%llu dropped=%llu total_ns=%llu "
		"mean_ns=%llu eps=%llu p50_ns=%u p99_ns=%u min_ns=%u "
		"max_ns=%u samples=%llu\n",
		s.rounds, s.dropped, s.total_ns, s.mean_ns, s.eps,
		s.p50_ns, s.p99_ns, s.min_ns, s.max_ns, n_samples);
}

void uml_nt_bench_write_marker(const char *kbuf, unsigned long len)
{
	static const char begin[] = "UMLNT-BENCH-BEGIN\n";
	static const char end[] = "UMLNT-BENCH-END\n";

	/* Length check first: the common console writes (markers
	 * aside) never pay the memcmp. */
	if (len == sizeof(begin) - 1 &&
	    __builtin_memcmp(kbuf, begin, sizeof(begin) - 1) == 0)
		bench_begin();
	else if (len == sizeof(end) - 1 &&
		 __builtin_memcmp(kbuf, end, sizeof(end) - 1) == 0)
		bench_end();
}
