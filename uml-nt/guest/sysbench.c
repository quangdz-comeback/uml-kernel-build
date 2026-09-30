/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/sysbench.c — the REAL sysbench cpu workload (runs as PID 1
 * via init=/bin/sysbench).
 *
 * This is akopytov/sysbench src/tests/cpu/sb_cpu.c cpu_execute_event()
 * 1:1 — the double-sqrt trial-division sweep to cpu-max-prime (the
 * sysbench default 10000), one event per full sweep — driven by the
 * same window math sysbench's timer uses: events until the 10 s
 * monotonic window closes, then "events per second" (the M4-done
 * metric; the getpid RTT microbench says nothing about compute
 * throughput). No threads: --threads=1 is the contract.
 *
 * Freestanding: no libm — sqrtsd inline (identical double semantics
 * to sqrt()); time = clock_gettime(CLOCK_MONOTONIC) (kernel: QPC).
 * The sweep's prime count is DETERMINISTIC (1228 for 10000) — the
 * guest prints it so the gate can prove the compute was real and
 * not optimized away. Same ABI trap as every guest: clang compiles
 * _start as a normal callee — naked entry realigns rsp (sigtest.c
 * lesson).
 *
 * Freestanding static, linked INSIDE the guest window (Makefile).
 */
#include <stdint.h>

#define CPU_MAX_PRIME 10000ull /* sysbench's cpu-max-prime default */
#define WINDOW_SECS   10.0     /* sysbench's --time default */

static long sys_write(int fd, const void *buf, unsigned long len)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (1L), "D" ((long)fd), "S" (buf),
			    "d" (len)
			  : "rcx", "r11", "memory");
	return ret;
}

static void __attribute__((noreturn)) sys_exit(int code)
{
	__asm__ volatile ("syscall"
			  :
			  : "a" (60L), "D" ((long)code)
			  : "rcx", "r11");
	__builtin_unreachable();
}

struct timespec64 {
	long long tv_sec;
	long long tv_nsec;
};

static long sys_clock_gettime(int clk, struct timespec64 *ts)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (228L), "D" ((long)clk), "S" (ts)
			  : "rcx", "r11", "memory");
	return ret;
}

static double now_secs(void)
{
	struct timespec64 ts;

	if (sys_clock_gettime(1 /* CLOCK_MONOTONIC */, &ts) != 0)
		return -1.0;
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* sqrt() with no libm: the same instruction glibc/musl end up on for
 * a single sqrt (sqrtsd); errno semantics unused here. */
static double sqrt_f64(double x)
{
	double r;

	__asm__ ("sqrtsd %1, %0" : "=x" (r) : "x" (x));
	return r;
}

/* ---- sb_cpu.c cpu_execute_event, 1:1 ------------------------------- */

static unsigned long long prime_sweep(void)
{
	unsigned long long c, l, n = 0;
	double t;

	for (c = 3; c < CPU_MAX_PRIME; c++) {
		t = sqrt_f64((double)c);
		for (l = 2; l <= t; l++)
			if (c % l == 0)
				break;
		if (l > t)
			n++;
	}
	return n;
}

/* ---- output helpers ------------------------------------------------- */

static void put(const char *s)
{
	unsigned n = 0;

	while (s[n])
		n++;
	sys_write(1, s, n);
}

static void put_u64(unsigned long long v)
{
	char tmp[24];
	unsigned i = 0, j = 0;
	char buf[26];

	do {
		tmp[i++] = (char)('0' + (v % 10));
		v /= 10;
	} while (v);
	while (i)
		buf[j++] = tmp[--i];
	sys_write(1, buf, j);
}

static void put_f64_frac(unsigned long long whole, unsigned frac,
			 unsigned long long frac_val)
{
	put_u64(whole);
	if (frac) {
		char d[8];
		unsigned i, j;
		unsigned long long v = frac_val;

		put(".");
		for (i = 0; i < frac; i++) {
			d[i] = (char)('0' + (v % 10));
			v /= 10;
		}
		for (j = frac; j > 0; j--)
			sys_write(1, &d[j - 1], 1);
	}
}

/* ---- main (post-realign) ------------------------------------------- */

void sysbench_main(void);
void _start(void) __attribute__((naked, noreturn));
void _start(void)
{
	__asm__ volatile (
		"andq	$-16, %rsp\n\t"
		"subq	$8, %rsp\n\t"
		"xorl	%ebp, %ebp\n\t"
		"jmp	sysbench_main\n\t"
	);
}

void sysbench_main(void)
{
	double t0, t1, elapsed, eps;
	unsigned long long events = 0, primes = 0;
	unsigned long long whole, frac_val;

	put("sysbench (uml-nt) cpu benchmark\n");
	put("Prime numbers limit: ");
	put_u64(CPU_MAX_PRIME);
	put("\n");

	t0 = now_secs();
	if (t0 < 0.0)
		goto fail;
	for (;;) {
		primes = prime_sweep();
		events++;
		t1 = now_secs();
		if (t1 < 0.0)
			goto fail;
		if (t1 - t0 >= WINDOW_SECS)
			break;
	}
	elapsed = t1 - t0;
	eps = (double)events / elapsed;

	put("total number of events: ");
	put_u64(events);
	put("\nPRIMES=");
	put_u64(primes);
	put("\n");

	/* The sweep is deterministic: primes in [3, 10000) = 1228
	 * (pi(10000) = 1229 minus the skipped 2). Anything else means
	 * the compute was not what it claims. */
	if (primes != 1228ull)
		goto fail;

	whole = (unsigned long long)eps;
	frac_val = (unsigned long long)((eps - (double)whole) * 100.0);
	put("events per second: ");
	put_f64_frac(whole, 2, frac_val);
	put("\n");

	whole = (unsigned long long)elapsed;
	frac_val = (unsigned long long)((elapsed - (double)whole) * 100.0);
	put("total time: ");
	put_f64_frac(whole, 2, frac_val);
	put("s\n");

	put("SYSBENCH-OK\n");
	sys_exit(0);

fail:
	put("SYSBENCH-FAIL\n");
	sys_exit(9);
}
