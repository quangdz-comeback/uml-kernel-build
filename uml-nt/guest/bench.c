/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/bench.c — M4.1 syscall RTT benchmark, guest side.
 *
 * Runs as PID 1 via init=/bin/bench (its own launcher invocation —
 * the POC exec chain stays untouched). The workload is the cheapest
 * dispatch round that exists on this kernel: getpid (pure
 * bookkeeping in the D16 handler — no VFS, no stub ops), BENCH_N
 * times in a tight loop, bracketed by two console markers the
 * KERNEL recognizes inside the write handler (UMLNT-BENCH-BEGIN /
 * UMLNT-BENCH-END — bench.c opens/closes the sampling window
 * there). The kernel prints the ns summary at END; this program
 * prints its own rdtsc total for the same loop — cycles/syscall is
 * frequency-independent, and cycles ÷ kernel-total_ns yields the
 * effective TSC frequency as a cross-check.
 *
 * rdtsc is safe to run in the stub: only `0F 05` (syscall) opcodes
 * are patched to ud2 — rdtsc (0F 31) executes natively.
 *
 * Freestanding static, linked INSIDE the guest window (--image-base,
 * see Makefile — baked absolute pointers here are real addresses).
 */
#include <stdint.h>

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

static long sys_getpid(void)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (39L)
			  : "rcx", "r11", "memory");
	return ret;
}

static unsigned long long rdtsc(void)
{
	unsigned int lo, hi;

	__asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
	return ((unsigned long long)hi << 32) | lo;
}

/* Caller supplies the buffer; returns one past the last digit. */
static char *utoa_dec(unsigned long long v, char *buf)
{
	char tmp[24];
	unsigned int i = 0, j = 0;

	do {
		tmp[i++] = (char)('0' + (v % 10));
		v /= 10;
	} while (v);
	while (i)
		buf[j++] = tmp[--i];
	buf[j] = 0;
	return buf + j;
}

static char *strcat_into(char *dst, const char *src)
{
	while (*src)
		*dst++ = *src++;
	return dst;
}

#define BENCH_N 8000u

void _start(void)
{
	static const char begin[] = "UMLNT-BENCH-BEGIN\n";
	static const char end[] = "UMLNT-BENCH-END\n";
	unsigned long long t0, t1, cyc;
	char line[128];
	char *p;

	sys_write(1, begin, sizeof(begin) - 1);
	t0 = rdtsc();
	for (unsigned int i = 0; i < BENCH_N; i++)
		(void)sys_getpid();
	t1 = rdtsc();
	sys_write(1, end, sizeof(end) - 1);

	cyc = t1 - t0;
	p = strcat_into(line, "BENCH-GUEST-CYCLES: total=");
	p = utoa_dec(cyc, p);
	p = strcat_into(p, " cyc (");
	p = utoa_dec(cyc / BENCH_N, p);
	p = strcat_into(p, " cyc/syscall, N=");
	p = utoa_dec(BENCH_N, p);
	*p++ = ')';
	*p++ = '\n';
	sys_write(1, line, (unsigned long)(p - line));

	sys_exit(0);
}
