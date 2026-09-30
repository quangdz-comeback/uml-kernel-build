/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/heaptest.c — M4 slice 4 proof: multi-run heap growth.
 *
 * Runs as PID 1 via init=/bin/heaptest (its own launcher run). The
 * exec path reserves ONE 64 KiB heap run; this binary walks brk(2)
 * past that reservation run by run. Every growth re-homes the heap
 * in a fresh contiguous span (contents memcpy'd kernel-side, stub
 * view swapped via UNMAP old / MAP new ops) — so the proof is
 * CONTENT SURVIVAL across growths, not just brk returning the new
 * value:
 *
 *   A. grow 0→HEAP_STEPS runs; each step writes a step magic at the
 *      last qword of the step's area; after all steps re-verify
 *      EVERY step's magic (the realloc-copy kept them all);
 *   B. grow one more run: the never-touched growth area must read
 *      ZERO (fresh __GFP_ZERO span), then write its magic;
 *   C. shrink to base+2 runs (brk returns the new value);
 *   D. regrow past the original reservation: ALL magics (A, B and
 *      the D regrow area's) must still be there.
 *
 * HEAPTEST-OK + exit(0) only when every check passed. Freestanding
 * static, linked INSIDE the guest window (--image-base, Makefile).
 */
#include <stdint.h>

#define NR_brk 12

#define HEAP_STEPS 24 /* 24 runs = 1.5 MiB, 24x the exec reservation */
#define RUN_SIZE   0x10000ull

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

static long sys_brk(long addr)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (12L), "D" (addr)
			  : "rcx", "r11", "memory");
	return ret;
}

static void put(const char *s)
{
	unsigned n = 0;

	while (s[n])
		n++;
	sys_write(1, s, n);
}

/* Magic for step i: address-derived, distinct per qword. */
static unsigned long long magic(unsigned long long slot)
{
	return 0x0DEAD0000000000ull + slot * 0x0101ull + slot;
}

static int check(unsigned long long *p, unsigned long long slot)
{
	return *p == magic(slot);
}

static void write_magic(unsigned long long *p, unsigned long long slot)
{
	*p = magic(slot);
	__asm__ volatile ("" : : "r" (*p) : "memory"); /* keep the store */
}

void _start(void)
{
	unsigned long long base, brk0, i, slot;
	unsigned long long *q;

	/* brk(0) = current brk = the exec reservation's start. */
	brk0 = (unsigned long long)sys_brk(0);
	if (brk0 == 0 || (brk0 & 0xfffull))
		goto fail;
	base = brk0;

	/* A: grow run by run, write a magic at each step's last qword. */
	for (i = 1; i <= HEAP_STEPS; i++) {
		unsigned long long want = base + i * RUN_SIZE;

		if ((unsigned long long)sys_brk((long)want) != want)
			goto fail;
		q = (unsigned long long *)(want - 8);
		write_magic(q, i);
	}
	/* Every step's magic survived the copy chain. */
	for (i = 1; i <= HEAP_STEPS; i++) {
		q = (unsigned long long *)(base + i * RUN_SIZE - 8);
		if (!check(q, i))
			goto fail;
	}
	put("HEAP-GROW-OK\n");

	/* B: one more run — untouched area must read ZERO. */
	{
		unsigned long long want = base + (HEAP_STEPS + 1) *
					  RUN_SIZE;

		if ((unsigned long long)sys_brk((long)want) != want)
			goto fail;
		q = (unsigned long long *)(want - 8);
		if (*q != 0)
			goto fail;
		write_magic(q, HEAP_STEPS + 1);
	}
	put("HEAP-FRESH-ZERO-OK\n");

	/* C: shrink to base + 2 runs. */
	if ((unsigned long long)sys_brk((long)(base + 2 * RUN_SIZE)) !=
	    base + 2 * RUN_SIZE)
		goto fail;
	if (!check((unsigned long long *)(base + RUN_SIZE - 8), 1))
		goto fail;
	put("HEAP-SHRINK-OK\n");

	/* D: regrow past the original reservation — everything still
	 * there. */
	{
		unsigned long long want = base + (HEAP_STEPS + 1) *
					  RUN_SIZE;

		if ((unsigned long long)sys_brk((long)want) != want)
			goto fail;
		for (i = 1; i <= HEAP_STEPS + 1; i++) {
			q = (unsigned long long *)(base + i * RUN_SIZE - 8);
			if (!check(q, i))
				goto fail;
		}
	}
	put("HEAP-REGROW-OK\n");

	/* E: one more full re-home (the regrow in D stayed inside the
	 * grown reservation — force a fresh span realloc and re-verify
	 * the content chain end to end). */
	{
		unsigned long long want = base + (HEAP_STEPS + 2) *
					  RUN_SIZE;

		if ((unsigned long long)sys_brk((long)want) != want)
			goto fail;
		for (i = 1; i <= HEAP_STEPS + 1; i++) {
			q = (unsigned long long *)(base + i * RUN_SIZE - 8);
			if (!check(q, i))
				goto fail;
		}
		q = (unsigned long long *)(want - 8);
		slot = HEAP_STEPS + 2;
		write_magic(q, slot);
		if (!check(q, slot))
			goto fail;
	}
	put("HEAPTEST-OK\n");
	sys_exit(0);

fail:
	put("HEAPTEST-FAIL\n");
	sys_exit(9);
}
