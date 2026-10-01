/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/canary.c — M5.4 c3 fork/COW/recycled-run canary (048 map item 3).
 *
 * Reproduces the systemd corruption surfaces WITHOUT systemd: a
 * freestanding raw-syscall guest (dyntest/forkwait pattern) that
 * stresses exactly the two hypotheses the SIGSEGV autopsy left open
 * (report 047/048), so the next M5.5a run decides between them from a
 * marker line instead of a guess:
 *
 * - recycled-run (the 044 family): anon mmap MUST read back zero —
 *   the backend's __GFP_ZERO guarantee. A munmap/mmap cycle that
 *   hands back a run with old bytes in it is the recycle bug caught
 *   red-handed, no systemd involved.
 * - fork/COW surgery: parent and child write DISTINGUISHABLE node
 *   patterns into the same VAs (the corrupt shape: {pointer, magic,
 *   "STREAM=n" string, guard} — string bytes beside pointer slots).
 *   After every reap the parent re-verifies its whole arena: a torn
 *   fork-seed copy or a missed parent re-protect shows up as the
 *   child's bytes inside the parent (the class-2 signature).
 *
 * Markers: CANARY-INIT-OK / CANARY-RECYCLE-OK / CANARY-FORK-OK and
 * the final CANARY-OK. Any verification failure prints
 * CANARY-BAD stage=... with the node index and exits non-zero; a
 * crash dies through the real SIGSEGV path with the kernel's own
 * print. Freestanding static, linked INSIDE the guest window (see
 * the Makefile note).
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

static long sys_fork(void)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (57L)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_wait4(long pid, int *status, long options, void *rusage)
{
	long ret;
	register long r10 __asm__ ("r10") = (long)rusage;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (61L), "D" (pid), "S" (status),
			    "d" (options), "r" (r10)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_mmap(void *addr, unsigned long len, long prot, long flags,
		     long fd, long off)
{
	long ret;
	register long r10 __asm__ ("r10") = flags;
	register long r8 __asm__ ("r8") = fd;
	register long r9 __asm__ ("r9") = off;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (9L), "D" ((long)addr), "S" (len),
			    "d" (prot), "r" (r10), "r" (r8), "r" (r9)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_munmap(void *addr, unsigned long len)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (11L), "D" ((long)addr), "S" (len)
			  : "rcx", "r11", "memory");
	return ret;
}

/* ---- the corrupt shape: pointer slots with string bytes beside ---- */

struct node {
	struct node *next;      /* the class-2 victim slot */
	unsigned long long magic;
	char name[16];          /* "STREAM=%d" — the injected marker */
	unsigned long long guard; /* ~magic */
};

#define ARENA_LEN  (1024u * 1024u)
#define NODE_N     (ARENA_LEN / sizeof(struct node))
#define PARENT_MAGIC 0x1111111100000000ULL
#define CHILD_MAGIC  0x2222222200000000ULL

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

/* fill: build the linked list forward, magic/name/guard per node */
static void arena_fill(struct node *a, unsigned long long magicbase)
{
	unsigned int i;

	for (i = 0; i < NODE_N; i++) {
		char nm[24];
		char *p = strcat_into(nm, "STREAM=");
		struct node *n = &a[i];

		p = utoa_dec(i & 7, p);
		*p++ = '\0';
		n->next = (i + 1 < NODE_N) ? &a[i + 1] : (struct node *)0;
		n->magic = magicbase | (unsigned long long)i;
		n->guard = ~n->magic;
		{
			unsigned int j;

			for (j = 0; j < sizeof(n->name); j++)
				n->name[j] = nm[j] ? nm[j] : '\0';
		}
	}
}

/* verify EVERY byte of the pattern; returns the bad index or NODE_N */
static unsigned int arena_verify(const struct node *a,
				 unsigned long long magicbase)
{
	unsigned int i;

	for (i = 0; i < NODE_N; i++) {
		const struct node *n = &a[i];
		unsigned long long magic = magicbase |
			(unsigned long long)i;

		if ((unsigned long long)(uintptr_t)n->next !=
		    (unsigned long long)(uintptr_t)(i + 1 < NODE_N ?
						    &a[i + 1] : (const struct node *)0))
			return i;
		if (n->magic != magic)
			return i;
		if (n->guard != ~magic)
			return i;
		if (n->name[0] != 'S' || n->name[7] != (char)('0' + (i & 7)))
			return i;
	}
	return NODE_N;
}

static void __attribute__((noreturn))
canary_bad(const char *stage, unsigned int idx, unsigned long long got)
{
	char line[96];
	char *p = strcat_into(line, "CANARY-BAD stage=");

	p = strcat_into(p, stage);
	p = strcat_into(p, " idx=");
	p = utoa_dec(idx, p);
	p = strcat_into(p, " got=0x");
	p = utoa_dec(got, p);
	*p++ = '\n';
	sys_write(1, line, (unsigned long)(p - line));
	sys_exit(9);
}

/* The whole fill+verify cycle; exits the process on any mismatch. */
static unsigned long long cycle(void *arena, const char *stage,
				unsigned long long magicbase)
{
	unsigned int bad;

	arena_fill((struct node *)arena, magicbase);
	bad = arena_verify((const struct node *)arena, magicbase);
	if (bad != NODE_N) {
		const struct node *n = &((const struct node *)arena)[bad];

		canary_bad(stage, bad, (bad < NODE_N && n->magic) ?
			   n->magic : 0);
	}
	return magicbase;
}

/* Process entry (naked — no prologue may run before the realign;
 * the guardtest.c lesson: clang compiles _start as a NORMAL callee
 * (rsp+8 ≡ 0 mod 16 at entry) and the loader sets rsp at the SysV
 * PROCESS convention — arena_fill's SSE stores movaps/movups through
 * the misaligned frame and die at the prologue). Realign, jump. */
void canary_main(void);
void _start(void) __attribute__((naked, noreturn));
void _start(void)
{
	__asm__ volatile (
		"andq	$-16, %rsp\n\t"
		"subq	$8, %rsp\n\t"
		"xorl	%ebp, %ebp\n\t"
		"jmp	canary_main\n\t"
	);
}

void canary_main(void)
{
	static const char init_ok[] = "CANARY-INIT-OK\n";
	static const char recycle_ok[] = "CANARY-RECYCLE-OK\n";
	static const char fork_ok[] = "CANARY-FORK-OK\n";
	static const char all_ok[] = "CANARY-OK\n";
	static const char child_run[] = "CANARY-CHILD-RUN\n";
	void *arena;
	unsigned int round;
	char line[64];
	char *p;

	/* stage 1: fresh arena — anon mmap reads back ZERO (the
	 * __GFP_ZERO contract), then carries the pattern */
	arena = (void *)sys_mmap((void *)0, ARENA_LEN, 0x3 /*RW*/,
				 0x22 /*PRIVATE|ANON*/, -1, 0);
	if ((long)arena < 0 && (long)arena > -4096)
		canary_bad("mmap", 0,
			   (unsigned long long)(-(long)arena));
	{
		const unsigned long long *z = (const unsigned long long *)arena;
		unsigned int i;

		for (i = 0; i < NODE_N * sizeof(struct node) / 8; i += 64) {
			if (z[i] != 0)
				canary_bad("fresh-not-zero", i, z[i]);
		}
	}
	cycle(arena, "init", PARENT_MAGIC);
	sys_write(1, init_ok, sizeof(init_ok) - 1);

	/* stage 2: recycled runs — munmap + fresh mmap cycles; every
	 * fresh mapping must be ZERO (a recycled run leaking bytes is
	 * the 044 family, caught without systemd) */
	for (round = 0; round < 8; round++) {
		const unsigned long long *z = (const unsigned long long *)arena;
		unsigned int i;

		if (sys_munmap(arena, ARENA_LEN) != 0)
			canary_bad("munmap", round, 0);
		arena = (void *)sys_mmap((void *)0, ARENA_LEN, 0x3, 0x22,
					 -1, 0);
		if ((long)arena < 0 && (long)arena > -4096)
			canary_bad("mmap-recycle", round,
				   (unsigned long long)(-(long)arena));
		for (i = 0; i < NODE_N * sizeof(struct node) / 8; i += 64) {
			if (z[i] != 0)
				canary_bad("recycled-not-zero", i, z[i]);
		}
		cycle(arena, "recycle",
		      PARENT_MAGIC | ((unsigned long long)round << 32));
	}
	sys_write(1, recycle_ok, sizeof(recycle_ok) - 1);

	/* stage 3: fork/COW churn — the child verifies the fork-seed
	 * copy intact, rewrites the arena with ITS magic, verifies
	 * again and exits; the parent re-verifies its OWN arena after
	 * every reap (child bytes inside the parent = the injection
	 * class), then rewrites + re-verifies for the next round */
	cycle(arena, "fork-prep", PARENT_MAGIC);
	for (round = 0; round < 8; round++) {
		unsigned long long magic = PARENT_MAGIC |
			((unsigned long long)round << 32);
		long pid;
		int st = 0;

		pid = sys_fork();
		if (pid < 0)
			canary_bad("fork", round, 0);
		if (pid == 0) {
			/* child: a real kernel task on its own conn */
			unsigned int bad;

			sys_write(1, child_run, sizeof(child_run) - 1);
			bad = arena_verify((const struct node *)arena,
					   magic);
			if (bad != NODE_N)
				canary_bad("child-seed", bad, 0);
			cycle(arena, "child-rewrite",
			      CHILD_MAGIC | ((unsigned long long)round
					     << 32));
			sys_exit(7);
		}
		if (sys_wait4(pid, &st, 0, (void *)0) != pid ||
		    ((st >> 8) & 0xff) != 7)
			canary_bad("wait4", round,
				   (unsigned long long)st);
		{
			unsigned int bad = arena_verify(
				(const struct node *)arena, magic);

			if (bad != NODE_N)
				canary_bad("parent-after-fork", bad, 0);
		}
		/* the next round's seed pattern (round 7's rewrite is
		 * the final state the last child inherits) */
		arena_fill((struct node *)arena,
			   PARENT_MAGIC |
			   ((unsigned long long)(round + 1) << 32));
		{
			unsigned int bad = arena_verify(
				(const struct node *)arena,
				PARENT_MAGIC |
				((unsigned long long)(round + 1) << 32));

			if (bad != NODE_N)
				canary_bad("parent-rewrite", bad, 0);
		}
		p = strcat_into(line, "CANARY-FORK-ROUND ");
		p = utoa_dec(round, p);
		*p++ = '\n';
		sys_write(1, line, (unsigned long)(p - line));
	}
	sys_write(1, fork_ok, sizeof(fork_ok) - 1);
	sys_write(1, all_ok, sizeof(all_ok) - 1);
	sys_exit(0);
}
