/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/forkwait.c — M4.2 block-wait proof (real fork + scheduler).
 *
 * Runs as PID 1 via init=/bin/forkwait (its own launcher run). fork()
 * now goes through the GENERIC copy_process path on the kernel side:
 * the child is a real kernel task (cold stack at fork_handler) with
 * its own conn (init_new_context spawn) whose userspace() loop serves
 * it — not the POC bare-stub fork. The parent's wait4 therefore must
 * BLOCK (do_wait → schedule()) while the scheduler runs the child's
 * stack; the child's exit(7) runs the real do_exit teardown and wakes
 * the parent. The marker ORDER proves the block: WAIT-BLOCK-ENTER is
 * printed by the parent BEFORE wait4, CHILD-RUN by the child while
 * the parent is blocked (nothing else could run the child — one host
 * thread), WAIT-OK only when wait4 returned the child pid with
 * WEXITSTATUS 7. The POC wait4 (-EAGAIN retry) cannot produce this:
 * a live child always answered -EAGAIN.
 *
 * Freestanding static, linked INSIDE the guest window (--image-base,
 * see Makefile).
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

	/* arg4 lives in r10 (rcx/r11 are clobbered by syscall itself —
	 * the M3.7 lesson). */
	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (61L), "D" (pid), "S" (status),
			    "d" (options), "r" (r10)
			  : "rcx", "r11", "memory");
	return ret;
}

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

void _start(void)
{
	static const char block_enter[] = "WAIT-BLOCK-ENTER\n";
	static const char child_run[] = "CHILD-RUN\n";
	long pid, r;
	int st = 0;
	char line[64];
	char *p;

	pid = sys_fork();
	if (pid < 0) {
		sys_write(1, "FORK-FAIL\n", 10);
		sys_exit(8);
	}
	if (pid == 0) {
		/* The child: a REAL kernel task now — this write and
		 * exit go through ITS conn and its do_exit wakes the
		 * blocked parent. */
		sys_write(1, child_run, sizeof(child_run) - 1);
		sys_exit(7);
	}

	p = strcat_into(line, "FORK-PID: ");
	p = utoa_dec((unsigned long)pid, p);
	*p++ = '\n';
	sys_write(1, line, (unsigned long)(p - line));

	/* The child cannot have run yet: the host thread is on the
	 * parent's stack and the child's userspace() loop starts only
	 * when this wait4 blocks and schedule() switches stacks. */
	sys_write(1, block_enter, sizeof(block_enter) - 1);
	r = sys_wait4(pid, &st, 0, (void *)0);

	p = strcat_into(line, "WAIT-RESULT r=");
	if (r < 0) {
		*p++ = '-';
		p = utoa_dec((unsigned long)(-r), p);
	} else {
		p = utoa_dec((unsigned long)r, p);
	}
	p = strcat_into(p, " st=");
	p = utoa_dec((unsigned long)st, p);
	*p++ = '\n';
	sys_write(1, line, (unsigned long)(p - line));

	if (r == pid && (st >> 8) == 7) {
		sys_write(1, "WAIT-OK: child reaped, exit 7\n", 30);
		sys_write(1, "FORKWAIT-OK\n", 12);
		sys_exit(0);
	}
	sys_write(1, "WAIT-BAD\n", 9);
	sys_exit(9);
}
