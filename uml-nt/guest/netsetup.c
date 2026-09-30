/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/netsetup.c — M5.1c: bring the D8 channel up to a guest lease.
 *
 * PID 1 of the net gate's own launcher run (init=/bin/netsetup): the
 * vector device (vec0 — spawned helper + dialed TCP channel) shows up
 * The vector device keeps its own name upstream (vec0 — the howto's
 * `iface vec0 inet dhcp`; there is no eth0 rename), and this binary
 * execve()s busybox sh onto /net.sh, which
 * runs udhcpc (DHCP DISCOVER through the vector TX path, OFFER/ACK
 * back through the D19 reader ring) and pings the NAT gateway. The
 * markers NET-LEASE-OK / NET-PING-GW-OK are the gate's evidence.
 *
 * Freestanding static, no libc; same link recipe as the other guests
 * (in-window base — baked absolute pointers are real addresses).
 */
#include <stdint.h>

static long sys_execve(const char *path, char **argv, char **envp)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (59L), "D" (path), "S" (argv),
			    "d" (envp)
			  : "rcx", "r11", "memory");
	return ret;
}

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

static const char fail[] = "NETSETUP-EXEC-FAIL (busybox sh /net.sh)\n";

void _start(void)
{
	static char *argv[] = { "/bin/busybox", "sh", "/net.sh", 0 };
	static char *envp[] = { 0 };

	if (sys_execve("/bin/busybox", argv, envp) < 0) {
		sys_write(2, fail, sizeof(fail) - 1);
		sys_exit(1);
	}
	sys_exit(0); /* unreachable — the exec replaced this image */
}
