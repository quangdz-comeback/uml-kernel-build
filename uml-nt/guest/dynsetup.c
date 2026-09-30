/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/dynsetup.c — M5.4 cluster 2 (D20): the dynamic-lib proof.
 *
 * PID 1 of the c2 gate's own launcher run (init=/bin/dynsetup): this
 * binary is static freestanding (the c1 machinery proved dynamic
 * START; it execve()s the DYNAMIC busybox — /bin/busybox-dyn, musl
 * dynamic: PT_INTERP /lib/ld-musl-x86_64.so.1 + DT_NEEDED libc.so).
 * The dynamic exec rides c1 (interp as second image + full auxv);
 * the applet's own write to the console is the evidence that
 * ld-musl resolved the DT_NEEDED libc against itself and the app
 * ran: DYNBUSY-OK. The glibc cluster (ld.so mapping libc.so.6 via
 * file-backed mmap + the D20 exec sweep) is the PVE image's
 * /bin/true — local, no CI artifact (hard rule).
 *
 * Freestanding static, no libc; same link recipe as the other
 * guests (in-window base — baked absolute pointers are real
 * addresses).
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

static const char fail[] = "DYNSETUP-EXEC-FAIL (busybox-dyn echo)\n";

void _start(void)
{
	static char *argv[] = { "busybox-dyn", "echo", "M5.4-C2-DYNBUSY-OK",
				0 };
	static char *envp[] = { 0 };

	if (sys_execve("/bin/busybox-dyn", argv, envp) < 0) {
		sys_write(2, fail, sizeof(fail) - 1);
		sys_exit(1);
	}
	sys_exit(0); /* unreachable — the exec replaced this image */
}
