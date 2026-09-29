/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rootfs/init.c — minimal static /sbin/init for the M3.5 boot gate.
 *
 * The M3.5 CI gate mounts an ext4 root image and expects the kernel to
 * find and run this binary. No libc, no console (the TTY stack lands
 * at M3.6): write to fd 1 anyway (it fails with -EBADF, harmless),
 * then exit 42 — the kernel's "Attempted to kill init!" panic prints
 * the exit code, which the boot log grep turns into the pass signal.
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

void _start(void)
{
	sys_write(1, "INIT-RAN\n", 9);
	sys_exit(42);
}
