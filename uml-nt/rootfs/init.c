/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rootfs/init.c — minimal static /sbin/init for the boot gates.
 *
 * M3.5: the CI gate mounted an ext4 root image and expected the
 * kernel to find and run this binary; write to fd 1 failed with
 * -EBADF (no console then) and exit 42 made the "Attempted to kill
 * init!" panic the pass signal.
 *
 * M3.8 S3 (binfmt_umlnt): the exec now runs the real chain —
 * do_execve → binfmt_umlnt loads this ELF into the conn (D17) → the
 * S2 userspace() loop serves it → write(2) goes through the D16
 * dispatch to the console and exit(0) halts the stub (kernel panic,
 * exit 1). The gate greps INIT-SYSCALL-OK: the marker must appear on
 * the console THROUGH the exec + userspace path, not just the probe.
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
	sys_write(1, "INIT-SYSCALL-OK\n", 16);
	sys_exit(0);
}
