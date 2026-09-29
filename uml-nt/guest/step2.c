/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/step2.c — S4c: the exec-chain proof binary.
 *
 * /sbin/init (rootfs/init.c) execve()s this file through the guest
 * syscall path: the dispatch handler (D16) runs kernel_execve in the
 * init task's context — do_execve walks the real VFS (ext4/ubd),
 * binfmt_umlnt loads THIS image into a NEW conn and the userspace()
 * loop restarts on it. Printing STEP2-OK proves the full chain:
 * guest execve → conn switch → second exec → the D16 write path.
 *
 * Freestanding static, no TLS (musl needs arch_prctl — S4c2), tiny
 * by design: the loader reads the whole file into kernel memory.
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
	sys_write(1, "STEP2-OK\n", 9);
	sys_exit(0);
}
