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
 * S4c2 adds the TLS proof: arch_prctl(ARCH_SET_FS) through the
 * dispatch, then a %fs:0 read-back. The read-back only prints
 * TLS-OK when the stub's D18 re-apply worked — the FS base has
 * crossed one full syscall round-trip (publish → kernel → resume)
 * plus whatever the scheduler did meanwhile, and the VEH repair
 * covers a wipe between resume and the mov. The anonymous mmap
 * check is the musl malloc floor (brk fallback covered by case 12).
 *
 * Freestanding static, no libc; linked INSIDE the guest window
 * (--image-base, see Makefile — baked absolute pointers here are
 * real addresses, not link-VA fossils).
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

static long sys_arch_prctl(long code, long addr)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (158L), "D" (code), "S" (addr)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_mmap_anon_rw(unsigned long len)
{
	long ret;
	register long r10 __asm__ ("r10") = 0x22L; /* MAP_PRIVATE|ANON */
	register long r8  __asm__ ("r8")  = -1L;   /* fd: -1 */
	register long r9  __asm__ ("r9")  = 0L;    /* offset */

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (9L), "D" (0L), "S" (len), "d" (3L)
			    /* PROT_READ|PROT_WRITE */,
			    "r" (r10), "r" (r8), "r" (r9)
			  : "rcx", "r11", "memory");
	return ret;
}

void _start(void)
{
	char tp[64];
	unsigned long got, *fs0 = (unsigned long *)tp;
	long mm;

	sys_write(1, "STEP2-OK\n", 9);

	/* TLS through the D18 path: SET_FS round-trips to the kernel
	 * (which records + republishes the base), the stub re-applies
	 * it at resume, then we dereference through %fs. */
	if (sys_arch_prctl(0x1002 /* ARCH_SET_FS */, (long)fs0) == 0) {
		__asm__ volatile ("movq %%fs:0, %0" : "=r" (got));
		if (got == (unsigned long)fs0)
			sys_write(1, "TLS-OK\n", 7);
		else
			sys_write(1, "TLS-BAD\n", 8);
	} else {
		sys_write(1, "TLS-FAIL\n", 9);
	}

	mm = sys_mmap_anon_rw(4096);
	if (mm > 0) {
		*(volatile int *)mm = 0x5a5a;
		if (*(volatile int *)mm == 0x5a5a)
			sys_write(1, "MMAP-OK\n", 8);
		else
			sys_write(1, "MMAP-BAD\n", 9);
	} else {
		sys_write(1, "MMAP-FAIL\n", 10);
	}

	sys_exit(0);
}
