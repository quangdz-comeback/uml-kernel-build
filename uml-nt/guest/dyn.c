/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/dyn.c — M5.4 cluster 1 (D20): the dynamic-PIE proof.
 *
 * PID 1 of the dyn gate's own launcher run (init=/bin/dyntest): this
 * binary is ET_DYN with a PT_INTERP (—dynamic-linker=/lib/ld-musl-
 * x86_64.so.1, copied into the image as /lib/ld-musl-x86_64.so.1) —
 * binfmt_umlnt loads the interpreter as a SECOND image (ET_DYN
 * first-fit), starts it at the interp entry with the full auxv
 * (AT_PHDR/AT_PHENT/AT_PHNUM/AT_BASE/AT_ENTRY/ids/AT_RANDOM...), and
 * ld-musl self-relocates, sets its TLS (arch_prctl, D18) and jumps
 * to AT_ENTRY — here. Raw syscalls only (no DT_NEEDED: ld.so maps
 * nothing — the mmap-exec patch hook is cluster 2, glibc census).
 * DYNTASK-OK on the console is the gate's evidence; exit(0) halts
 * (the usual panic exit 1).
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

static const char ok[] = "DYNTASK-OK\n";
static const char fail[] = "DYNTASK-FAIL\n";

void _start(void)
{
	if (sys_write(1, ok, sizeof(ok) - 1) != sizeof(ok) - 1) {
		sys_write(2, fail, sizeof(fail) - 1);
		sys_exit(1);
	}
	sys_exit(0);
}
