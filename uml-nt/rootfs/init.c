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

/* arg4 lives in r10 on the x86_64 syscall ABI (rcx/r11 are clobbered
 * by the syscall instruction itself — that is why the probe went
 * wrong in M3.7 when rax was reused as an address register). */
static long sys_openat(int dfd, const char *path, long flags, long mode)
{
	long ret;
	register long r10 __asm__ ("r10") = mode;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (257L), "D" ((long)dfd), "S" (path),
			    "d" (flags), "r" (r10)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_read(int fd, void *buf, unsigned long len)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (0L), "D" ((long)fd), "S" (buf),
			    "d" (len)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_close(int fd)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (3L), "D" ((long)fd)
			  : "rcx", "r11", "memory");
	return ret;
}

/* Success never returns — the task becomes the new image (the
 * kernel-side dispatch runs kernel_execve and the userspace() loop
 * restarts on the new conn). */
static long sys_execve(const char *path, const char *const *argv,
		       const char *const *envp)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (59L), "D" (path), "S" (argv),
			    "d" (envp)
			  : "rcx", "r11", "memory");
	return ret;
}

/*
 * M3.8 S4b: the exec chain still starts here, but the S4 goal is the
 * busybox shell — this init now proves the REAL VFS surface first:
 * openat("/hi.sh") + read + close go through do_sys_openat2 /
 * vfs_read on the guest kernel (ubd → ext4), with the guest pointers
 * translated by the D15 uaccess walker. The bytes read back are the
 * script busybox will run in S4c — the gate asserts them verbatim.
 */
void _start(void)
{
	static char buf[256];
	long fd, n;

	sys_write(1, "INIT-SYSCALL-OK\n", 16);

	fd = sys_openat(-100 /* AT_FDCWD */, "/hi.sh", 0 /* O_RDONLY */, 0);
	if (fd < 0) {
		sys_write(1, "OPENAT-FAIL\n", 12);
		sys_exit(3);
	}
	n = sys_read(fd, buf, sizeof(buf));
	if (n <= 0) {
		sys_write(1, "READ-FAIL\n", 10);
		sys_exit(4);
	}
	if (sys_close(fd) != 0) {
		sys_write(1, "CLOSE-FAIL\n", 11);
		sys_exit(5);
	}
	/* Print the content ESCAPED on one line. A raw multi-line
	 * write leaked the script's own lines into the log ("echo
	 * BUSYBOX-SHELL-OK" as a standalone line) — the S4c2
	 * acceptance grep matched the LEAK once, not busybox's echo. */
	{
		unsigned long i;

		sys_write(1, "OPENAT-READ-OK: ", 16);
		for (i = 0; i < (unsigned long)n; i++) {
			if (buf[i] == '\n') {
				sys_write(1, "\\n", 2);
			} else if (buf[i] == 0) {
				sys_write(1, "\\0", 2);
			} else {
				sys_write(1, &buf[i], 1);
			}
		}
		sys_write(1, "\n", 1);
	}

	/* S4c: chain the exec — the dispatch's kernel_execve swaps this
	 * task to /bin/step2 (STEP2-OK, exit 0); a failure returns
	 * errno here. */
	{
		static const char *const argv[] = { "/bin/step2", (void *)0 };

		if (sys_execve("/bin/step2", argv, (void *)0) != 0) {
			sys_write(1, "EXEC-FAIL\n", 10);
			sys_exit(6);
		}
	}
	sys_exit(0); /* unreachable: exec success never returns */
}
