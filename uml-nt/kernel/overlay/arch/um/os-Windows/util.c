// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/util.c — misc host utilities + early console.
 * Upstream: linux v6.18.37 arch/um/os-Linux/util.c
 *
 * The early console is the M1 lifeline: um_early_printk writes straight
 * to the inherited stdout handle via NtWriteFile (no channel stack —
 * drivers/ returns at M3). os_info/os_warn format with the kernel's
 * vscnprintf and ride the same path.
 */
#include <linux/stdarg.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <ntabi.h>
#include <os.h>
#include "internal.h"

void nt_console_write(const char *s, unsigned int n)
{
	IO_STATUS_BLOCK iosb;

	if (nt == NULL || uml_boot.stdio_out == NULL || n == 0)
		return;
	nt->NtWriteFile(uml_boot.stdio_out, NULL, NULL, NULL, &iosb,
			(void *)s, n, NULL, NULL);
}

void um_early_printk(const char *s, unsigned int n)
{
	nt_console_write(s, n);
}

void os_info(const char *fmt, ...)
{
	char buf[256];
	va_list args;
	int n;

	va_start(args, fmt);
	n = vscnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	if (n > 0)
		nt_console_write(buf, n);
	nt_console_write("\n", 1);
}

void os_warn(const char *fmt, ...)
{
	char buf[256];
	va_list args;
	int n;

	va_start(args, fmt);
	n = vscnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	if (n > 0)
		nt_console_write(buf, n);
	nt_console_write("\n", 1);
}

void os_dump_core(void)
{
	/* Upstream: dump logs + core file via host tools. NT M1: flush
	 * the console and terminate the process (dump-to-file at M4). */
	nt_console_write("\numl-nt: os_dump_core — terminating\n", 37);
	if (nt != NULL)
		nt->NtTerminateProcess(UML_NT_CURRENT_PROCESS, 1);
	for (;;)
		;
}

void stack_protections(unsigned long address)
{
	/* Upstream: mprotect the IRQ stack non-exec/no-access guards. The
	 * NT kernel image has no per-stack guard pages yet (M4 hardening).
	 * Deliberate no-op — must not PANIC, boot calls it. */
}

int raw(int fd)
{
	/* tty raw mode — console on NT is always 8-bit-clean; the fd
	 * abstraction arrives with the chan port (M3). */
	return 0;
}

void setup_machinename(char *machine_out)
{
	/* Upstream: host uname -m. The guest kernel arch is fixed x86_64. */
	strcpy(machine_out, "x86_64");
}

void setup_hostinfo(char *buf, int len)
{
	snprintf(buf, len, "%s", "uml-nt (Windows NT host)");
}

ssize_t os_getrandom(void *buf, size_t len, unsigned int flags)
{
	/* NT: ProcessPrng (bcryptprimitives) — not in the D9 table yet;
	 * the guest entropy story lands with the network stack (M5).
	 * Filling with a weak-but-nonzero pattern keeps boot unblocked. */
	memset(buf, 0xA5, len);
	return len;
}

void os_fix_helper_signals(void)
{
	/* helper threads use NT threads, no signals to fix (D7). */
}

void os_flush_stdout(void)
{
	/* Console writes are synchronous NtWriteFile — nothing buffered
	 * to flush (upstream: fflush(stdout)). */
}
