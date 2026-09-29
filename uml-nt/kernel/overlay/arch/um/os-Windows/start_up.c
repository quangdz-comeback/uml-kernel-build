// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/start_up.c — pre-kernel start helpers.
 * Upstream: linux v6.18.37 arch/um/os-Linux/start_up.c
 *
 * Most of start_up.c upstream is ptrace/skas setup (D6: not on NT).
 * What remains for M1: cpu-feature feeding for the boot arch code,
 * boot-time checks (no-ops on NT), and the D9 table self-check.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <ntabi.h>
#include <stub-panic.h>

#include <os.h>
#include "internal.h"

void os_early_checks(void)
{
	/* upstream: /tmp exec + tmpfs probes — nothing applies on NT */
}

void os_check_bugs(void)
{
	/* upstream /proc/cpuinfo sanity — nothing to check on NT */
}

void get_host_cpu_features(void (*flags_helper_func)(char *line),
			   void (*cache_helper_func)(char *line))
{
	/* Upstream feeds /proc/cpuinfo lines. NT: synthesize the one
	 * line the guest arch code needs (FPU flag so boot settles). */
	flags_helper_func("flags\t\t: fpu");
	cache_helper_func("cache_alignment\t: 64");
}

int __init parse_iomem(char *str, int *add)
{
	/* /proc/iomem doesn't exist on NT; no host iomem map for M1. */
	os_warn("parse_iomem: no host iomem on NT — ignored\n");
	return 0;
}

int uml_nt_check_api_table(void)
{
	/* Launcher must have handed a compatible table (D9). Checked in
	 * nt_main already; a second explicit check keeps os-layer code
	 * able to rely on `nt` unconditionally. */
	if (nt == NULL)
		return -1;
	if (nt->version != UML_NT_API_VERSION)
		return -1;
	if (nt->size < sizeof(struct uml_nt_api_table))
		return -1;
	return 0;
}

/* ---- M3.8: kernel-process crash reporter ----------------------------- *
 * Upstream parity: UML's kernel process installs a SIGSEGV handler
 * that panics loudly on kernel faults (arch/um/kernel/trap.c + the
 * os-Linux signal layer). On NT nothing caught a wild kernel-side
 * deref: the process died STATUS_ACCESS_VIOLATION and the CI shell
 * reported a bare "exit 139" — no location, no address (the busybox
 * S4c2 window). VEH fires before any debugger/wer machinery; the
 * handler must assume the world is broken:
 *   - write DIRECTLY via NtWriteFile on boot.stdio_out, bypassing
 *     nt_console_write's spinlock (the crashing thread may hold it);
 *   - then terminate exit 1 (os_dump_core parity) — never resume
 *     into a corrupted kernel.
 * Every exception in the kernel process is fatal-by-definition
 * (nothing here raises/handles exceptions legitimately — S1 kept
 * VEH strictly in the stub process). */

static void uml_nt_crash_write(const char *s, unsigned int n)
{
	IO_STATUS_BLOCK iosb;

	if (nt == NULL || uml_boot.stdio_out == NULL || n == 0)
		return;
	nt->NtWriteFile(uml_boot.stdio_out, NULL, NULL, NULL, &iosb,
			(void *)s, n, NULL, NULL);
}

static LONG __attribute__((ms_abi)) uml_nt_crash_report(void *ep)
{
	const struct uml_nt_exception_pointers *e = ep;
	const struct uml_nt_exception_record *r =
		(e != NULL) ? e->record : NULL;
	unsigned long long rip = (e != NULL && e->context != NULL) ?
				 UML_NT_X64_CTX_RIP(e->context) : 0;
	char buf[192];
	int n;

	n = snprintf(buf, sizeof(buf),
		     "\numl-nt: KERNEL NATIVE FAULT code=%08x rip=%llx "
		     "addr=%llx op=%d info1=%llx — terminating\n",
		     r != NULL ? (unsigned int)r->code : 0, rip,
		     r != NULL ? (unsigned long long)r->address : 0,
		     (r != NULL && r->nparams > 1) ?
			     (int)r->info[0] : -1,
		     (r != NULL && r->nparams > 1) ? r->info[1] : 0);
	if (n > 0)
		uml_nt_crash_write(buf, (unsigned int)n);
	if (nt != NULL)
		nt->NtTerminateProcess(UML_NT_CURRENT_PROCESS, 1);
	for (;;)
		;
}

void uml_nt_install_crash_reporter(void)
{
	/* FIRST handler: the reporter must see the exception before
	 * anything else could swallow it. A non-AV kill (terminate from
	 * outside) does not go through VEH — the process just exits. */
	if (nt->AddVectoredExceptionHandler(1,
			(PVOID)uml_nt_crash_report) == NULL)
		os_warn("crash reporter: VEH install failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
}

/* Kernel glue data (declared extern by kernel sources):
 * no seccomp on NT (D6); no auxv hwcap on NT (no ELF loader). */
int using_seccomp;
unsigned long elf_aux_hwcap;
