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

/* Kernel glue data (declared extern by kernel sources):
 * no seccomp on NT (D6); no auxv hwcap on NT (no ELF loader). */
int using_seccomp;
unsigned long elf_aux_hwcap;
