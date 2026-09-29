// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/start_up.c — early host checks before the kernel is up.
 * Upstream: linux v6.18.37 arch/um/os-Linux/start_up.c
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

/*
 * Upstream sets this from the "seccomp" cmdline check (os-Linux/
 * start_up.c); the NT backend has neither ptrace (D6) nor seccomp, so
 * it is permanently 0 — kept as a symbol because kernel/skas/mmu.c and
 * the stub loaders read it.
 */
int using_seccomp;
/*
 * Upstream keeps parse_iomem here since 6.18 (see M1.2 diff notes);
 * __uml_setup handler — only reached when the guest cmdline carries
 * iomem=, which the M1 boot never passes.
 */
int parse_iomem(char *str, int *add)
{
	stub_panic("start_up.c: parse_iomem");
}

void os_early_checks(void)
{
	stub_panic("start_up.c: os_early_checks");
}

void os_check_bugs(void)
{
	stub_panic("start_up.c: os_check_bugs");
}

void get_host_cpu_features(void (*flags_helper_func)(char *line),
			   void (*cache_helper_func)(char *line))
{
	stub_panic("start_up.c: get_host_cpu_features — NT: __cpuid/GetLogicalProcessorInformationEx");
}
