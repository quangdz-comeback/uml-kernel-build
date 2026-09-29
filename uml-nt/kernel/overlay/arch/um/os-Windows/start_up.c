// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/start_up.c — early host checks before the kernel is up.
 * Upstream: linux v6.18.37 arch/um/os-Linux/start_up.c
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

void os_early_checks(void)
{
	stub_panic("start_up.c: os_early_checks");
}

void os_check_bugs(void)
{
	stub_panic("start_up.c: os_check_bugs");
}

void check_host_supports_tls(int *supports_tls, int *tls_min)
{
	stub_panic("start_up.c: check_host_supports_tls — D1: no ELF TLS on NT");
}

void get_host_cpu_features(void (*flags_helper_func)(char *line),
			   void (*cache_helper_func)(char *line))
{
	stub_panic("start_up.c: get_host_cpu_features — NT: __cpuid/GetLogicalProcessorInformationEx");
}
