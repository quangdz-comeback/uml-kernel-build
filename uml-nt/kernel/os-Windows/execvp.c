// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/execvp.c — PATH-resolving exec helper.
 * Upstream: linux v6.18.37 arch/um/os-Linux/execvp.c
 * Status: M1.3 skeleton — PANICs. NT path goes through CreateProcess;
 * the helper survives only if some cmdline-driven exec needs PATH lookup.
 */
#include <stub-impl.h>

int execvp_noalloc(char *buf, const char *file, char *const argv[])
{
	stub_panic("execvp.c: execvp_noalloc");
}
