// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/umid.c — per-instance identity dir (/tmp/umid equivalent).
 * Upstream: linux v6.18.37 arch/um/os-Linux/umid.c
 * Status: M1.3 skeleton — PANICs; NT build will point umid at a
 * CreateDirectory-backed path instead of /tmp.
 */
#include <stub-impl.h>

int umid_file_name(char *name, char *buf, int len)
{
	stub_panic("umid.c: umid_file_name");
}

int set_umid(char *name)
{
	stub_panic("umid.c: set_umid");
}

char *get_umid(void)
{
	stub_panic("umid.c: get_umid");
}
