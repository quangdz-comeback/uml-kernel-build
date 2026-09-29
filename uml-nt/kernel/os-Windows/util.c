// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/util.c — misc host utilities + early console.
 * Upstream: linux v6.18.37 arch/um/os-Linux/util.c
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

void stack_protections(unsigned long address)
{
	stub_panic("util.c: stack_protections");
}

int raw(int fd)
{
	stub_panic("util.c: raw — tty raw mode; NT: console mode API");
}

void setup_machinename(char *machine_out)
{
	stub_panic("util.c: setup_machinename");
}

void setup_hostinfo(char *buf, int len)
{
	stub_panic("util.c: setup_hostinfo");
}

ssize_t os_getrandom(void *buf, size_t len, unsigned int flags)
{
	stub_panic("util.c: os_getrandom — NT: ProcessPrng/RTL_CAPTURE");
}

void os_dump_core(void)
{
	stub_panic("util.c: os_dump_core");
}

void os_fix_helper_signals(void)
{
	stub_panic("util.c: os_fix_helper_signals");
}

void os_info(const char *fmt, ...)
{
	stub_panic("util.c: os_info");
}

void os_warn(const char *fmt, ...)
{
	stub_panic("util.c: os_warn");
}

void um_early_printk(const char *s, unsigned int n)
{
	stub_panic("util.c: um_early_printk — NT: NtWriteFile to stdout handle (first console seam, M1.7)");
}
