// SPDX-License-Identifier: GPL-2.0
/*
 * stub-impl.c — body of the temporary PANIC hook (see stub-impl.h).
 * Freestanding: no libc, no host syscalls; park forever if ever reached.
 */
#include <stub-impl.h>

void stub_panic(const char *why)
{
	for (;;)
		;
}
