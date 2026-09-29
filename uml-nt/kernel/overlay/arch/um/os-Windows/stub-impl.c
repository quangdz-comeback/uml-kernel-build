// SPDX-License-Identifier: GPL-2.0
/*
 * stub-impl.c — body of the temporary PANIC hook (see stub-impl.h).
 * Freestanding: no libc, no host syscalls. Loud, then park: an unreached
 * milestone failing silently looks exactly like a boot hang (it did, at
 * M1.8 — os_flush_stdout sat here while linux_main called it).
 */
#include <stub-impl.h>
#include "internal.h"

void stub_panic(const char *why)
{
	if (nt) {
		const char *why_s = why;

		nt_console_write("\numl-nt stub_panic: ", 20);
		while (*why_s) {
			const char *e = why_s;

			while (*e)
				e++;
			nt_console_write(why_s, (unsigned int)(e - why_s));
			why_s = e;
		}
		nt_console_write("\n", 1);
	}
	for (;;)
		;
}
