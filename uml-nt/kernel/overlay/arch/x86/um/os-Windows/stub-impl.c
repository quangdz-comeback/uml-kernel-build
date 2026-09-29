// SPDX-License-Identifier: GPL-2.0
/* stub-impl.c (x86/um/os-Windows) — see stub-impl.h. Freestanding. */
#include "stub-impl.h"

unsigned long host_fp_size;

void stub_panic(const char *why)
{
	for (;;)
		;
}
