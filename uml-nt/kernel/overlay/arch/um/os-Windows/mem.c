// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/mem.c — guest physical memory backing store.
 * Upstream: linux v6.18.37 arch/um/os-Linux/mem.c (IDENTICAL to the old
 * snapshot — see research/v6.18.37-diff-notes.md).
 * The NT backend replaces the memfd/physfd with the pagefile-backed
 * section created by launcher.exe (ARCHITECTURE §2); this file keeps the
 * kernel-side seam. Status: M1.3 skeleton — PANICs.
 */
#include <stub-impl.h>

int create_mem_file(unsigned long long len)
{
	stub_panic("mem.c: create_mem_file — NT: pagefile section, 64KB allocation granularity (S5)");
}
