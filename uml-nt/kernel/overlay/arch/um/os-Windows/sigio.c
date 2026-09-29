// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/sigio.c — SIGIO delivery has no NT equivalent.
 * Upstream: linux v6.18.37 arch/um/os-Linux/sigio.c
 *
 * Why keep the file at all: os.h parity for kernel-side callers until
 * M1.7 decides whether the async-fd path collapses into IOCP completions
 * entirely (expected). Status: M1.3 skeleton — PANICs.
 */
#include <stub-impl.h>

int add_sigio_fd(int fd)
{
	stub_panic("sigio.c: add_sigio_fd");
}

int ignore_sigio_fd(int fd)
{
	stub_panic("sigio.c: ignore_sigio_fd");
}

void maybe_sigio_broken(int fd)
{
	stub_panic("sigio.c: maybe_sigio_broken");
}

void sigio_broken(void)
{
	stub_panic("sigio.c: sigio_broken");
}

int __add_sigio_fd(int fd)
{
	stub_panic("sigio.c: __add_sigio_fd");
}

int __ignore_sigio_fd(int fd)
{
	stub_panic("sigio.c: __ignore_sigio_fd");
}
