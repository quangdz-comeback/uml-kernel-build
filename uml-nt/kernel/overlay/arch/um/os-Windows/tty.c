// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/tty.c — console/pty seam.
 * Upstream: linux v6.18.37 arch/um/os-Linux/tty.c
 *
 * The NT backend pipes console IO (ARCHITECTURE §3); get_pty() maps to
 * the pipe pair creation used by launcher.exe. Upstream also declares
 * `long syscall(long, ...)` here — dropped: no host-syscall gateway on
 * the freestanding NT kernel (D1). Status: M1.3 skeleton — PANICs.
 */
#include <stub-impl.h>

int get_pty(void)
{
	stub_panic("tty.c: get_pty — NT: anonymous pipe pair with FILE_FLAG_OVERLAPPED");
}
