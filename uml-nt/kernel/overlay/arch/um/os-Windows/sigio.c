// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/sigio.c — SIGIO delivery has no NT equivalent.
 * Upstream: linux v6.18.37 arch/um/os-Linux/sigio.c
 *
 * Upstream keeps the async-fd (O_ASYNC) plumbing for the "SIGIO via
 * host signal" model: these helpers fcntl the fd, spawn a sigio
 * thread, and detect a broken async state. The NT port delivers IO
 * readiness through the irq.c registry + flag machine instead (D19) —
 * the aux reader thread replaces the signal entirely. The kernel-side
 * irq.c still calls maybe_sigio_broken/ignore_sigio_fd at the
 * upstream call sites, so the functions stay as honest no-ops rather
 * than being removed (os.h parity, M1.3 convention).
 */
#include <os.h>

int add_sigio_fd(int fd)
{
	(void)fd;
	return 0;
}

int ignore_sigio_fd(int fd)
{
	(void)fd;
	return 0;
}

void maybe_sigio_broken(int fd)
{
	(void)fd;
}

void sigio_broken(void)
{
}

int __add_sigio_fd(int fd)
{
	(void)fd;
	return 0;
}

int __ignore_sigio_fd(int fd)
{
	(void)fd;
	return 0;
}
