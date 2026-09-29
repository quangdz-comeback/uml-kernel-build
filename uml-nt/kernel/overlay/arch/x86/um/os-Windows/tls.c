// SPDX-License-Identifier: GPL-2.0
/*
 * x86/um/os-Windows/tls.c — GDT thread-area plumbing (i386 heritage).
 * Upstream: linux v6.18.37 arch/x86/um/os-Linux/tls.c
 *
 * NT has no settable GDT entries for user TLS; x86_64 guests set FS/GS
 * BASE directly (stub_data arch_data sync, M2). Kept for link parity —
 * D1 forbids ELF TLS, so these only ever PANIC if actually reached.
 * Status: M1.4 skeleton.
 */
#include "stub-impl.h"

typedef struct {
	unsigned int entry_number;
	unsigned long long opaque[4];
} user_desc_t;

void check_host_supports_tls(int *supports_tls, int *tls_min)
{
	stub_panic("tls.c: check_host_supports_tls — NT: no GDT TLS (D1)");
}

int os_set_thread_area(user_desc_t *info, int pid)
{
	stub_panic("tls.c: os_set_thread_area");
}

int os_get_thread_area(user_desc_t *info, int pid)
{
	stub_panic("tls.c: os_get_thread_area");
}
