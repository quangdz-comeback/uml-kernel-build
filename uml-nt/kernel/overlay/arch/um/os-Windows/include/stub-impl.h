/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub-impl.h — TEMPORARY scaffolding for the os-Windows skeleton (M1.3).
 *
 * Why: each os-Windows module must compile standalone (clang
 * --target=x86_64-linux-gnu -ffreestanding) before Kbuild integration
 * (M1.4) and before the real NT implementation lands (M1.5+). This header
 * provides only the minimal type surface os.h signatures need.
 *
 * When a module gets its real implementation, stop including this header
 * from that module and include the real kernel headers (<os.h>, ...) —
 * then delete this file entirely.
 */
#ifndef __OS_WINDOWS_STUB_IMPL_H
#define __OS_WINDOWS_STUB_IMPL_H

typedef int pid_t;
typedef long ssize_t;
typedef unsigned long size_t;

/* Mirror of upstream struct openflags (os.h) — needed by value. */
struct openflags {
	unsigned int r:1, w:1, c:1, a:1, cl:1;
};

/* NT threads replace siglongjmp threads; opaque until M2 decides the
 * exact context-switch mechanism (jmp_buf here only for signature parity). */
typedef struct {
	unsigned long long opaque[16];
} jmp_buf;

/* Mirror of upstream enum um_irq_type (irq_user.h). */
enum um_irq_type {
	IRQ_READ,
	IRQ_WRITE,
	IRQ_PENDING,
};

/* PANIC-style placeholder — every skeleton entry point lands here. */
#include "stub-panic.h"

/* Forward decls: only ever used by pointer in os.h signatures. */
struct uml_stat;
struct mm_id;
struct uml_pt_regs;
struct os_helper_thread;

#endif /* __OS_WINDOWS_STUB_IMPL_H */
