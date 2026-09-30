// SPDX-License-Identifier: GPL-2.0
/* stub-impl.c (x86/um/os-Windows) — see stub-impl.h. Freestanding. */
#include "stub-impl.h"
#include <stub_nt.h>

/* S4d: the FP block rides the stub protocol (UML_STUB_XS_SIZE bytes
 * of XSAVE_FORMAT per trap — the stub captures CONTEXT.FloatSave,
 * the kernel pulls it into regs->fp and pushes it back). Upstream
 * discovers this size from the host ptrace regset; the NT format is
 * fixed by the protocol. Must be final before the first task alloc:
 * arch_task_struct_size = sizeof(task_struct) + host_fp_size
 * (um_arch.c). */
unsigned long host_fp_size = UML_STUB_XS_SIZE;
