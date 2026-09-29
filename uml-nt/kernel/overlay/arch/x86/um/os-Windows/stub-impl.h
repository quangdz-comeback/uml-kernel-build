/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub-impl.h (x86/um/os-Windows) — TEMPORARY scaffolding for the M1.4
 * skeleton, same role as arch/um/os-Windows/include/stub-impl.h: lets the
 * NT seams compile freestanding before real NT CONTEXT plumbing (M2).
 * Deleted when the modules gain real implementations.
 */
#ifndef __X86_UM_OS_WINDOWS_STUB_IMPL_H
#define __X86_UM_OS_WINDOWS_STUB_IMPL_H

typedef int pid_t;
typedef long ssize_t;
typedef unsigned long size_t;

/* Opaque stand-in for the host ucontext mcontext: on NT the source of
 * truth is the VEH NT CONTEXT (S1), mapped in M2. */
typedef struct {
	unsigned long long opaque[32];
} mcontext_t;

/* Minimal mirror of sysdep/ptrace.h uml_pt_regs for signature parity. */
struct uml_pt_regs {
	unsigned long gp[27];
	unsigned long fp[3];
};

struct stub_data;

/* Mirror of the setjmp.h jmp_buf shape used by upstream signatures. */
typedef struct {
	unsigned long long opaque[16];
} jmp_buf;

void stub_panic(const char *why) __attribute__((noreturn));
extern unsigned long host_fp_size;

#endif
