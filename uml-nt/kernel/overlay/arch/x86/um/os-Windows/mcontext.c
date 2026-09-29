// SPDX-License-Identifier: GPL-2.0
/*
 * x86/um/os-Windows/mcontext.c — mcontext <-> uml_pt_regs conversion.
 * Upstream: linux v6.18.37 arch/x86/um/os-Linux/mcontext.c (ucontext +
 * xstate-in-sigstack). NT: the VEH NT CONTEXT carries gp; FP/xstate comes
 * from an explicit XSAVE performed by the stub into its data page (M2).
 * Status: M1.4 skeleton — PANICs.
 */
#include "stub-impl.h"

void get_regs_from_mc(struct uml_pt_regs *regs, mcontext_t *mc)
{
	stub_panic("mcontext.c: get_regs_from_mc — NT CONTEXT -> gp[] (M2)");
}

void mc_set_rip(void *_mc, void *target)
{
	stub_panic("mcontext.c: mc_set_rip — NT: CONTEXT->Rip");
}

void get_mc_from_regs(struct uml_pt_regs *regs, mcontext_t *mc,
		      int single_stepping)
{
	stub_panic("mcontext.c: get_mc_from_regs — NT: gp[] -> CONTEXT (TF flag = single-step)");
}

int get_stub_state(struct uml_pt_regs *regs, struct stub_data *data,
		   unsigned long *fp_size_out)
{
	stub_panic("mcontext.c: get_stub_state — stub_data page -> regs (M2 protocol)");
}

int set_stub_state(struct uml_pt_regs *regs, struct stub_data *data,
		   int single_stepping)
{
	stub_panic("mcontext.c: set_stub_state");
}
