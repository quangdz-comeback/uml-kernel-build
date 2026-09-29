// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/user_syms.c — EXPORT_SYMBOL of string/compiler builtins.
 * Upstream: linux v6.18.37 arch/um/os-Linux/user_syms.c
 *
 * Kept as a documented empty object: with D1 (freestanding, -nostdlib)
 * the compiler builtins must come from the kernel's own lib/ once the
 * real build links (M1.4/M1.6); module exports only matter if guest
 * modules are ever enabled (not planned for uml-nt).
 */
#include <stub-impl.h>

/* intentionally empty — see file comment */
