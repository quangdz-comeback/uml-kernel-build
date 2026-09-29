/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub-panic.h — the one symbol real os-Windows modules may share with
 * the M1.3 scaffolding: the loud-fail placeholder for entry points that
 * keep their skeleton until later milestones. Type mirrors stay in
 * stub-impl.h; modules with real implementations must NOT include that
 * file (its typedefs collide with the kernel headers).
 */
#ifndef __OS_WINDOWS_STUB_PANIC_H
#define __OS_WINDOWS_STUB_PANIC_H

void stub_panic(const char *why) __attribute__((noreturn));

#endif
