// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/signal.c — host "signal" layer = VEH + NT sync primitives.
 * Upstream: linux v6.18.37 arch/um/os-Linux/signal.c
 *
 * Why this module carries the port's core risk: upstream masks/handles
 * SIGALRM/SIGIO/SIGSEGV per thread; the NT backend maps these onto VEH
 * dispatch (S1: 1.7us p50) and interlocked flag words. The
 * enabled/pending bookkeeping API below keeps kernel-side callers
 * unchanged. Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

/*
 * Kernel-side irqflags/longjmp read this (extern in asm/irqflags.h).
 * Upstream keeps it in __thread TLS; D1 forbids ELF TLS — plain global
 * for M1 boot, per-thread redesign lands with the VEH signal model (M2).
 */
int signals_enabled;

void timer_set_signal_handler(void)
{
	stub_panic("signal.c: timer_set_signal_handler — NT: waitable HR timer thread (S2)");
}

void set_sigstack(void *sig_stack, int size)
{
	stub_panic("signal.c: set_sigstack — NT: VEH uses the thread's NT stack; likely a no-op");
}

void set_handler(int sig)
{
	stub_panic("signal.c: set_handler");
}

void send_sigio_to_self(void)
{
	stub_panic("signal.c: send_sigio_to_self");
}

int change_sig(int signal, int on)
{
	stub_panic("signal.c: change_sig");
}

void block_signals(void)
{
	stub_panic("signal.c: block_signals");
}

void unblock_signals(void)
{
	stub_panic("signal.c: unblock_signals");
}

int um_set_signals(int enable)
{
	stub_panic("signal.c: um_set_signals");
}

int um_set_signals_trace(int enable)
{
	stub_panic("signal.c: um_set_signals_trace");
}

void deliver_alarm(void)
{
	stub_panic("signal.c: deliver_alarm — timer thread hands to kernel scheduler");
}

void register_pm_wake_signal(void)
{
	stub_panic("signal.c: register_pm_wake_signal");
}

void block_signals_hard(void)
{
	stub_panic("signal.c: block_signals_hard");
}

void unblock_signals_hard(void)
{
	stub_panic("signal.c: unblock_signals_hard");
}

void mark_sigio_pending(void)
{
	stub_panic("signal.c: mark_sigio_pending");
}
