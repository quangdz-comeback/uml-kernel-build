// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/signal.c — signal-flag emulation.
 * Upstream: linux v6.18.37 arch/um/os-Linux/signal.c
 *
 * NT has no POSIX signals (D7). The kernel-side callers only observe
 * the enable/pending state machine, so that machine is ported verbatim:
 * same masks, same block/unblock semantics (flush pending on unblock),
 * same deliver_alarm() entry. Delivery sources differ: the timer is a
 * thread callback (time.c), IO events arrive at M3 (IOCP).
 */
#include <linux/string.h>
#include <kern_util.h>
#include <ntabi.h>
#include <os.h>
#include "internal.h"

/* No <signal.h> on NT freestanding (D1): pin the Linux x86_64 numbers
 * — they only feed the flag machine + dmesg readability. */
#define SIGCHLD  17
#define SIGALRM  14
#define SIGWINCH 28
#define SIGIO    29

#define SIGIO_BIT   0
#define SIGIO_MASK  (1 << SIGIO_BIT)
#define SIGALRM_BIT 1
#define SIGALRM_MASK (1 << SIGALRM_BIT)
#define SIGCHLD_BIT 2
#define SIGCHLD_MASK (1 << SIGCHLD_BIT)

int signals_enabled;
static unsigned int signals_pending;
static unsigned int signals_active;

/* Kernel-side handlers reached on delivery (upstream sig_info[]): */
extern void relay_signal(int sig, struct siginfo *si,
			 struct uml_pt_regs *regs, void *mc);

static void sig_handler_common(int sig, struct siginfo *si, void *mc)
{
	struct uml_pt_regs r;

	memset(&r, 0, sizeof(r));
	r.is_user = 0;

	if ((sig != SIGIO) && (sig != SIGWINCH) && (sig != SIGCHLD))
		unblock_signals_trace();

	relay_signal(sig, si, &r, mc);
}

static void timer_real_alarm_handler(void *mc)
{
	struct uml_pt_regs regs;

	memset(&regs, 0, sizeof(regs));
	timer_handler(SIGALRM, NULL, &regs);
}

static void timer_alarm_handler(int sig, struct siginfo *si, void *mc)
{
	int enabled = signals_enabled;

	if (!signals_enabled) {
		signals_pending |= SIGALRM_MASK;
		return;
	}

	block_signals_trace();
	signals_active |= SIGALRM_MASK;

	timer_real_alarm_handler(mc);

	signals_active &= ~SIGALRM_MASK;
	um_set_signals_trace(enabled);
}

void deliver_alarm(void)
{
	timer_alarm_handler(SIGALRM, NULL, NULL);
}

void block_signals(void)
{
	signals_enabled = 0;
}

void block_signals_hard(void)
{
	signals_enabled = 0;
}

void unblock_signals(void)
{
	unsigned int save_pending;

	if (signals_enabled)
		return;

	save_pending = signals_pending;
	signals_pending = 0;
	if (save_pending == 0)
		goto out;

	signals_enabled = 0;

	if (save_pending & SIGIO_MASK)
		sig_handler_common(SIGIO, NULL, NULL);

	if ((save_pending & SIGALRM_MASK) &&
	    !(signals_active & SIGALRM_MASK))
		timer_real_alarm_handler(NULL);

out:
	signals_enabled = 1;
}

void unblock_signals_hard(void)
{
	unblock_signals();
}

int um_set_signals(int enable)
{
	int ret = signals_enabled;

	if (enable)
		unblock_signals();
	else
		block_signals();
	return ret;
}

int um_set_signals_trace(int enable)
{
	return um_set_signals(enable);
}

int change_sig(int signal, int on)
{
	/* per-signal granularity doesn't exist on the flag machine */
	return 1;
}

void set_handler(int sig)
{
	/* no sigaction on NT — timer thread + IOCP replace it (D7) */
}

void timer_set_signal_handler(void)
{
	set_handler(SIGALRM);
}

void set_sigstack(void *sig_stack, int size) { }
void remove_sigstack(void) { }

void mark_sigio_pending(void)
{
	signals_pending |= SIGIO_MASK;
}

void send_sigio_to_self(void)
{
	mark_sigio_pending();
	unblock_signals();
}

void register_pm_wake_signal(void)
{
	/* PM wakeups: M6. */
}
