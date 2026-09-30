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
#include <irq_user.h>
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

/*
 * Kernel-side handler table (upstream os-Linux/signal.c defines it
 * with the same shape). SIGIO → sigio_handler (kernel/irq.c — the
 * registry flush, os-Windows/irq.c); SIGCHLD → sigchld_handler.
 * relay_signal is for fault-shaped signals only and PANICS on a
 * kernel-context regs — pointing SIGIO there (the pre-M5 wiring)
 * would have panicked the first net IRQ (found reading trap.c:
 * "Kernel mode signal %d").
 */
void (*sig_info[65])(int, struct siginfo *, struct uml_pt_regs *,
		     void *mc) = {
	[SIGIO]    = sigio_handler,
	[SIGCHLD]  = sigchld_handler,
};

int signals_enabled;
static unsigned int signals_pending;
static unsigned int signals_active;

static void sig_handler_common(int sig, struct siginfo *si, void *mc)
{
	struct uml_pt_regs r;

	memset(&r, 0, sizeof(r));
	r.is_user = 0;

	if ((sig != SIGIO) && (sig != SIGWINCH) && (sig != SIGCHLD))
		unblock_signals_trace();

	(*sig_info[sig])(sig, si, &r, mc);
}

static void timer_real_alarm_handler(void *mc)
{
	struct uml_pt_regs regs;

	memset(&regs, 0, sizeof(regs));
	timer_handler(SIGALRM, NULL, &regs);
}

/* D19: the timer thread owns NO kernel context. Upstream delivers
 * SIGALRM into the vCPU thread, where the OS signal mask serializes
 * delivery against every IRQ-disabled region (block_signals IS
 * sigprocmask there). The NT flag machine has no such force: a tick
 * running on the timer thread races the vCPU thread inside the SAME
 * per-cpu SLUB/IRQ state (two host threads, one "cpu"), which is the
 * S4c2 busybox heap corruption — the first long alloc/free window
 * (the 131KB execve read through the sync ubd path) gave the tick a
 * wide window and kmem_cache_free died on a trashed pointer
 * (c0000005, reporter v2 run 36643648747).
 *
 * So the alarm is PENDING-ONLY here; the vCPU thread flushes it at
 * exactly the points upstream flushes signals (unblock_signals —
 * every spin_unlock_irqrestore pair and the userspace() round-trip).
 * Ticks coalesce under load, which upstream TT_MODE_BASIC already
 * tolerates; real guest preemption stays M4. The vCPU-side flush
 * machine below is otherwise upstream-verbatim. */
void deliver_alarm(void)
{
	__sync_fetch_and_or(&signals_pending, SIGALRM_MASK);
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

/* The vCPU-side SIGIO flush for waiters with signals ENABLED: the
 * userspace() loop blocks on {stub evt_in, net wake} and unblock_
 * signals() only flushes when signals were disabled — a frame arriving
 * mid-wait needs its IRQ run HERE (upstream: the SIGIO signal simply
 * interrupts the blocking poll and hard_handler runs it). Atomic
 * clear-then-run: a reader re-arming the bit mid-flush re-runs later,
 * never strands. */
void uml_nt_sigio_flush(void)
{
	unsigned int p = __sync_fetch_and_and(&signals_pending,
					      ~SIGIO_MASK);

	if (p & SIGIO_MASK)
		sig_handler_common(SIGIO, NULL, NULL);
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
