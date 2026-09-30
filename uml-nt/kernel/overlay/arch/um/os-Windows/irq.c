// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/irq.c — IRQ availability + the wake multiplex.
 * Upstream: linux v6.18.37 arch/um/os-Linux/irq.c (epoll over host fds)
 *
 * NT has neither fds nor epoll. The kernel-side irq.c machinery is kept
 * upstream-verbatim (activate_fd → os_add_epoll_fd(events, fd, entry);
 * sigio_handler → os_waiting_for_events_epoll → os_epoll_triggered);
 * this layer substitutes a small REGISTRY for the epoll set and a
 * readiness flag per entry:
 *
 *   - os_add_epoll_fd records {events, fd, data} (data = the kernel's
 *     irq_entry, opaque here),
 *   - the device's aux reader thread (D19 edge-capture — the ONLY
 *     writer of readiness) calls uml_nt_net_rx_ready(fd) when a frame
 *     has been staged: sets the entry's ready flag, marks the SIGIO
 *     flag pending (the same machine the timer flag feeds) and sets
 *     the WAKE event,
 *   - sigio_handler (vCPU, from the flag flush at unblock_signals or
 *     the userspace() wake) drains the registry via the upstream
 *     contract functions below and runs the handlers.
 *
 * No kernel code ever runs on the aux thread: the registry handoff is
 * data + events only (D19 — the S4c2 lesson).
 */
#include <linux/string.h>
#include <linux/errno.h>
#include <ntabi.h>
#include <irq_user.h>
#include <os.h>
#include "internal.h"

#define UML_NT_IRQ_MAX 16

static struct {
	int fd;
	int events;   /* os_event_mask bits (IRQ_READ/IRQ_WRITE) */
	void *data;   /* kernel irq_entry back-reference */
	int ready;    /* set by the aux reader, consumed by the flush */
} irq_fds[UML_NT_IRQ_MAX];

/* The fired snapshot: os_waiting_for_events_epoll copies ready entries
 * here and clears their flags; sigio_handler walks the snapshot. */
static void *fired[UML_NT_IRQ_MAX];
static int n_fired;

/* Auto-reset event the reader threads SetEvent to break the vCPU's
 * userspace() wait (it waits on {stub evt_in, this}). */
static HANDLE wake_evt;
static int wake_evt_ready;

HANDLE uml_nt_net_wake_event(void)
{
	int old;

	if (wake_evt_ready)
		return wake_evt;
	old = __sync_val_compare_and_swap(&wake_evt_ready, 0, 1);
	if (old == 0)
		wake_evt = nt->CreateEventW(NULL, 0 /*auto-reset*/, 0,
					    NULL);
	/* A racing loser re-reads the winner's handle; by the time
	 * anyone SetEvents it, creation has returned (open/init and
	 * the vCPU wait are both vCPU-context). */
	return wake_evt;
}

/* D19 handoff point: the aux reader thread says "a frame is staged on
 * fd". Registry flag + SIGIO pending flag + wake. NEVER called with
 * kernel work on the aux thread. */
void uml_nt_net_rx_ready(int fd)
{
	HANDLE w;
	int i;

	for (i = 0; i < UML_NT_IRQ_MAX; i++) {
		if (irq_fds[i].fd == fd && irq_fds[i].data != NULL)
			break;
	}
	if (i == UML_NT_IRQ_MAX)
		return; /* unregistered/closing — drop the edge */

	__sync_fetch_and_or(&irq_fds[i].ready, 1);
	mark_sigio_pending();

	w = uml_nt_net_wake_event();
	if (w != NULL)
		nt->NtSetEvent(w, NULL);
}

int os_setup_epoll(void)
{
	return 0;
}

int os_add_epoll_fd(int events, int fd, void *data)
{
	int i;

	/* Upstream epoll_ctl semantics: a second registration for a
	 * known fd (vector registers IRQ_WRITE on the rx fd too)
	 * MODIFIES the entry — update_irq_entry always passes the
	 * FULL combined mask, so replace (never accumulate, never
	 * duplicate; the kernel relies on one entry per fd). */
	for (i = 0; i < UML_NT_IRQ_MAX; i++) {
		if (irq_fds[i].data != NULL && irq_fds[i].fd == fd) {
			irq_fds[i].events = events;
			return 0;
		}
	}
	for (i = 0; i < UML_NT_IRQ_MAX; i++) {
		if (irq_fds[i].data == NULL) {
			irq_fds[i].fd = fd;
			irq_fds[i].events = events;
			irq_fds[i].data = data;
			irq_fds[i].ready = 0;
			return 0;
		}
	}
	os_warn("irq: registry full (fd %d)\n", fd);
	return -ENOMEM;
}

int os_mod_epoll_fd(int events, int fd, void *data)
{
	int i;

	for (i = 0; i < UML_NT_IRQ_MAX; i++) {
		if (irq_fds[i].data != NULL && irq_fds[i].fd == fd) {
			irq_fds[i].events = events;
			irq_fds[i].data = data;
			return 0;
		}
	}
	return -1;
}

int os_del_epoll_fd(int fd)
{
	int i;

	for (i = 0; i < UML_NT_IRQ_MAX; i++) {
		if (irq_fds[i].data != NULL && irq_fds[i].fd == fd) {
			irq_fds[i].data = NULL;
			irq_fds[i].fd = -1;
			return 0;
		}
	}
	return 0;
}

void os_set_ioignore(void) { }

void os_close_epoll_fd(void) { }

int os_waiting_for_events_epoll(void)
{
	int i, n;

	n = 0;
	for (i = 0; i < UML_NT_IRQ_MAX; i++) {
		int was;

		if (irq_fds[i].data == NULL || !irq_fds[i].ready)
			continue;
		was = __sync_fetch_and_and(&irq_fds[i].ready, 0);
		if (!was)
			continue; /* consumed concurrently */
		fired[n++] = irq_fds[i].data;
	}
	return n;
}

void *os_epoll_get_data_pointer(int index)
{
	return fired[index];
}

int os_epoll_triggered(int index, int events)
{
	/* Upstream masks the fired EPOLL bits against reg->events; our
	 * reader-edge model has no direction — the registration's own
	 * mask decides which handler runs. */
	(void)index;
	return events;
}

int os_event_mask(enum um_irq_type irq_type)
{
	/* Values are registry-internal (upstream: EPOLLIN/EPOLLOUT). */
	return irq_type == IRQ_READ ? 1 : 2;
}

void free_irqs(void)
{
	/* Upstream: deferred free of os_del'd fds after the flush pass.
	 * The registry freed the slots in os_del_epoll_fd directly. */
}
