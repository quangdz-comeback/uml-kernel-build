// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/irq.c — IRQ availability.
 * Upstream: linux v6.18.37 arch/um/os-Linux/irq.c
 *
 * Upstream multiplexes IRQ readiness via epoll over host fds. The NT
 * handle-based IOCP event loop is M3+ (drivers return). M1 boots with
 * no external IRQ sources: the timer runs on its own waitable-timer
 * thread (time.c) and never touches this layer. Surface mirrors os.h.
 */
#include <ntabi.h>
#include <os.h>
#include "internal.h"

int os_setup_epoll(void)
{
	/* M1: no epfd — kernel glue registers nothing before panic. */
	return 0;
}

int os_add_epoll_fd(int events, int fd, void *data)
{
	return -1; /* unreachable until drivers return (M3) */
}

int os_mod_epoll_fd(int events, int fd, void *data)
{
	return -1;
}

int os_del_epoll_fd(int fd)
{
	return 0;
}

void os_set_ioignore(void) { }

void os_close_epoll_fd(void) { }

int os_waiting_for_events_epoll(void)
{
	/* M1: kernel panics before the first wait would ever run. */
	return 0;
}

void *os_epoll_get_data_pointer(int index)
{
	return NULL;
}

int os_epoll_triggered(int index, int events)
{
	return 0;
}

int os_event_mask(enum um_irq_type irq_type)
{
	return 0;
}

void free_irqs(void)
{
	/* M1: nothing registered. M3 walks the IOCP handle table. */
}
