// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/irq.c — IRQ wait loop: IOCP/overlapped replaces epoll+sigio.
 * Upstream: linux v6.18.37 arch/um/os-Linux/irq.c
 *
 * Names keep the epoll spelling for os.h parity even though the NT
 * backend has no epoll; the wait loop itself becomes IOCP
 * (ARCHITECTURE §3). Status: M1.3 skeleton — PANICs.
 */
#include <stub-impl.h>
/*
 * Upstream: drivers/chan_kern.c (excluded at M1 — see arch/um/Kbuild
 * patch). With no channels registered there is nothing to free, so the
 * no-op below is exact M1 semantics; replaced at M3.
 */
void free_irqs(void)
{
}

int os_waiting_for_events_epoll(void)
{
	stub_panic("irq.c: os_waiting_for_events_epoll — NT: GetQueuedCompletionStatus loop");
}

void *os_epoll_get_data_pointer(int index)
{
	stub_panic("irq.c: os_epoll_get_data_pointer");
}

int os_epoll_triggered(int index, int events)
{
	stub_panic("irq.c: os_epoll_triggered");
}

int os_event_mask(enum um_irq_type irq_type)
{
	stub_panic("irq.c: os_event_mask");
}

int os_setup_epoll(void)
{
	stub_panic("irq.c: os_setup_epoll — NT: CreateIoCompletionPort");
}

int os_add_epoll_fd(int events, int fd, void *data)
{
	stub_panic("irq.c: os_add_epoll_fd");
}

int os_mod_epoll_fd(int events, int fd, void *data)
{
	stub_panic("irq.c: os_mod_epoll_fd");
}

int os_del_epoll_fd(int fd)
{
	stub_panic("irq.c: os_del_epoll_fd");
}

void os_set_ioignore(void)
{
	stub_panic("irq.c: os_set_ioignore");
}

void os_close_epoll_fd(void)
{
	stub_panic("irq.c: os_close_epoll_fd");
}
