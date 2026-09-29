// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/time.c — timekeeping: QPC + waitable high-resolution timer.
 * Upstream: linux v6.18.37 arch/um/os-Linux/time.c
 * Status: M1.3 skeleton — every entry point PANICs.
 */
#include <stub-impl.h>

void os_idle_sleep(void)
{
	stub_panic("time.c: os_idle_sleep — NT: WaitForSingleObject on timer");
}

int os_timer_create(void)
{
	stub_panic("time.c: os_timer_create — NT: CreateWaitableTimerEx HIGH_RESOLUTION (S2)");
}

int os_timer_set_interval(unsigned long long nsecs)
{
	stub_panic("time.c: os_timer_set_interval — 6.18.37 API: NO cpu param (snapshot has per-CPU, post-6.18)");
}

int os_timer_one_shot(unsigned long long nsecs)
{
	stub_panic("time.c: os_timer_one_shot");
}

void os_timer_disable(void)
{
	stub_panic("time.c: os_timer_disable");
}

long long os_persistent_clock_emulation(void)
{
	stub_panic("time.c: os_persistent_clock_emulation — NT: GetSystemTimePreciseAsFileTime");
}

long long os_nsecs(void)
{
	stub_panic("time.c: os_nsecs — NT: QPC scaled to ns");
}

void deliver_time_travel_irqs(void)
{
	stub_panic("time.c: deliver_time_travel_irqs — time-travel mode unsupported on NT for now");
}
