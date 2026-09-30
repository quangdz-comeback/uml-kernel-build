// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/time.c — timekeeping + interval timer.
 * Upstream: linux v6.18.37 arch/um/os-Linux/time.c
 *
 * Upstream arms a POSIX timer delivering SIGALRM into the kernel timer
 * machinery. NT has no signals (D7): os_timer_create makes a high-
 * resolution waitable timer and a dedicated thread whose only job is
 * WaitForSingleObject → deliver_alarm() (kernel/um/kernel/time.c), the
 * same entry point the SIGALRM handler runs.
 *
 * QPC for os_nsecs (monotonic), GetSystemTimePreciseAsFileTime for the
 * wall clock. Both are multi-unit-safe (D6: query APIs, one thread only
 * touches each).
 */
#include <linux/init.h>
#include <ntabi.h>
#include <os.h>
#include "internal.h"

/* 100ns units between 1601-01-01 and 1970-01-01. */
#define UML_NT_EPOCH_DELTA_100NS 116444736000000000ULL

static HANDLE g_timer;           /* waitable timer (not owned by table) */
static unsigned long long g_qpc_freq;
static int g_timer_hr;           /* created with HIGH_RESOLUTION flag */

static LARGE_INTEGER qpc_to_li(long long nsecs)
{
	LARGE_INTEGER li;

	/* negative = relative, 100ns units (D6). Clamp to signed range. */
	if (nsecs > 4000000000000000LL)
		nsecs = 4000000000000000LL;
	li.QuadPart = -(nsecs / 100LL); /* ns -> 100ns units */
	return li;
}

static unsigned long __attribute__((ms_abi)) nt_timer_thread(void *arg)
{
	uml_nt_thread_role = "timer";
	for (;;) {
		nt->NtWaitForSingleObject(g_timer, 0, NULL);
		deliver_alarm();
	}
	return 0;
}

int os_timer_create(void)
{
	LARGE_INTEGER f;
	HANDLE thread;
	ULONG tid;

	f.QuadPart = 0;
	nt->QueryPerformanceFrequency(&f);
	g_qpc_freq = (unsigned long long)f.QuadPart;
	if (g_qpc_freq == 0)
		return -1;

	/* HIGH_RESOLUTION first; some VMs (observed on the GitHub
	 * windows-2022 runner, M1.9) create the HR timer fine but fail
	 * SetWaitableTimer on it — recreate plain in that case. */
	g_timer_hr = 1;
	g_timer = nt->CreateWaitableTimerExW(NULL, NULL, 0x00000002,
					     0x1F0003);
	if (g_timer == NULL) {
		g_timer_hr = 0;
		g_timer = nt->CreateWaitableTimerExW(NULL, NULL, 0,
						     0x1F0003);
	}
	if (g_timer == NULL)
		return -1;

	thread = nt->CreateThread(NULL, 0, nt_timer_thread, NULL, 0, &tid);
	if (thread == NULL)
		return -1;
	os_info("timer: thread tid=%lu\n", tid);
	/* Thread handle leaked deliberately: it lives for the UML run. */
	return 0;
}

int os_timer_set_interval(unsigned long long nsecs)
{
	LARGE_INTEGER due;
	LONG period_ms;

	/* PERIODIC: due = first interval (relative), then repeats every
	 * period_ms forever. A one-shot (period=0) fires exactly once —
	 * calibrate_delay then waits for a second jiffies tick forever
	 * (found at M1.8 under wine). */
	due = qpc_to_li((long long)nsecs);
	period_ms = (LONG)(nsecs / 1000000ULL);
	if (period_ms < 1)
		period_ms = 1;
	if (nt->SetWaitableTimer(g_timer, &due, period_ms, NULL, NULL, 0))
		return 0;

	/* HR-timer quirk on some VMs: recreate without the HR flag. */
	os_info("[probe] SetWaitableTimer hr failed win32=%lu\n",
		nt->RtlGetLastWin32Error()); /* TEMP M1.9 */
	if (!g_timer_hr)
		return -1;
	nt->CloseHandle(g_timer);
	g_timer = nt->CreateWaitableTimerExW(NULL, NULL, 0, 0x1F0003);
	if (g_timer == NULL)
		return -1;
	if (!nt->SetWaitableTimer(g_timer, &due, period_ms, NULL, NULL, 0)) {
		os_info("[probe] SetWaitableTimer plain failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		return -1;
	}
	return 0;
}

int os_timer_one_shot(unsigned long long nsecs)
{
	return os_timer_set_interval(nsecs);
}

void os_timer_disable(void)
{
	if (g_timer == NULL)
		return;
	nt->CancelWaitableTimer(g_timer);
}

long long os_nsecs(void)
{
	LARGE_INTEGER c;

	c.QuadPart = 0;
	nt->QueryPerformanceCounter(&c);
	{
		unsigned long long ticks = (unsigned long long)c.QuadPart;
		unsigned long long secs, rem;

		/* 64-bit-safe ns conversion (no 128-bit helper: freestand-
		 * ing links no libgcc — D1): secs-first then remainder. */
		secs = ticks / g_qpc_freq;
		rem = ticks % g_qpc_freq;
		return (long long)(secs * 1000000000ULL +
				   rem * 1000000000ULL / g_qpc_freq);
	}
}

static long long wallclock_nsecs(void)
{
	FILETIME ft;

	ft.LowPart = 0;
	ft.HighPart = 0;
	nt->GetSystemTimePreciseAsFileTime(&ft);
	{
		unsigned long long t100 =
			((unsigned long long)ft.HighPart << 32) | ft.LowPart;
		if (t100 < UML_NT_EPOCH_DELTA_100NS)
			return 0;
		return (long long)((t100 - UML_NT_EPOCH_DELTA_100NS) * 100ULL);
	}
}

void os_idle_sleep(void)
{
	LARGE_INTEGER li;

	/* Upstream sleeps until the next timer tick; the NT timer thread
	 * delivers ticks independently, so a short relative sleep keeps
	 * the idle loop from burning CPU. ≥1ms, capped. */
	li = qpc_to_li(1000000LL); /* 1ms in 100ns units, relative */
	nt->NtDelayExecution(0, &li);
}

long long os_persistent_clock_emulation(void)
{
	return wallclock_nsecs();
}

void deliver_time_travel_irqs(void)
{
	/* timetravel not supported on NT (M6+ decision). */
}

void um_timetravel_start(void)
{
	/* timetravel not supported on NT (M6+ decision). */
}
