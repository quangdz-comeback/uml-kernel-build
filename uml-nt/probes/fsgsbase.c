/* SPDX-License-Identifier: GPL-2.0 */
/*
 * probes/fsgsbase.c — can guest musl TLS ever work on native Windows?
 *
 * Busybox (musl-static) calls arch_prctl(ARCH_SET_FS, tp) at startup
 * and dereferences TLS through fs-relative addressing right after.
 * The NT guest has no FS base mechanism yet, so S4c needs to know
 * what the hardware + kernel actually allow before D18 is written:
 *
 *   1. CPU feature: CPUID leaf 7 EBX bit 0 (FSGSBASE) + the OS-level
 *      detector IsProcessorFeaturePresent(PF_RDWRFSGSBASE_AVAILABLE)
 *      (Windows 8.1+ enables the instructions when the CPU has them —
 *      merryhime's FS/GS-on-x64 notes).
 *   2. Can USER code write FSBASE at all (wrgsbase is documented as
 *      allowed for user-level threading; wrfsbase was "unknown")? A
 *      wrfsbase/rdfsbase #UD kills the process — so the bare test
 *      runs in a CHILD process (exit code = the answer; this mingw
 *      gcc has no usable __try/__except to VEH-guard one instruction
 *      with, and mixing it with the ud2 VEH would need instruction
 *      length decoding in the handler).
 *   3. Does a user-written FSBASE survive a VEH round-trip (the ud2
 *      → kernel dispatch → resume path EVERY guest syscall takes)?
 *   4. Does it survive scheduling (thread switched out and back)?
 *
 * Evidence probe, not a gate: exit 0 with markers printed either way —
 * the design decision reads the log, and the CI runner is the arbiter
 * (wine's answer would be worthless here, pitfall 4.1.8).
 *
 * Safety while the magic base is installed: x64 user CRT reaches the
 * TEB through gs:[...], nothing of ours walks fs:; every test restores
 * the original base as its last step. An fs-relative stranger in that
 * window faults loud — that outcome is an answer too.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#ifndef PF_RDWRFSGSBASE_AVAILABLE
#define PF_RDWRFSGSBASE_AVAILABLE 21
#endif

/* busybox's real TLS pointer shape (strace: 0x4fb738) — a LOW VA,
 * i.e. NOT a TEB: exactly what the kernel may refuse or clobber. */
#define FSB_MAGIC 0x4fb738ull

#define FSB_EXIT_OK     0        /* child: rdfsbase+wrfsbase worked */
#define FSB_EXIT_MISMATCH 2      /* child: readback disagreed */

static inline unsigned long long rd_fsbase(void)
{
	unsigned long long v;

	__asm__ volatile ("rdfsbase %0" : "=r" (v));
	return v;
}

static inline void wr_fsbase(unsigned long long v)
{
	__asm__ volatile ("wrfsbase %0" :: "r" (v) : "memory");
}

/* The S1 pattern: a ud2 lands here on every round-trip; continuing
 * without RIP+2 would re-execute ud2 forever. */
static LONG CALLBACK ud2_veh(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
		ep->ContextRecord->Rip += 2;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

static int cpuid_fsgsbase(void)
{
	unsigned int a, b, c, d;

	__asm__ volatile ("cpuid"
			  : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
			  : "a" (7), "c" (0));
	return (b >> 0) & 1;
}

/* Child mode (--bare): the only place rdfsbase/wrfsbase may #UD.
 * Exit code carries the verdict; prints are diagnostics. */
static int bare_child(void)
{
	unsigned long long base;

	printf("FSGSBASE-CHILD: PF=%d\n",
	       (int)IsProcessorFeaturePresent(PF_RDWRFSGSBASE_AVAILABLE));
	base = rd_fsbase();
	printf("FSGSBASE-CHILD: rdfsbase ok (base 0x%llx)\n", base);
	wr_fsbase(FSB_MAGIC);
	if (rd_fsbase() != FSB_MAGIC) {
		printf("FSGSBASE-CHILD: readback mismatch\n");
		return FSB_EXIT_MISMATCH;
	}
	printf("FSGSBASE-CHILD: wrfsbase+readback ok\n");
	return FSB_EXIT_OK;
}

/* Test 3: write → ud2 (the VEH round-trip) → read back → restore, one
 * asm block. *seen = what rdfsbase says AFTER the dispatcher resumed
 * us — the honest VEH-persistence answer. */
static int veh_preserved(unsigned long long old_fs, unsigned long long *seen)
{
	unsigned long long out = 0;

	__asm__ volatile (
		"wrfsbase %[m]\n\t"
		"ud2\n\t"
		"rdfsbase %[out]\n\t"
		"wrfsbase %[old]\n\t"
		: [out] "=r" (out)
		: [m] "r" (FSB_MAGIC), [old] "r" (old_fs)
		: "memory");
	*seen = out;
	return 1;
}

/* Test 4: write → yield the thread away and back (100 switches + a
 * sleep) → read → (caller restores). The kernel restores segments
 * from its own bookkeeping at switch boundaries — a user TLS base
 * the OS does not track may not survive. */
static int sched_preserved(void)
{
	unsigned long long seen;
	int i;

	wr_fsbase(FSB_MAGIC);
	for (i = 0; i < 100; i++)
		SwitchToThread();
	Sleep(20);
	seen = rd_fsbase();
	return seen == FSB_MAGIC;
}

int main(int argc, char **argv)
{
	unsigned long long fs_orig = 0, veh_seen = 0;
	int cpuid, pfpf, bare, veh_same, sched_ok;

	if (argc == 2 && !strcmp(argv[1], "--bare"))
		return bare_child();

	cpuid = cpuid_fsgsbase();
	pfpf = (int)IsProcessorFeaturePresent(PF_RDWRFSGSBASE_AVAILABLE);
	printf("FSGSBASE-CPUID: %s (leaf7.ebx bit0; PF_RDWRFSGSBASE_AVAILABLE=%d)\n",
	       cpuid ? "yes" : "no", pfpf);

	if (!cpuid) {
		printf("FSGSBASE-WRITE: n/a (CPU lacks FSGSBASE)\n");
		printf("FSGSBASE-VEH-PRESERVED: n/a\n");
		printf("FSGSBASE-SCHED-PRESERVED: n/a\n");
		printf("FSGSBASE-PROBE-DONE\n");
		return 0;
	}

	/* Bare write test in a child: a #UD there is the answer, not a
	 * probe crash. */
	{
		STARTUPINFOA si;
		PROCESS_INFORMATION pi;
		char cmd[MAX_PATH + 32];
		DWORD code = (DWORD)-1;

		GetModuleFileNameA(NULL, cmd, MAX_PATH);
		strcat(cmd, " --bare");
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si); /* 104 on x64 — pitfall 10 */
		memset(&pi, 0, sizeof(pi));
		if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL,
				    NULL, &si, &pi)) {
			printf("FSGSBASE-WRITE: spawn failed %lu\n",
			       GetLastError());
			printf("FSGSBASE-VEH-PRESERVED: n/a\n");
			printf("FSGSBASE-SCHED-PRESERVED: n/a\n");
			printf("FSGSBASE-PROBE-DONE\n");
			return 0;
		}
		WaitForSingleObject(pi.hProcess, 30000);
		GetExitCodeProcess(pi.hProcess, &code);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		bare = (code == FSB_EXIT_OK);
		printf("FSGSBASE-WRITE: %s (child exit 0x%lX)\n",
		       bare ? "ok" :
		       code == 0xC000001Du ? "#UD (OS did not enable)" :
		       code == FSB_EXIT_MISMATCH ? "readback mismatch" :
		       "other crash",
		       (unsigned long)code);
		if (!bare) {
			printf("FSGSBASE-VEH-PRESERVED: n/a\n");
			printf("FSGSBASE-SCHED-PRESERVED: n/a\n");
			printf("FSGSBASE-PROBE-DONE\n");
			return 0;
		}
	}

	AddVectoredExceptionHandler(1, ud2_veh);
	fs_orig = rd_fsbase();

	veh_same = veh_preserved(fs_orig, &veh_seen) &&
		   veh_seen == FSB_MAGIC;
	printf("FSGSBASE-VEH-PRESERVED: %s (readback 0x%llx)\n",
	       veh_same ? "yes" : "no", (unsigned long long)veh_seen);

	sched_ok = sched_preserved();
	/* Restore the CRT base no matter what the tests did. */
	wr_fsbase(fs_orig);
	printf("FSGSBASE-SCHED-PRESERVED: %s\n", sched_ok ? "yes" : "no");
	printf("FSGSBASE-PROBE-DONE\n");
	return 0;
}
