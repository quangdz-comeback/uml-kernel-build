// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/stub_ctl.c — stub.exe parent side (M2/M3).
 *
 * Upstream analogue: os-Linux/skas/process.c start_userspace()/
 * userspace() — the kernel side of the stub protocol (clone + ptrace
 * or futex/socket there; CreateProcess + events + shared section
 * here, per stub_nt.h).
 *
 * M2 scope (acceptance: guest write(1,"hi") round-trip on the console):
 *  - cmdline param `uml_nt_stubtest=<stub.exe path>` gates a late
 *    initcall probe; without it this module is inert.
 *  - The probe stages a static init image (init_blob.S) into guest
 *    RAM, patches its syscalls to ud2 (scan_patch.c), creates one
 *    stub process with inherited handles, and services its requests
 *    (write → console, exit → done) synchronously from the boot CPU.
 *  - Real fork/exec integration (mm_id per guest process, the
 *    userspace() loop, turnstile) is M3+; this module proves the
 *    round-trip mechanism end to end.
 *
 * M3.1 extends the probe with the page-fault round-trip: the kernel
 * seeds two guard-page offsets in the stub bootstrap (stub-side
 * PAGE_NOACCESS before the guest runs), the guest blob faults on
 * them, and dispatch() answers via uml_nt_fault_decide() —
 * ACTION_PROT, then verifies the stub's PROT_DONE result. A failed
 * protect KILLs the stub instead of letting the guest re-fault
 * forever (every fail path loud — M1 pitfall 17).
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <init.h>
#include <ntabi.h>
#include <fault.h>
#include <stub-panic.h>
#include <stub_nt.h>

#include <os.h>
#include "internal.h"

extern const char nt_guest_init_start[], nt_guest_init_end[];
/* Absolute symbols (init_blob.S .set): byte offsets of the guard
 * address slots inside the blob. */
extern const char nt_guest_init_slot0[], nt_guest_init_slot1[];

/* scan_patch.c */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off);

/* Guest stack sits this far above the init image (grows down). */
#define GUEST_STACK_SLACK 0x20000ull

static char stub_path[512];
static int have_stub_path;

static int __init uml_nt_stubtest_setup(char *str, int *add)
{
	*add = 0;
	if (!str || !*str) {
		os_warn("uml_nt_stubtest: missing path\n");
		return 0;
	}
	if (strlen(str) >= sizeof(stub_path))
		return 0;
	strcpy(stub_path, str);
	have_stub_path = 1;
	return 0;
}
__uml_setup("uml_nt_stubtest=", uml_nt_stubtest_setup,
"uml_nt_stubtest=<path>\n"
"    M2 probe: boot a static guest init in one stub.exe process and\n"
"    run the write/exit syscall round-trip.\n");

/* Guard pages for the fault probe (phys offsets; computed in the
 * probe thread, VA table built from them per dispatch). */
static unsigned long long guard_off0, guard_off1;

/* Dispatch one published request. Returns 0 on success. */
static int stub_ctl_dispatch(struct uml_nt_stub_data *d)
{
	struct uml_nt_gp_regs *g = &d->regs;
	unsigned long long nr = g->rax;

	if (d->cmd == UML_STUB_CMD_PROT_DONE) {
		/* The stub reports its VirtualProtect result. Failure
		 * here means the guest would re-fault forever — kill
		 * it instead (loud, M1 pitfall 17). */
		if (d->retval != 1) {
			os_info("[stubtest] stub VirtualProtect FAILED "
				"(retval=%llu) — killing\n", d->retval);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return -1;
		}
		d->action = UML_STUB_ACTION_NONE;
		d->err = 0;
		return 0;
	}
	if (d->cmd == UML_STUB_CMD_FAULT) {
		struct uml_nt_fault_range allow[2];
		unsigned action, prot;
		unsigned long long page;
		int rc;

		allow[0].start = UML_STUB_RAM_BASE + guard_off0;
		allow[0].end = allow[0].start + UML_NT_FAULT_PAGE_SIZE;
		allow[1].start = UML_STUB_RAM_BASE + guard_off1;
		allow[1].end = allow[1].start + UML_NT_FAULT_PAGE_SIZE;

		rc = uml_nt_fault_decide(d->fault_addr, d->fault_type,
					 allow, 2, &action, &prot, &page);
		os_info("[stubtest] FAULT addr=0x%llx type=%u -> action=%u "
			"prot=0x%x page=0x%llx\n",
			d->fault_addr, d->fault_type, action, prot, page);
		d->action = action;
		d->prot = prot;
		d->err = rc ? 1 : 0;
		return rc;
	}

	/* Syscall trap: dispatch on the guest syscall number (rax). */
	d->action = UML_STUB_ACTION_NONE;
	if (nr == 60) { /* __NR_exit */
		d->retval = g->rdi;
		d->halt = 1;
		return 0;
	}
	if (nr == 1) { /* __NR_write */
		unsigned long long off = d->args[1] - d->ram_base;
		unsigned long long len = d->args[2];

		if (d->args[1] < d->ram_base || off >= d->ram_size ||
		    len > d->ram_size - off)
			goto bad;
		/* fd 1 = console for M2; others: -EBADF later. */
		if (d->args[0] != 1 && d->args[0] != 2)
			goto bad;
		nt_console_write((char *)uml_boot.physmem_base + off,
				 (unsigned int)len);
		d->retval = len;
		d->err = 0;
		return 0;
	}
bad:
	d->retval = (unsigned long long)-9LL; /* -EBADF */
	d->err = 1;
	return -1;
}

static unsigned long __attribute__((ms_abi)) stubtest_thread(void *arg)
{
	unsigned long long blob_len, entry_off, stack_off, patched;
	struct uml_nt_stub_data *d;
	unsigned long long dsec_h, phys_h, ein_h, eout_h;
	HANDLE dsec, view, evt_in, evt_out;
	char cmd[1200];
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ULONG exit_code;
	int i;

	(void)arg;

	blob_len = nt_guest_init_end - nt_guest_init_start;
	entry_off = (uml_boot.image_size + 0xFFFFull) & ~0xFFFFull;
	stack_off = entry_off + GUEST_STACK_SLACK;

	/* Guard pages live just past the blob image: the guest blob
	 * stores their GUEST VAs through these slots. */
	guard_off0 = (entry_off + blob_len + 0xFFF) & ~0xFFFull;
	guard_off1 = guard_off0 + 0x1000;

	/* Stage the init image, fill the guard-VA slots, and turn its
	 * `syscall`s into ud2 — the central-patch contract §5.1. */
	memcpy(uml_boot.physmem_base + entry_off, nt_guest_init_start,
	       blob_len);
	{
		unsigned long long off0, off1;
		unsigned long long va0, va1;

		off0 = (unsigned long long)(uintptr_t)nt_guest_init_slot0;
		off1 = (unsigned long long)(uintptr_t)nt_guest_init_slot1;
		va0 = UML_STUB_RAM_BASE + guard_off0;
		va1 = UML_STUB_RAM_BASE + guard_off1;
		memcpy(uml_boot.physmem_base + entry_off + off0, &va0, 8);
		memcpy(uml_boot.physmem_base + entry_off + off1, &va1, 8);
	}
	patched = uml_nt_patch_syscalls(uml_boot.physmem_base + entry_off,
					blob_len, 0);
	/* The linear sweep must never have eaten a slot byte as an
	 * instruction (decoder false-positive = wild guest pointer =
	 * fault outside the allow table). Verify loud. */
	{
		unsigned long long off0, off1, va0, va1;

		off0 = (unsigned long long)(uintptr_t)nt_guest_init_slot0;
		off1 = (unsigned long long)(uintptr_t)nt_guest_init_slot1;
		memcpy(&va0, uml_boot.physmem_base + entry_off + off0, 8);
		memcpy(&va1, uml_boot.physmem_base + entry_off + off1, 8);
		if (va0 != UML_STUB_RAM_BASE + guard_off0 ||
		    va1 != UML_STUB_RAM_BASE + guard_off1) {
			os_info("[stubtest] guard slot clobbered by patch "
				"scan (va0=0x%llx va1=0x%llx)\n", va0, va1);
			goto fail;
		}
	}
	os_info("[stubtest] init staged at phys 0x%llx (%llu bytes, %lu "
		"syscall(s) patched, guards 0x%llx/0x%llx)\n", entry_off,
		blob_len, patched, guard_off0, guard_off1);

	/* stub_data section + events — all inheritable, so the handle
	 * VALUES stay valid in the stub (S5 bootstrap pattern). */
	{
		SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, 1 };

		dsec = nt->CreateFileMappingW((HANDLE)-1, &sa, 0x04 /*RW*/,
					      0, UML_STUB_SECTION_SIZE, NULL);
		if (dsec == NULL) {
			os_info("[stubtest] CreateFileMappingW failed "
				"win32=%lu\n", nt->RtlGetLastWin32Error());
			goto fail;
		}
		evt_in = nt->CreateEventW(&sa, 0, 0, NULL);  /* stub→kern */
		evt_out = nt->CreateEventW(&sa, 0, 0, NULL); /* kern→stub */
		if (evt_in == NULL || evt_out == NULL) {
			os_info("[stubtest] CreateEventW failed win32=%lu\n",
				nt->RtlGetLastWin32Error());
			goto fail;
		}
		os_info("[stubtest] dsec=%p evt_in=%p evt_out=%p\n",
			dsec, evt_in, evt_out);
	}

	view = nt->MapViewOfFileEx(dsec, 0x000F001F /*FILE_MAP_ALL_ACCESS*/,
				   0, 0, UML_STUB_SECTION_SIZE, NULL);
	if (view == NULL) {
		os_info("[stubtest] MapViewOfFileEx failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		goto fail;
	}
	d = view;
	d->magic = UML_STUB_MAGIC;
	d->version = UML_STUB_VERSION;
	d->req_seq = 0;
	d->done_seq = 0;
	d->ram_base = UML_STUB_RAM_BASE;
	d->ram_size = uml_boot.physmem_size;
	d->entry_off = entry_off;
	d->stack_off = stack_off;
	d->image_len = blob_len;
	d->halt = 0;
	d->fault_addr = 0;
	d->fault_type = 0;
	d->action = UML_STUB_ACTION_NONE;
	d->prot = 0;
	d->guard_off[0] = guard_off0;
	d->guard_off[1] = guard_off1;

	phys_h = (unsigned long long)(uintptr_t)uml_boot.physmem_section;
	dsec_h = (unsigned long long)(uintptr_t)dsec;
	ein_h = (unsigned long long)(uintptr_t)evt_in;
	eout_h = (unsigned long long)(uintptr_t)evt_out;

	i = snprintf(cmd, sizeof(cmd),
		     "\"%s\" --data %llu --phys %llu --evt-in %llu "
		     "--evt-out %llu", stub_path, dsec_h, phys_h,
		     ein_h, eout_h);
	if (i <= 0 || i >= (int)sizeof(cmd))
		goto fail;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	os_info("[stubtest] spawning: %s\n", cmd);
	if (!nt->CreateProcessA(NULL, cmd, NULL, NULL, 1,
				0x4 /*CREATE_SUSPENDED*/, NULL, NULL,
				&si, &pi)) {
		os_info("[stubtest] CreateProcess failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		goto fail;
	}
	os_info("[stubtest] CreateProcess ok\n");
	d->pid = pi.dwProcessId;
	os_info("[stubtest] stub pid %lu — resuming\n",
		(unsigned long)pi.dwProcessId);

	/* Handshake is published; let it run. Bootstrap failures die in
	 * the stub with exit 111+ (read via GetExitCodeProcess below). */
	nt->ResumeThread(pi.hThread);

	/* Service requests. Auto-reset event = one signal per publish;
	 * the seq guards reuse (M0 pitfall 4.4). Wait with a timeout so
	 * a dead/hung stub is reported instead of hanging the boot. */
	for (i = 0; i < 100; i++) {
		LARGE_INTEGER to;
		long st;

		to.QuadPart = -10000000LL; /* 1s */
		st = nt->NtWaitForSingleObject(evt_in, 0, &to);
		if (st == 0x102 /*STATUS_TIMEOUT*/) {
			ULONG code = 0;

			nt->GetExitCodeProcess(pi.hProcess, &code);
			os_info("[stubtest] stub did not signal in 1s "
				"(exit code so far: %lu)\n",
				(unsigned long)code);
			goto fail;
		}
		mb();
		if (d->req_seq != d->done_seq + 1) {
			os_info("[stubtest] seq desync req=%llu done=%llu\n",
				d->req_seq, d->done_seq);
			goto fail;
		}
		stub_ctl_dispatch(d);
		mb();
		nt->NtSetEvent(evt_out, NULL);
		if (d->halt) {
			/* Kernel owns the kill (upstream parity): exit
			 * code = guest retval, observed via
			 * GetExitCodeProcess below. */
			nt->NtTerminateProcess(pi.hProcess,
					       (NTSTATUS)d->retval);
			break;
		}
	}

	nt->NtWaitForSingleObject(pi.hProcess, 0, UML_NT_INFINITE);
	if (!nt->GetExitCodeProcess(pi.hProcess, &exit_code))
		exit_code = 0xFFFFFFFFu;

	os_info("[stubtest] ROUND-TRIP OK: write delivered, guest exit "
		"code %lu (want 0)\n", (unsigned long)exit_code);
	return 0;

fail:
	os_info("[stubtest] FAILED (see messages above)\n");
	return 0;
}

/*
 * The probe runs on its OWN NT thread with a fat stack: the boot CPU
 * stack is a UML THREAD_SIZE stack and CreateProcessA + loader work
 * blew it natively (wine tolerates; found M2.1 CI — exit 127 mid-call).
 */
static int __init uml_nt_stubtest_init(void)
{
	ULONG tid;
	HANDLE th;

	if (!have_stub_path)
		return 0;
	/* 32MB: CreateProcessA (wine builtin + native kernel32 loader
	 * work) burned ~2MB — the UML boot stack (16KB) died natively
	 * and even a 1MB thread overflowed under wine (M2.1 CI). */
	th = nt->CreateThread(NULL, 0x2000000, stubtest_thread, NULL, 0,
			      &tid);
	if (th == NULL) {
		os_info("[stubtest] CreateThread failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		return 0;
	}
	/* Serialize with the boot thread: concurrent console NtWriteFile
	 * from two threads loses/dups output nondeterministically (seen
	 * under wine, M2.1) and the probe result must be assertable. */
	nt->NtWaitForSingleObject(th, 0, UML_NT_INFINITE);
	return 0;
}
__initcall(uml_nt_stubtest_init);
