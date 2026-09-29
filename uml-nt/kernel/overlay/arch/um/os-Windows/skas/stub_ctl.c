// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/stub_ctl.c — stub.exe parent side (M2).
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
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <init.h>
#include <ntabi.h>
#include <stub-panic.h>
#include <stub_nt.h>

#include <os.h>
#include "internal.h"

extern const char nt_guest_init_start[], nt_guest_init_end[];

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

/* Dispatch one published request. Returns 0 on success. */
static int stub_ctl_dispatch(struct uml_nt_stub_data *d)
{
	struct uml_nt_gp_regs *g = &d->regs;
	unsigned long long nr = g->rax;

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

static int __init uml_nt_stubtest_init(void)
{
	unsigned long long blob_len, entry_off, stack_off, patched;
	struct uml_nt_stub_data *d;
	unsigned long long dsec_h, phys_h, ein_h, eout_h;
	HANDLE dsec, view, evt_in, evt_out;
	char cmd[1200];
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ULONG dummy, exit_code;
	int i;

	(void)dummy;

	if (!have_stub_path)
		return 0;

	blob_len = nt_guest_init_end - nt_guest_init_start;
	entry_off = (uml_boot.image_size + 0xFFFFull) & ~0xFFFFull;
	stack_off = entry_off + GUEST_STACK_SLACK;

	/* Stage the init image into guest RAM (identity view) and turn
	 * its `syscall`s into ud2 — the central-patch contract §5.1. */
	memcpy(uml_boot.physmem_base + entry_off, nt_guest_init_start,
	       blob_len);
	patched = uml_nt_patch_syscalls(uml_boot.physmem_base + entry_off,
					blob_len, 0);
	os_info("[stubtest] init staged at phys 0x%llx (%llu bytes, %lu "
		"syscall(s) patched)\n", entry_off, blob_len, patched);

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
		if (d->halt)
			break;
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
__initcall(uml_nt_stubtest_init);
