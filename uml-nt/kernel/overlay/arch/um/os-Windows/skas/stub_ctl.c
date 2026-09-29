// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/stub_ctl.c — stub.exe parent side (M3).
 *
 * Upstream analogue: os-Linux/skas/process.c start_userspace()/
 * userspace() — the kernel side of the stub protocol (clone + ptrace
 * or futex/socket there; CreateProcess + events + shared section
 * here, per stub_nt.h).
 *
 * M2 proved the single-stub round-trip (write/exit). M3.1/M3.2 added
 * the page-fault round-trip and the per-mm VMA manager. M3.3 turns
 * the probe into a two-process system:
 *
 *  - `struct uml_nt_stub_conn` — one guest process: its stub_data
 *    mapping, event pair, process handle, mm and plan-runner state
 *    (the embryonic per-connection userspace() loop state).
 *  - Guest fork (__NR_fork): kernel clones the parent mm (M3.2 COW
 *    machinery — the child shares every run, writable VMAs marked
 *    COW), spawns a second stub.exe (S5 pattern, suspended), hands it
 *    the parent's register snapshot with rax = 0, and resumes it; the
 *    child streams its own INIT plan (per-VMA views, COW-shared runs
 *    mapped read-only) before jumping. Parent gets the child pid in
 *    rax, upstream fork semantics.
 *  - The service loop waits on ALL live stubs' evt_in handles
 *    (WaitForMultipleObjects — the D10 turnstile per stub: seq +
 *    event pair in each stub's own section) and serves whichever
 *    published.
 *
 * Real fork/exec syscall integration (wait4, the generic userspace()
 * dispatcher) is M3.7; this module proves the mechanism end to end.
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

/* Guest stack: two runs above the text run (grows down); guards live
 * one run above the stack. All run-multiples (vma.h contract). */
#define GUEST_STACK_RUNS 2
#define GUARD_RUN_DELTA  0x10000ull

/* One guest process (stub side of the protocol). */
struct uml_nt_stub_conn {
	struct uml_nt_stub_data *d;
	HANDLE evt_in, evt_out;
	HANDLE proc, thread;
	struct uml_nt_mm *mm;
	ULONG pid;
	int alive;
	ULONG exit_code;
	/* plan runner: ops stream one round-trip each */
	struct uml_nt_fault_plan plan;
	int plan_next, plan_left;
};

static struct uml_nt_stub_conn conn_parent, conn_child;
static struct uml_nt_mm mm_parent, mm_child;
static struct uml_nt_phys probe_phys;

static char stub_path[512];
static int have_stub_path;

static int spawn_stub(struct uml_nt_stub_conn *c, unsigned long long entry_va,
		      unsigned long long stack_va,
		      const struct uml_nt_gp_regs *init);

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
"    M3 probe: boot a static guest init (fault round-trips + fork)\n"
"    across stub.exe processes.\n");

/* Push one plan op into the conn's slot. */
static void issue_plan_op(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op)
{
	struct uml_nt_stub_data *d = c->d;

	switch (op->op) {
	case UML_NT_FOP_PROTECT:
		d->action = UML_STUB_ACTION_PROT;
		d->prot = op->prot;
		d->map_va = op->va;  /* PROTECT target page/range */
		d->map_len = op->len;
		break;
	case UML_NT_FOP_MAP:
		d->action = UML_STUB_ACTION_MAP;
		d->map_prot = op->prot;
		d->map_va = op->va;
		d->map_len = op->len;
		d->map_off = op->off;
		break;
	default: /* UML_NT_FOP_UNMAP */
		d->action = UML_STUB_ACTION_UNMAP;
		d->map_va = op->va;
		d->map_len = op->len;
		break;
	}
	c->plan_next++;
}

/* Serve one published request on this conn. Returns 0 on success. */
static int serve_conn(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	struct uml_nt_gp_regs *g = &d->regs;
	unsigned long long nr = g->rax;

	if (d->cmd == UML_STUB_CMD_PROT_DONE) {
		/* The stub reports its op result. Failure here means
		 * the guest would re-fault forever — kill it instead
		 * (loud, M1 pitfall 17). */
		if (d->retval != 1) {
			os_info("[stubtest] stub op FAILED (pid %lu, "
				"retval=%llu) — killing\n",
				(unsigned long)c->pid, d->retval);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return -1;
		}
		if (c->plan_left > 1) {
			c->plan_left--;
			issue_plan_op(c, &c->plan.ops[c->plan_next]);
			return 0;
		}
		c->plan_left = 0;
		d->action = UML_STUB_ACTION_NONE;
		d->err = 0;
		return 0;
	}
	if (d->cmd == UML_STUB_CMD_INIT) {
		/* Stream the conn's initial per-VMA map plan; the probe
		 * appends NOACCESS protects for the parent's guard
		 * pages (the fault-probe seed). */
		if (uml_nt_mm_init_plan(c->mm, &probe_phys, &c->plan) < 0) {
			os_info("[stubtest] INIT plan overflow (pid %lu)\n",
				(unsigned long)c->pid);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return -1;
		}
		if (c == &conn_parent && c->plan.n_ops + 2 <=
					      UML_NT_FAULT_MAX_OPS) {
			unsigned long long g0 = d->entry_va + GUARD_RUN_DELTA;
			/* guard run = text+stack runs above entry */
			struct uml_nt_fault_op *op;
			int base = c->plan.n_ops;

			op = &c->plan.ops[base];
			op->op = UML_NT_FOP_PROTECT;
			op->prot = UML_NT_PAGE_NOACCESS;
			op->va = g0;
			op->len = UML_NT_FAULT_PAGE_SIZE;
			op->off = 0;
			op = &c->plan.ops[base + 1];
			op->op = UML_NT_FOP_PROTECT;
			op->prot = UML_NT_PAGE_NOACCESS;
			op->va = g0 + 0x1000;
			op->len = UML_NT_FAULT_PAGE_SIZE;
			op->off = 0;
			c->plan.n_ops += 2;
		}
		c->plan_next = 0;
		c->plan_left = c->plan.n_ops;
		os_info("[stubtest] INIT pid %lu: %d map op(s)\n",
			(unsigned long)c->pid, c->plan.n_ops);
		issue_plan_op(c, &c->plan.ops[0]);
		return 0;
	}
	if (d->cmd == UML_STUB_CMD_FAULT) {
		int rc;

		rc = uml_nt_mm_fault(c->mm, &probe_phys, d->fault_addr,
				     d->fault_type, &c->plan);
		if (rc < 0 || c->plan.kill) {
			os_info("[stubtest] FATAL fault pid %lu "
				"addr=0x%llx type=%u — killing\n",
				(unsigned long)c->pid, d->fault_addr,
				d->fault_type);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return -1;
		}
		os_info("[stubtest] FAULT pid %lu addr=0x%llx type=%u -> "
			"%d op(s)\n", (unsigned long)c->pid, d->fault_addr,
			d->fault_type, c->plan.n_ops);
		/* COW copy directive: the kernel owns the physmem
		 * content — memcpy the run through its own flat view
		 * before the stub maps the new one. */
		if (c->plan.copy_src_off != 0 ||
		    c->plan.copy_dst_off != 0) {
			memcpy(uml_boot.physmem_base +
				       c->plan.copy_dst_off,
			       uml_boot.physmem_base +
				       c->plan.copy_src_off,
			       UML_NT_PHYS_RUN_SIZE);
		}
		c->plan_next = 0;
		c->plan_left = c->plan.n_ops;
		issue_plan_op(c, &c->plan.ops[0]);
		return 0;
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
		/* fd 1 = console for now; others: -EBADF later. */
		if (d->args[0] != 1 && d->args[0] != 2)
			goto bad;
		nt_console_write((char *)uml_boot.physmem_base + off,
				 (unsigned int)len);
		d->retval = len;
		d->err = 0;
		return 0;
	}
	if (nr == 57) { /* __NR_fork */
		struct uml_nt_stub_conn *k = &conn_child;

		if (k->alive) {
			os_info("[stubtest] fork: child already exists\n");
			goto bad;
		}
		/* Clone the parent mm: writable VMAs become COW except
		 * the stack VMA (holds rsp — the NT VEH dispatch cannot
		 * run on a COW-faulted stack page), which eager-copies.
		 * Copy the eager runs' contents parent→child through
		 * the kernel's flat view (the clone is pure logic). */
		if (uml_nt_mm_clone(&mm_child, c->mm, &probe_phys,
				    g->rsp) < 0) {
			os_info("[stubtest] fork: mm clone failed\n");
			d->retval = (unsigned long long)-12LL; /* -ENOMEM */
			d->err = 1;
			return -1;
		}
		{
			int vi;

			for (vi = 0; vi < mm_child.nvma; vi++) {
				const struct uml_nt_vma *pv =
					&c->mm->vma[vi];
				const struct uml_nt_vma *cv =
					&mm_child.vma[vi];

				if (cv->run_off == pv->run_off)
					continue; /* shared run */
				memcpy(uml_boot.physmem_base +
					       cv->run_off,
				       uml_boot.physmem_base +
					       pv->run_off,
				       cv->end - cv->start);
			}
		}
		k->mm = &mm_child;
		/* The child resumes at the same instruction with the
		 * parent's registers and rax = 0 (fork semantics); the
		 * parent gets the child pid. */
		if (spawn_stub(k, g->rip + 2, g->rsp, g) < 0) {
			uml_nt_mm_drop(&mm_child, &probe_phys);
			d->retval = (unsigned long long)-12LL;
			d->err = 1;
			return -1;
		}
		k->d->init_regs = *g;
		k->d->init_regs.rax = 0;
		nt->ResumeThread(k->thread);
		d->retval = k->pid;
		d->err = 0;
		os_info("[stubtest] fork: child pid %lu\n",
			(unsigned long)k->pid);
		return 0;
	}
bad:
	d->retval = (unsigned long long)-9LL; /* -EBADF */
	d->err = 1;
	return -1;
}

/* Spawn one stub.exe for `mm` (S5 pattern: inheritable handles, value
 * cmdline, CREATE_SUSPENDED). init_regs are applied by the stub right
 * before the jump (fork children need the parent snapshot). */
static int spawn_stub(struct uml_nt_stub_conn *c, unsigned long long entry_va,
		      unsigned long long stack_va,
		      const struct uml_nt_gp_regs *init)
{
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, 1 };
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	struct uml_nt_stub_data *d;
	HANDLE dsec, view;
	char cmd[1200];
	unsigned long long dsec_h, phys_h, ein_h, eout_h;
	int i;

	dsec = nt->CreateFileMappingW((HANDLE)-1, &sa, 0x04 /*RW*/, 0,
				      UML_STUB_SECTION_SIZE, NULL);
	if (dsec == NULL)
		goto fail;
	c->evt_in = nt->CreateEventW(&sa, 0, 0, NULL);  /* stub→kern */
	c->evt_out = nt->CreateEventW(&sa, 0, 0, NULL); /* kern→stub */
	if (c->evt_in == NULL || c->evt_out == NULL)
		goto fail;

	view = nt->MapViewOfFileEx(dsec, 0x000F001F /*FILE_MAP_ALL_ACCESS*/,
				   0, 0, UML_STUB_SECTION_SIZE, NULL);
	if (view == NULL)
		goto fail;
	d = view;
	memset(d, 0, sizeof(*d));
	d->magic = UML_STUB_MAGIC;
	d->version = UML_STUB_VERSION;
	d->ram_base = UML_STUB_RAM_BASE;
	d->ram_size = uml_boot.physmem_size;
	d->entry_va = entry_va;
	d->stack_va = stack_va;
	d->init_regs = *init;
	d->halt = 0;

	phys_h = (unsigned long long)(uintptr_t)uml_boot.physmem_section;
	dsec_h = (unsigned long long)(uintptr_t)dsec;
	ein_h = (unsigned long long)(uintptr_t)c->evt_in;
	eout_h = (unsigned long long)(uintptr_t)c->evt_out;

	i = snprintf(cmd, sizeof(cmd),
		     "\"%s\" --data %llu --phys %llu --evt-in %llu "
		     "--evt-out %llu", stub_path, dsec_h, phys_h,
		     ein_h, eout_h);
	if (i <= 0 || i >= (int)sizeof(cmd))
		goto fail;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si); /* 104 on x64 — pitfall 10 */
	memset(&pi, 0, sizeof(pi));
	if (!nt->CreateProcessA(NULL, cmd, NULL, NULL, 1,
				0x4 /*CREATE_SUSPENDED*/, NULL, NULL,
				&si, &pi))
		goto fail;

	c->d = d;
	c->proc = pi.hProcess;
	c->thread = pi.hThread;
	c->pid = pi.dwProcessId;
	c->alive = 1;
	c->exit_code = 0;
	c->plan_next = 0;
	c->plan_left = 0;
	return 0;

fail:
	os_info("[stubtest] spawn failed win32=%lu\n",
		nt->RtlGetLastWin32Error());
	return -1;
}

/* Serve one signaled conn: seq-check, dispatch, release. Returns 1
 * when the conn halted (kernel terminated it), -1 on protocol error. */
static int pump_conn(struct uml_nt_stub_conn *c)
{
	mb();
	if (c->d->req_seq != c->d->done_seq + 1) {
		os_info("[stubtest] seq desync pid %lu req=%llu done=%llu\n",
			(unsigned long)c->pid, c->d->req_seq,
			c->d->done_seq);
		return -1;
	}
	serve_conn(c);
	mb();
	nt->NtSetEvent(c->evt_out, NULL);
	if (c->d->halt || c->d->action == UML_STUB_ACTION_KILL) {
		/* Kernel owns the kill (upstream parity, M2.2): halt =
		 * guest exit; KILL = the stub parked on a fatal fault/
		 * failed op — terminate it now, never wait it out. */
		nt->NtTerminateProcess(c->proc,
				       (NTSTATUS)c->d->retval);
		c->exit_code = c->d->retval;
		c->alive = 0;
		os_info("[stubtest] pid %lu halt (exit %lu)\n",
			(unsigned long)c->pid,
			(unsigned long)c->exit_code);
		return 1;
	}
	return 0;
}

static unsigned long __attribute__((ms_abi)) stubtest_thread(void *arg)
{
	unsigned long long blob_len, entry_off, text_va, stack_va;
	unsigned long long guard_va0, guard_va1, patched;
	struct uml_nt_gp_regs zero_regs;
	HANDLE waits[2];
	int i, nwaits;

	(void)arg;

	blob_len = nt_guest_init_end - nt_guest_init_start;
	entry_off = (uml_boot.image_size + 0xFFFFull) & ~0xFFFFull;
	text_va = UML_STUB_RAM_BASE + entry_off;
	/* Layout in runs above the image: text (1), stack (2), guard
	 * (1). The guard run IS the run at text+3 — the guard VMA and
	 * the guard VAs must name the SAME run. */
	stack_va = text_va + (1 + GUEST_STACK_RUNS) * 0x10000ull;
	guard_va0 = stack_va;
	guard_va1 = guard_va0 + 0x1000;

	/* Guest physical pool over the section (M3.2 allocator). */
	if (uml_nt_phys_init(&probe_phys, uml_boot.physmem_size) < 0) {
		os_info("[stubtest] phys init failed (mem too big for "
			"the run table)\n");
		return 0;
	}

	/* Stage the init image, fill the guard-VA slots, patch the
	 * `syscall`s to ud2 — the central-patch contract §5.1. */
	memcpy(uml_boot.physmem_base + entry_off, nt_guest_init_start,
	       blob_len);
	{
		unsigned long long off0, off1;
		unsigned long long va0, va1;

		off0 = (unsigned long long)(uintptr_t)nt_guest_init_slot0;
		off1 = (unsigned long long)(uintptr_t)nt_guest_init_slot1;
		va0 = guard_va0;
		va1 = guard_va1;
		memcpy(uml_boot.physmem_base + entry_off + off0, &va0, 8);
		memcpy(uml_boot.physmem_base + entry_off + off1, &va1, 8);
	}
	patched = uml_nt_patch_syscalls(uml_boot.physmem_base + entry_off,
					blob_len, 0);
	/* The linear sweep must never have eaten a slot byte as an
	 * instruction (decoder false-positive = wild guest pointer).
	 * Verify loud. */
	{
		unsigned long long off0, off1, va0, va1;

		off0 = (unsigned long long)(uintptr_t)nt_guest_init_slot0;
		off1 = (unsigned long long)(uintptr_t)nt_guest_init_slot1;
		memcpy(&va0, uml_boot.physmem_base + entry_off + off0, 8);
		memcpy(&va1, uml_boot.physmem_base + entry_off + off1, 8);
		if (va0 != guard_va0 || va1 != guard_va1) {
			os_info("[stubtest] guard slot clobbered by patch "
				"scan (va0=0x%llx va1=0x%llx)\n", va0, va1);
			return 0;
		}
	}
	os_info("[stubtest] init staged at phys 0x%llx (%llu bytes, %lu "
		"syscall(s) patched, guards 0x%llx/0x%llx)\n", entry_off,
		blob_len, patched, guard_va0, guard_va1);

	/* Parent mm (M3 model): per-VMA views — text (1 run RWX), stack
	 * (GUEST_STACK_RUNS runs RW), guard run (RW; the INIT plan
	 * NOACCESS-protects the guard pages). The kernel image occupies
	 * the section head: burn those runs first (the allocator must
	 * never hand them out), then claim the exact probe runs. */
	{
		unsigned long long off;

		for (off = 0; off < entry_off; off += 0x10000ull) {
			if (uml_nt_phys_alloc_at(&probe_phys,
						 (long long)off) < 0) {
				os_info("[stubtest] image run burn failed "
					"at 0x%llx\n", off);
				return 0;
			}
		}
	}
	uml_nt_mm_init(&mm_parent);
	if (uml_nt_phys_alloc_at(&probe_phys, (long long)entry_off) < 0 ||
	    uml_nt_vma_add(&mm_parent, text_va, text_va + 0x10000ull,
			   entry_off, UML_NT_PAGE_EXECUTE_READWRITE,
			   0) < 0) {
		os_info("[stubtest] text vma failed\n");
		return 0;
	}
	for (i = 0; i < GUEST_STACK_RUNS; i++) {
		if (uml_nt_phys_alloc_at(&probe_phys,
				(long long)(entry_off +
				 (unsigned long long)(i + 1) * 0x10000ull)) < 0) {
			os_info("[stubtest] stack run alloc failed\n");
			return 0;
		}
	}
	if (uml_nt_vma_add(&mm_parent, text_va + 0x10000ull, stack_va,
			   entry_off + 0x10000ull, UML_NT_PAGE_READWRITE,
			   0) < 0) {
		os_info("[stubtest] stack vma failed\n");
		return 0;
	}
	if (uml_nt_phys_alloc_at(&probe_phys,
			(long long)(entry_off +
			 (GUEST_STACK_RUNS + 1) * 0x10000ull)) < 0) {
		os_info("[stubtest] guard run alloc failed\n");
		return 0;
	}
	if (uml_nt_vma_add(&mm_parent, stack_va, stack_va + 0x10000ull,
			   entry_off + (GUEST_STACK_RUNS + 1) * 0x10000ull,
			   UML_NT_PAGE_READWRITE, 0) < 0) {
		os_info("[stubtest] guard vma failed\n");
		return 0;
	}
	conn_parent.mm = &mm_parent;

	memset(&zero_regs, 0, sizeof(zero_regs));
	if (spawn_stub(&conn_parent, text_va, stack_va, &zero_regs) < 0)
		return 0;
	os_info("[stubtest] parent stub pid %lu — resuming\n",
		(unsigned long)conn_parent.pid);
	nt->ResumeThread(conn_parent.thread);

	/* Service loop: wait on ALL live stubs' evt_in (the per-stub
	 * D10 turnstile), serve the publisher. 1s timeout = a dead or
	 * hung stub is reported, not hung (M1.9 lesson). A halt keeps
	 * the loop running while other conns live. */
	for (;;) {
		LARGE_INTEGER to;
		DWORD w;
		ULONG code;
		int any, rc;

		nwaits = 0;
		waits[nwaits++] = conn_parent.evt_in;
		if (conn_child.alive)
			waits[nwaits++] = conn_child.evt_in;

		w = nt->WaitForMultipleObjects((ULONG)nwaits, waits, 0,
					       1000);
		if (w == 0xFFFFFFFFu /*WAIT_FAILED*/) {
			os_info("[stubtest] wait failed win32=%lu\n",
				nt->RtlGetLastWin32Error());
			break;
		}
		if (w == 258u /*WAIT_TIMEOUT*/) {
			any = 0;
			if (conn_parent.alive) {
				code = 0;
				nt->GetExitCodeProcess(conn_parent.proc,
						       &code);
				if (code != 259u /*STILL_ACTIVE*/) {
					conn_parent.exit_code = code;
					conn_parent.alive = 0;
					os_info("[stubtest] parent died "
						"silently: %lu\n",
						(unsigned long)code);
				} else {
					any = 1;
				}
			}
			if (conn_child.alive) {
				code = 0;
				nt->GetExitCodeProcess(conn_child.proc,
						       &code);
				if (code != 259u) {
					conn_child.exit_code = code;
					conn_child.alive = 0;
					os_info("[stubtest] child died "
						"silently: %lu\n",
						(unsigned long)code);
				} else {
					any = 1;
				}
			}
			if (!any)
				break;
			continue;
		}
		/* WAIT_OBJECT_0 == 0: w = signaled index */
		if (w == 0)
			rc = pump_conn(&conn_parent);
		else if (conn_child.alive)
			rc = pump_conn(&conn_child);
		else
			rc = 0;
		if (rc < 0)
			break;
	}

	/* The child (if forked) runs to its own exit: wait, then
	 * collect both codes. The blob orders child exit before parent
	 * exit, so no child request is left unanswered here. */
	if (conn_child.pid && conn_child.alive) {
		nt->NtWaitForSingleObject(conn_child.proc, 0,
					  UML_NT_INFINITE);
		nt->GetExitCodeProcess(conn_child.proc,
				       &conn_child.exit_code);
		conn_child.alive = 0;
	}
	nt->NtWaitForSingleObject(conn_parent.proc, 0, UML_NT_INFINITE);
	nt->GetExitCodeProcess(conn_parent.proc, &conn_parent.exit_code);

	os_info("[stubtest] FORK OK: parent exit %lu, child exit %lu "
		"(want 0 / 7)\n", (unsigned long)conn_parent.exit_code,
		(unsigned long)conn_child.exit_code);
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
