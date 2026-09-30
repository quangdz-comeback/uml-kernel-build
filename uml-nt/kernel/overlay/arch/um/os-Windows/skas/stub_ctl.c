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
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <init.h>
#include <ntabi.h>
#include <fault.h>
#include <elf.h>
#include <stub-panic.h>
#include <stub_nt.h>

#include <os.h>
#include <syscall.h>
#include <mm_id.h>
#include <uaccess_walk.h>
#include "internal.h"

extern const char nt_guest_init_start[], nt_guest_init_end[];
/* Absolute symbols (init_blob.S .set): byte offsets of the guard
 * address slots inside the blob. */
extern const char nt_guest_init_slot0[], nt_guest_init_slot1[];

/* scan_patch.c */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off);

/* M3.4: the kernel-side map of the launcher's exec section (the ELF
 * the loader parses). Fixed VA BELOW the stub_data block
 * (0x10000000..): same reasoning as the stub bootstrap — an unplaced
 * map lets the NT allocator land inside the image/guest span (M3.3
 * lesson, kernel side too). One view, mapped at probe time, unmapped
 * after the load (the bytes live in physmem runs from then on). */
#define UML_NT_EXEC_VIEW_VA 0x0C000000ULL

/* The probe's guard-page guest VAs: the guard run is its OWN page-
 * allocator run (D11 — dynamic offsets, no run-adjacency assumptions),
 * so the INIT plan's NOACCESS ops can't derive them from entry_va. */
static unsigned long long probe_guard_va0, probe_guard_va1;

/* wait4 bookkeeping (uml_nt_sys_wait4): one child conn, reaped once. */
static int child_reaped;

static struct uml_nt_stub_conn conn_parent, conn_child;
static struct uml_nt_mm mm_parent, mm_child;
static struct uml_nt_phys probe_phys;

static char stub_path[512];
static int have_stub_path;

static int __init uml_nt_stub_param_setup(char *str, int *add)
{
	*add = 0;
	if (!str || !*str) {
		os_warn("uml_nt_stub: missing path\n");
		return 0;
	}
	if (strlen(str) >= sizeof(stub_path))
		return 0;
	strcpy(stub_path, str);
	have_stub_path = 1;
	return 0;
}
__uml_setup("uml_nt_stub=", uml_nt_stub_param_setup,
"uml_nt_stub=<path>\n"
"    Path of stub.exe for the real mm-context lifecycle (S1:\n"
"    init_new_context spawns one stub per guest address space).\n");

/* The configured stub exe path, or NULL. mmctx.c asks before
 * spawning; the probe param below implies the same path. */
const char *uml_nt_stub_path(void)
{
	return have_stub_path ? stub_path : NULL;
}

static int __init uml_nt_stubtest_setup(char *str, int *add)
{
	/* The probe implies the stub path (its spawns are the same
	 * machinery); it additionally arms the probe thread. The
	 * shared setup consumes the param (add = 0: never leaks into
	 * the guest-visible cmdline). */
	uml_nt_stub_param_setup(str, add);
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

/* Publish one plan op into the stub slot (d->action operands) and
 * advance the runner. Exported for the pump-side signal delivery
 * (process.c): a sigframe write that COW-fixed-up a shared run
 * queues ops into the conn's plan mid-signal_check. */
void uml_nt_plan_issue_op(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op)
{
	issue_plan_op(c, op);
}

/* Serve one published request on this conn. Returns 0 on success. */
static int serve_conn(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

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
		if (c->plan_has_retval) {
			/* A syscall carried these ops: re-publish its
			 * return value (the stub's op results traveled
			 * through d->retval and clobbered it). */
			d->retval = c->plan_retval;
			c->plan_has_retval = 0;
		}
		d->action = UML_STUB_ACTION_NONE;
		d->err = 0;
		return 0;
	}
	if (d->cmd == UML_STUB_CMD_INIT) {
		/* Stream the conn's initial per-VMA map plan; the probe
		 * appends NOACCESS protects for the parent's guard
		 * pages (the fault-probe seed). */
		if (uml_nt_mm_init_plan(c->mm, c->ph, &c->plan) < 0) {
			os_info("[stubtest] INIT plan overflow (pid %lu)\n",
				(unsigned long)c->pid);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return -1;
		}
		if (c == &conn_parent && c->plan.n_ops + 2 <=
					      UML_NT_FAULT_MAX_OPS) {
			/* The probe's own guard pages (the fault-probe
			 * seed) — the guard run's guest VAs, recorded
			 * at staging (dynamic run offsets, D11). */
			struct uml_nt_fault_op *op;
			int base = c->plan.n_ops;

			op = &c->plan.ops[base];
			op->op = UML_NT_FOP_PROTECT;
			op->prot = UML_NT_PAGE_NOACCESS;
			op->va = probe_guard_va0;
			op->len = UML_NT_FAULT_PAGE_SIZE;
			op->off = 0;
			op = &c->plan.ops[base + 1];
			op->op = UML_NT_FOP_PROTECT;
			op->prot = UML_NT_PAGE_NOACCESS;
			op->va = probe_guard_va1;
			op->len = UML_NT_FAULT_PAGE_SIZE;
			op->off = 0;
			c->plan.n_ops += 2;
		}
		c->plan_next = 0;
		c->plan_left = c->plan.n_ops;
		os_info("[stubtest] INIT pid %lu: %d map op(s)\n",
			(unsigned long)c->pid, c->plan.n_ops);
		if (c->plan_left > 0) {
			issue_plan_op(c, &c->plan.ops[0]);
		} else {
			/* Empty mm (a fresh S1/S2 mm context holds no
			 * VMA until binfmt fills it): answer NONE so
			 * the stub proceeds — reading ops[0] here fed
			 * the slot garbage (found on the S2 userspace
			 * path, empty-INIT round). */
			d->action = UML_STUB_ACTION_NONE;
			d->err = 0;
		}
		return 0;
	}
	if (d->cmd == UML_STUB_CMD_FAULT) {
		int rc;

		rc = uml_nt_mm_fault(c->mm, c->ph, d->fault_addr,
				     d->fault_type, &c->plan);
		if (rc < 0 || c->plan.kill) {
			int vi;

			/* S4d: a task-backed conn turns the fatal fault
			 * into a REAL guest SIGSEGV (upstream parity —
			 * segv handler force_sig_faults, the generic
			 * machinery delivers: handler, or default
			 * death). The fault plan is dropped and the
			 * faulting instruction does NOT replay: the
			 * signal_check in the pump either runs the
			 * handler (verbatim resume into it) or the
			 * default action kills the task right there
			 * (do_exit → exit_mm → mmctx_destroy terminates
			 * this stub — no leak, no evt_out). POC conns
			 * have no task: keep the loud KILL. */
			if (c->task_backed && c->owner_regs != NULL) {
				int code = (c->plan.kill_why == 'w') ?
					SEGV_MAPERR : SEGV_ACCERR;

				os_info("[stubtest] SIGSEGV -> guest pid %lu "
					"addr=0x%llx type=%u rip=0x%llx "
					"why=%c\n",
					(unsigned long)c->pid, d->fault_addr,
					d->fault_type, d->regs.rip,
					c->plan.kill_why ?
					c->plan.kill_why : '?');
				force_sig_fault(SIGSEGV, code,
					(void __user *)(unsigned long)
						d->fault_addr);
				d->action = UML_STUB_ACTION_NONE;
				d->err = 0;
				return 0;
			}
			os_info("[stubtest] FATAL fault pid %lu "
				"addr=0x%llx type=%u why=%c — killing\n",
				(unsigned long)c->pid, d->fault_addr,
				d->fault_type,
				c->plan.kill_why ? c->plan.kill_why : '?');
			for (vi = 0; vi < c->mm->nvma; vi++)
				os_info("[stubtest]   vma[%d] "
					"0x%llx-0x%llx prot=0x%x "
					"flags=0x%x off=0x%llx\n",
					vi, c->mm->vma[vi].start,
					c->mm->vma[vi].end,
					c->mm->vma[vi].prot,
					c->mm->vma[vi].flags,
					c->mm->vma[vi].run_off);
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

	/* Syscall trap: the D16 dispatch (skas/syscall.c) owns the
	 * surface; this function keeps the plan/protocol streaming. */
	d->action = UML_STUB_ACTION_NONE;
	d->err = 0;
	d->halt = 0;
	c->plan.kill = 0;
	c->plan.n_ops = 0;
	c->plan.copy_src_off = 0;
	c->plan.copy_dst_off = 0;
	c->plan_next = 0;
	c->plan_left = 0;
	c->plan_has_retval = 0;
	uml_nt_syscall_handle(c, d);
	if (uml_nt_syscall_consume_exec()) {
		/* execve succeeded INSIDE the handler: exec_mmap
		 * dropped the old mm — c and d are freed/unmapped
		 * (mmctx_destroy). Bail without the plan streaming or
		 * the evt_out release; the userspace() loop restarts
		 * on the new conn. */
		return 2;
	}
	if (c->plan_left > 0)
		issue_plan_op(c, &c->plan.ops[c->plan_next]);
	return 0;
}

/* fork/clone(!CLONE_VM) hook (D16): clone the parent mm (M3.2 COW
 * machinery — writable VMAs become COW except the stack VMA, which
 * eager-copies: the NT VEH dispatch cannot run on a COW-faulted
 * stack page), copy the eager runs' contents parent→child through
 * the kernel's flat view, spawn the second stub with the parent's
 * register snapshot (rax = 0), resume it; the parent gets the child
 * pid. Upstream fork semantics. */
void uml_nt_sys_fork(struct uml_nt_stub_conn *c, struct uml_nt_stub_data *d)
{
	struct uml_nt_gp_regs *g = &d->regs;
	struct uml_nt_stub_conn *k = &conn_child;
	int vi;

	if (k->alive) {
		os_info("[stubtest] fork: child already exists\n");
		d->retval = (unsigned long long)-9LL; /* -EBADF */
		d->err = 1;
		return;
	}
	if (uml_nt_mm_clone(&mm_child, c->mm, c->ph, g->rsp) < 0) {
		os_info("[stubtest] fork: mm clone failed\n");
		d->retval = (unsigned long long)-12LL; /* -ENOMEM */
		d->err = 1;
		return;
	}
	for (vi = 0; vi < mm_child.nvma; vi++) {
		const struct uml_nt_vma *pv = &c->mm->vma[vi];
		const struct uml_nt_vma *cv = &mm_child.vma[vi];

		if (cv->run_off == pv->run_off)
			continue; /* shared run */
		memcpy(uml_boot.physmem_base + cv->run_off,
		       uml_boot.physmem_base + pv->run_off,
		       cv->end - cv->start);
	}
	k->mm = &mm_child;
	k->ph = c->ph;
	k->ppid = c->pid;
	/* The child resumes at the same instruction with the parent's
	 * registers and rax = 0 (fork semantics); the parent gets the
	 * child pid. */
	if (uml_nt_spawn_stub(k, g->rip + 2, g->rsp, g) < 0) {
		uml_nt_mm_drop(&mm_child, c->ph);
		d->retval = (unsigned long long)-12LL;
		d->err = 1;
		return;
	}
	k->d->init_regs = *g;
	k->d->init_regs.rax = 0;
	/* S4c2/D18: the child shares the TLS block COW and musl never
	 * re-runs arch_prctl after fork — inherit the base so the
	 * child's stub re-applies it like the parent's does. */
	k->fs_base = c->fs_base;
	k->d->fs_base = c->fs_base;
	child_reaped = 0;
	k->resumed = 1; /* the fork spawn resumes the child directly */
	nt->ResumeThread(k->thread);
	/* Upstream fork marks both pte tables read-only: re-protect the
	 * PARENT's views too (mm_clone flagged the kernel-side VMAs —
	 * the stub's MapViewOfFile views are per-conn and stay writable
	 * until told). Ops ride the fork answer (the dispatch parks the
	 * retval while plan_left > 0); the walker's by-refs fixup
	 * guards the uaccess path independently. */
	uml_nt_fork_reprotect_parent(c);
	d->retval = k->pid;
	d->err = 0;
	os_info("[stubtest] fork: child pid %lu\n",
		(unsigned long)k->pid);
}

/* ---- M4.2: real fork through the scheduler (task-backed conns) ----
 *
 * The POC fork above spawns a bare stub — no child KERNEL task, so
 * nobody ever runs a userspace() loop for the child, and the parent's
 * wait4 can only poll (-EAGAIN). The real path arms the pending state
 * below right before the GENERIC fork: copy_process → dup_mm →
 * init_new_context → mmctx_init spawns the child's conn and the seed
 * clones the parent's address space into it at birth; copy_thread
 * hands the child a cold stack at fork_handler → its own userspace()
 * loop serves its own conn; the parent's wait4 blocks in schedule()
 * and the child's do_exit wakes it — upstream parity end to end. */

static struct uml_nt_stub_conn *fork_pending_parent;
static unsigned long long fork_pending_rsp;

/* ---- M5.1c.4: switch-trace ring + the fork_handler birth trace ----
 *
 * The M5.1c fault dies at the final retq of um_set_signals_trace with
 * a garbage return slot, on a vmalloc'd task stack ~146KB away from
 * the one the ioctl ran on — i.e. the crash window spans several task
 * switches the log never names. The ring records every switch (pids +
 * the incoming task's state + stack base); the crash reporter prints
 * it, so a crash names the task chain that led to it instead of a
 * naked rsp. The hook calls arrive via patch 0017 (guarded
 * CONFIG_OS_WINDOWS) — this file already carries the sched headers
 * (skas/process.c cannot: its user.h include collides). */

static struct uml_nt_switch_rec switch_ring[UML_NT_SWITCH_RING];
static unsigned int switch_ring_n, switch_ring_i;
static int stale_task_warned;

unsigned long long uml_nt_switch_ring(const struct uml_nt_switch_rec **out)
{
	*out = switch_ring;
	return switch_ring_n;
}

void uml_nt_switch_trace(void *from, void *to)
{
	struct task_struct *f = from, *t = to;

	/* The "half-baked task in the runqueue" tripwire (039 audit
	 * item): __schedule() sets TASK_RUNNING on `to` before picking
	 * it, so anything else here is a stale/zombie context being
	 * switched to — say so loudly at the switch itself. */
	if (t->__state != TASK_RUNNING && !stale_task_warned) {
		stale_task_warned = 1;
		os_warn("switch: to-task %d state=%ld — not TASK_RUNNING "
			"at switch time\n", t->pid, (long)t->__state);
	}
	switch_ring[switch_ring_i].from_pid = f->pid;
	switch_ring[switch_ring_i].to_pid = t->pid;
	switch_ring[switch_ring_i].to_state = (unsigned long)t->__state;
	switch_ring[switch_ring_i].to_stack =
		(unsigned long long)(uintptr_t)task_stack_page(t);
	switch_ring_i = (switch_ring_i + 1) % UML_NT_SWITCH_RING;
	switch_ring_n++;
}

void uml_nt_fork_trace(void)
{
	/* fork_handler = a task's first breath on its cold vmalloc'd
	 * stack. One line per task: the log + the crash ring can then
	 * attribute every stack base to its owner. */
	os_info("fork_handler: task %d stack %px\n", current->pid,
		task_stack_page(current));
}

void uml_nt_fork_arm(struct uml_nt_stub_conn *parent, unsigned long long rsp)
{
	fork_pending_parent = parent;
	fork_pending_rsp = rsp;
}

void uml_nt_fork_disarm(void)
{
	fork_pending_parent = NULL;
	fork_pending_rsp = 0;
}

int uml_nt_fork_seed(struct uml_nt_stub_conn *child)
{
	struct uml_nt_stub_conn *parent = fork_pending_parent;
	int vi;

	if (parent == NULL)
		return 0;

	/* One phys table per MM CONTEXT would double-count nothing but
	 * also see nothing: run refcounts must count mm CONTEXTS
	 * sharing each run (S3 semantics, mmctx.c comment) — the child
	 * shares the parent's table and abandons its fresh, unclaimed
	 * one (phys_init allocates nothing — the kzalloc is the only
	 * memory). */
	kfree(child->ph);
	child->ph = parent->ph;
	child->ph_shared = 1;

	if (uml_nt_mm_clone(child->mm, parent->mm, child->ph,
			    fork_pending_rsp) < 0) {
		os_info("fork: mm clone failed (child conn pid %lu)\n",
			(unsigned long)child->pid);
		uml_nt_fork_disarm();
		return -ENOMEM;
	}
	/* Contents of the eager (private) spans: everything whose
	 * run_off moved (the stack VMA — the COW-shared runs are the
	 * same bytes by construction). */
	for (vi = 0; vi < child->mm->nvma; vi++) {
		const struct uml_nt_vma *cv = &child->mm->vma[vi];
		const struct uml_nt_vma *pv = &parent->mm->vma[vi];

		if (cv->run_off == pv->run_off)
			continue;
		memcpy(uml_boot.physmem_base + cv->run_off,
		       uml_boot.physmem_base + pv->run_off,
		       cv->end - cv->start);
	}
	/* D18: the child shares the TLS block COW and musl never
	 * re-runs arch_prctl after fork — the child's stub re-applies
	 * the inherited base at its first resume. */
	child->fs_base = parent->fs_base;
	if (child->d != NULL)
		child->d->fs_base = parent->fs_base;
	fork_pending_parent = NULL;
	fork_pending_rsp = 0;
	os_info("fork: child conn pid %lu seeded (%d vma(s), parent "
		"pid %lu)\n", (unsigned long)child->pid,
		child->mm->nvma, (unsigned long)parent->pid);
	return 0;
}

void uml_nt_fork_reprotect_parent(struct uml_nt_stub_conn *c)
{
	int vi, vi_reprotect = 0;

	for (vi = 0; vi < c->mm->nvma; vi++) {
		struct uml_nt_vma *pv = &c->mm->vma[vi];
		unsigned long long len = pv->end - pv->start;

		if (!uml_nt_prot_writable(pv->prot) ||
		    !(pv->flags & UML_NT_VMA_COW))
			continue;
		if (uml_nt_sc_plan_add(c, UML_NT_FOP_UNMAP, 0, pv->start,
				       len, 0) < 0 ||
		    uml_nt_sc_plan_add(c, UML_NT_FOP_MAP,
				       uml_nt_prot_readonly(pv->prot),
				       pv->start, len,
				       pv->run_off) < 0) {
			/* plan full: the parent keeps this writable view;
			 * shared-run safety falls back to the walker's
			 * by-refs fixup (kernel side) — never silently
			 * wrong there. */
			break;
		}
		vi_reprotect++;
	}
	if (vi_reprotect)
		os_info("fork: re-protected %d parent view(s) "
			"read-only\n", vi_reprotect);
}

/* wait4 hook (D16): reap the ONE forked child when it is dead — a
 * live child answers -EAGAIN and the guest retries the trap (the
 * service loop keeps serving every conn meanwhile); true blocking
 * waits ride the scheduler (M4.2, task-backed conns). Status encoding
 * = Linux wait4: WEXITSTATUS is bits 8..15. */
void uml_nt_sys_wait4(struct uml_nt_stub_conn *c, struct uml_nt_stub_data *d,
		      const unsigned long long *a)
{
	struct uml_nt_stub_conn *k = &conn_child;
	unsigned int status;

	(void)c;
	if (k->pid == 0 || child_reaped) {
		d->retval = (unsigned long long)-10LL; /* -ECHILD */
		d->err = 1;
		return;
	}
	if (k->alive) {
		d->retval = (unsigned long long)-11LL; /* -EAGAIN */
		d->err = 1;
		return;
	}
	status = ((unsigned int)k->exit_code & 0xffu) << 8;
	if (a[1] != 0) {
		if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a[1],
				     4, (char *)&status,
				     UML_NT_UACC_TO_GUEST) < 0) {
			d->retval = (unsigned long long)-14LL; /* -EFAULT */
			d->err = 1;
			return;
		}
	}
	child_reaped = 1;
	d->retval = k->pid;
	d->err = 0;
}

/* Spawn one stub.exe for `mm` (S5 pattern: inheritable handles, value
 * cmdline, CREATE_SUSPENDED). init_regs are applied by the stub right
 * before the jump (fork children need the parent snapshot).
 * EXPORT (S1): the real mm-context lifecycle (mmctx.c) spawns through
 * this too — same machinery as the probe, one protocol. */
int uml_nt_spawn_stub(struct uml_nt_stub_conn *c, unsigned long long entry_va,
		      unsigned long long stack_va,
		      const struct uml_nt_gp_regs *init)
{
	/* Kernel-side stub_data views at a FIXED va (below the guest
	 * span, same convention as the stub's own map — stub_nt.h
	 * bootstrap comment): an UNPLACED MapViewOfFileEx lets the NT
	 * allocator pick any 0x6x.. region it likes, which is exactly
	 * where the UML kernel image, guest section and its own
	 * allocations live — the second fork's map landed on live
	 * SLUB pages and the kernel NULL-derefed in kmem_cache_alloc
	 * on the next initcall (M3.3 CI, SIGSEGV 139 post-probe). One
	 * 64K section window per stub ever spawned. */
	static unsigned long long next_data_va = 0x10000000ULL;
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, 1 };
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	struct uml_nt_stub_data *d;
	HANDLE dsec, view;
	char cmd[1200];
	unsigned long long dsec_h, phys_h, ein_h, eout_h;
	unsigned long long data_va;
	int i;

	data_va = next_data_va;
	next_data_va += UML_STUB_SECTION_SIZE;

	dsec = nt->CreateFileMappingW((HANDLE)-1, &sa, 0x04 /*RW*/, 0,
				      UML_STUB_SECTION_SIZE, NULL);
	if (dsec == NULL)
		goto fail;
	/* Record handles AS THEY EXIST (S1): a failed spawn must
	 * clean up without leaking (mmctx destroy walks exactly
	 * these). */
	c->dsec = dsec;
	c->evt_in = nt->CreateEventW(&sa, 0, 0, NULL);  /* stub→kern */
	c->evt_out = nt->CreateEventW(&sa, 0, 0, NULL); /* kern→stub */
	if (c->evt_in == NULL || c->evt_out == NULL)
		goto fail;

	view = nt->MapViewOfFileEx(dsec, 0x000F001F /*FILE_MAP_ALL_ACCESS*/,
				   0, 0, UML_STUB_SECTION_SIZE,
				   (PVOID)(uintptr_t)data_va);
	if (view == NULL)
		goto fail;
	d = view;
	c->d = d;
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

	c->proc = pi.hProcess;
	c->thread = pi.hThread;
	c->pid = pi.dwProcessId;
	c->alive = 1;
	c->exit_code = 0;
	c->plan_next = 0;
	c->plan_left = 0;
	return 0;

fail:
	os_info("[stub] spawn failed win32=%lu\n",
		nt->RtlGetLastWin32Error());
	return -1;
}

/* Serve one signaled conn: seq-check, dispatch, release. Returns 1
 * when the conn halted (kernel terminated it), 2 when the round
 * EXECed (conn destroyed mid-dispatch — no release, the loop
 * restarts on the new conn), -1 on protocol error.
 * EXPORT (S2): the real userspace() loop serves through this — same
 * machinery as the probe's service loop, one protocol. */
int uml_nt_pump_conn(struct uml_nt_stub_conn *c)
{
	int rc;

	mb();
	if (c->d->req_seq != c->d->done_seq + 1) {
		os_info("[stubtest] seq desync pid %lu req=%llu done=%llu\n",
			(unsigned long)c->pid, c->d->req_seq,
			c->d->done_seq);
		return -1;
	}
	rc = serve_conn(c);
	if (rc == 2)
		return 2; /* exec: c/d are dead — no mb, no evt_out */
	/* S4d (task-backed conns): the signal delivery point between
	 * "trap served" and "stub resumed" — the upstream interrupt_
	 * end() position. Ops in flight: the answer is an op, not a
	 * resume — a pending signal stays pending (TIF_SIGPENDING
	 * survives) and delivers on the first op-free round. The INIT
	 * round never ran guest code: nothing can be pending and the
	 * boot conn's trap slot holds bootstrap garbage (rip=2,
	 * rsp=0xffffffffffffe000) — interrupt_end() on that state is
	 * meaningless (found on the first wine run: the rsp-fixup
	 * EFAULTed at frame ffffffffffffe000).
	 *
	 * M5.1c.4 (net gate): the INIT guard was NOT enough — the op-
	 * streaming rounds (cmd=PROT_DONE, the stub applying INIT/plan
	 * ops) publish a result WITHOUT touching d->regs, so their
	 * trap slot is STILL the bootstrap garbage; interrupt_end()
	 * ran on it, polluted the task's pt_regs via sync_trap_regs
	 * and EFAULTed the sigframe rsp fixup (frame ffffffffffffe000,
	 * seen right after the udhcpc-conn INIT round). Deliver only
	 * on REAL trap rounds (SYSCALL/FAULT publish d->regs); op
	 * results deliver at the next real trap. */
	if (c->task_backed && c->owner_regs != NULL &&
	    (c->d->cmd == UML_STUB_CMD_SYSCALL ||
	     c->d->cmd == UML_STUB_CMD_FAULT)) {
		if (c->plan_left == 0)
			uml_nt_signal_check(c);
		uml_nt_fp_push(c, c->owner_regs);
	}
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

/* Any VMA overlap with [s, e)? (guard placement — the loader's own
 * overlap checks live in elf.c). */
static int span_overlaps_mm(const struct uml_nt_mm *mm,
			    unsigned long long s, unsigned long long e)
{
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (s < mm->vma[i].end && e > mm->vma[i].start)
			return 1;
	}
	return 0;
}

static unsigned long __attribute__((ms_abi)) stubtest_thread(void *arg)
{
	unsigned long long blob_len, entry_off;
	unsigned long long text_off, stack_off, guard_off;
	unsigned long long text_va, stack_va, patched;
	unsigned long long entry_va, stack_top;
	struct uml_nt_elf_image img;
	struct uml_nt_gp_regs init_regs;
	int elf_mode, tries;
	HANDLE waits[2];
	int nwaits;

	(void)arg;

	/* Guest runs come from the KERNEL page allocator (D11): a
	 * private allocator over the section double-allocated against
	 * the kernel's buddy/slab (both own the pages past the image)
	 * — guest writes trashed SLUB/maple data and the kernel died
	 * after the fork probe. Offsets are DYNAMIC (pfn << PAGE_SHIFT,
	 * whatever the buddy hands out); every VA and plan op follows.
	 * No run-adjacency assumptions anywhere: the buddy does not
	 * owe us neighbours, so text/stack/guard are INDEPENDENT runs,
	 * one run per VMA (multi-run spans now come from alloc_span —
	 * D12, the loader/clone path). */
	if (uml_nt_phys_init(&probe_phys, uml_boot.physmem_size) < 0) {
		os_info("[stubtest] phys init failed (mem too big for "
			"the run table)\n");
		return 0;
	}
	memset(&img, 0, sizeof(img));
	memset(&init_regs, 0, sizeof(init_regs));
	uml_nt_mm_init(&mm_parent);
	elf_mode = uml_boot.exec_section != NULL &&
		   uml_boot.exec_size != 0;

	if (elf_mode) {
		/* M3.4: the guest init is a REAL ELF image handed over
		 * by the launcher (boot-info v2 exec section) — the
		 * execveat(memfd) analogue. The loader hands every
		 * load region its own span (D11/D12), copies bytes
		 * through the flat view and builds the mm's VMAs. */
		void *view = (void *)(uintptr_t)UML_NT_EXEC_VIEW_VA;
		SIZE_T vs = 0;
		NTSTATUS ms;
		long long rc;
		int si, gok;

		ms = nt->NtMapViewOfSection(uml_boot.exec_section,
			UML_NT_CURRENT_PROCESS, &view, 0, 0, NULL, &vs,
			1 /*ViewShare*/, 0, 0x02 /*PAGE_READONLY*/);
		if (!NT_SUCCESS(ms) ||
		    (unsigned long long)(uintptr_t)view !=
			    UML_NT_EXEC_VIEW_VA) {
			os_info("[stubtest] exec map failed %08x at %p\n",
				(unsigned)ms, view);
			return 0;
		}
		rc = uml_nt_elf_load(&img, &mm_parent, &probe_phys, view,
				     uml_boot.exec_size,
				     uml_boot.physmem_base);
		if (rc != UML_NT_ELF_OK) {
			os_info("[stubtest] exec load FAILED rc=%lld\n",
				rc);
			return 0;
		}
		rc = uml_nt_elf_stack_place(&img, &mm_parent, &probe_phys,
					    &stack_top);
		if (rc != UML_NT_ELF_OK) {
			os_info("[stubtest] stack place FAILED rc=%lld\n",
				rc);
			return 0;
		}
		/* Central patch contract §5.1: every `syscall` in the
		 * loaded image becomes ud2 before any stub maps the
		 * page. Executable regions only — data bytes holding
		 * 0F 05 are data, the decoder is for code. */
		patched = 0;
		for (si = 0; si < img.nseg; si++) {
			if (!uml_nt_prot_execable(img.seg[si].prot))
				continue;
			patched += uml_nt_patch_syscalls(
				uml_boot.physmem_base +
					img.seg[si].run_off,
				img.seg[si].end - img.seg[si].start, 0);
		}
		nt->NtUnmapViewOfSection(UML_NT_CURRENT_PROCESS, view);
		entry_va = img.entry;

		/* Guard run: a fresh run whose VA range misses every
		 * VMA the loader placed (D11: the buddy owes no
		 * position). Collisions LEAK the run instead of
		 * freeing — a freed block comes straight back on LIFO
		 * freelists, the retry would spin on it. */
		gok = 0;
		for (tries = 0; tries < 16 && !gok; tries++) {
			long long off = uml_nt_phys_alloc(&probe_phys);

			if (off < 0)
				break;
			probe_guard_va0 = UML_STUB_RAM_BASE + off;
			probe_guard_va1 = probe_guard_va0 + 0x1000;
			if (!span_overlaps_mm(&mm_parent,
					      probe_guard_va0,
					      probe_guard_va0 +
					      UML_NT_PHYS_RUN_SIZE))
				gok = 1;
		}
		if (!gok ||
		    uml_nt_vma_add(&mm_parent, probe_guard_va0,
				   probe_guard_va0 +
				   UML_NT_PHYS_RUN_SIZE,
				   probe_guard_va0 - UML_STUB_RAM_BASE,
				   UML_NT_PAGE_READWRITE, 0) < 0) {
			os_info("[stubtest] guard vma failed\n");
			return 0;
		}
		/* Probe convention: the guest saves its guard VAs from
		 * r12/r13 at entry (callee-saved — they survive the
		 * write() round-trips); no slot patching, no symbol
		 * lookups, no fixed VAs. */
		init_regs.r12 = probe_guard_va0;
		init_regs.r13 = probe_guard_va1;
		os_info("[stubtest] exec loaded: %d region(s), entry "
			"0x%llx, %llu syscall(s) patched, guards "
			"0x%llx/0x%llx\n", img.nseg, entry_va, patched,
			probe_guard_va0, probe_guard_va1);
	} else {
		/* Legacy M3.3 probe: raw embedded blob (init_blob.S)
		 * staged into one text run, guard VAs patched into its
		 * slots. Kept as the fallback gate; the ELF path above
		 * is the M3.4 acceptance. */
		text_off = uml_nt_phys_alloc(&probe_phys);
		stack_off = uml_nt_phys_alloc(&probe_phys);
		guard_off = uml_nt_phys_alloc(&probe_phys);
		if (text_off < 0 || stack_off < 0 || guard_off < 0) {
			os_info("[stubtest] run alloc failed\n");
			return 0;
		}
		entry_off = text_off;
		text_va = UML_STUB_RAM_BASE + text_off;
		stack_va = UML_STUB_RAM_BASE + stack_off;
		probe_guard_va0 = UML_STUB_RAM_BASE + guard_off;
		probe_guard_va1 = probe_guard_va0 + 0x1000;
		stack_top = stack_va + UML_NT_PHYS_RUN_SIZE;
		entry_va = text_va;

		/* Stage the init image, fill the guard-VA slots, patch
		 * the `syscall`s to ud2 — central-patch contract §5.1. */
		blob_len = nt_guest_init_end - nt_guest_init_start;
		memcpy(uml_boot.physmem_base + entry_off,
		       nt_guest_init_start, blob_len);
		{
			unsigned long long off0, off1;
			unsigned long long va0, va1;

			off0 = (unsigned long long)(uintptr_t)
			       nt_guest_init_slot0;
			off1 = (unsigned long long)(uintptr_t)
			       nt_guest_init_slot1;
			va0 = probe_guard_va0;
			va1 = probe_guard_va1;
			memcpy(uml_boot.physmem_base + entry_off + off0,
			       &va0, 8);
			memcpy(uml_boot.physmem_base + entry_off + off1,
			       &va1, 8);
		}
		patched = uml_nt_patch_syscalls(
			uml_boot.physmem_base + entry_off, blob_len, 0);
		/* The linear sweep must never have eaten a slot byte as
		 * an instruction (decoder false-positive = wild guest
		 * pointer). Verify loud. */
		{
			unsigned long long off0, off1, va0, va1;

			off0 = (unsigned long long)(uintptr_t)
			       nt_guest_init_slot0;
			off1 = (unsigned long long)(uintptr_t)
			       nt_guest_init_slot1;
			memcpy(&va0, uml_boot.physmem_base + entry_off +
				      off0, 8);
			memcpy(&va1, uml_boot.physmem_base + entry_off +
				      off1, 8);
			if (va0 != probe_guard_va0 ||
			    va1 != probe_guard_va1) {
				os_info("[stubtest] guard slot clobbered "
					"by patch scan (va0=0x%llx "
					"va1=0x%llx)\n", va0, va1);
				return 0;
			}
		}
		os_info("[stubtest] init staged at phys 0x%llx (%llu "
			"bytes, %lu syscall(s) patched, guards "
			"0x%llx/0x%llx)\n", entry_off, blob_len, patched,
			probe_guard_va0, probe_guard_va1);

		/* Parent mm (M3 model): per-VMA views — text (1 run
		 * RWX), stack (1 run RW), guard run (RW; the INIT plan
		 * NOACCESS-protects the guard pages). Each run
		 * allocated independently above. */
		if (uml_nt_vma_add(&mm_parent, text_va,
				   text_va + 0x10000ull, text_off,
				   UML_NT_PAGE_EXECUTE_READWRITE,
				   0) < 0) {
			os_info("[stubtest] text vma failed\n");
			return 0;
		}
		if (uml_nt_vma_add(&mm_parent, stack_va,
				   stack_va + 0x10000ull, stack_off,
				   UML_NT_PAGE_READWRITE, 0) < 0) {
			os_info("[stubtest] stack vma failed\n");
			return 0;
		}
		if (uml_nt_vma_add(&mm_parent, probe_guard_va0,
				   probe_guard_va0 + 0x10000ull,
				   guard_off, UML_NT_PAGE_READWRITE,
				   0) < 0) {
			os_info("[stubtest] guard vma failed\n");
			return 0;
		}
	}
	conn_parent.mm = &mm_parent;

	/* M3.7: the heap run — ONE pre-reserved, pre-mapped run the
	 * brk(2) surface moves inside (vma.h contract; the buddy owes
	 * no adjacency, so multi-run heap growth is M3.8+). The probe
	 * exercises brk/mmap on it. */
	{
		long long hoff = uml_nt_phys_alloc(&probe_phys);

		if (hoff < 0 ||
		    uml_nt_vma_add(&mm_parent,
				   UML_STUB_RAM_BASE + hoff,
				   UML_STUB_RAM_BASE + hoff +
				   UML_NT_PHYS_RUN_SIZE,
				   hoff, UML_NT_PAGE_READWRITE,
				   0) < 0) {
			os_info("[stubtest] heap run failed\n");
			return 0;
		}
		mm_parent.heap_start = UML_STUB_RAM_BASE + hoff;
		mm_parent.heap_end = mm_parent.heap_start +
				     UML_NT_PHYS_RUN_SIZE;
		mm_parent.brk = mm_parent.heap_start;
	}
	conn_parent.ph = &probe_phys;

	/* Initial guest rsp = the TOP of the stack run (grows down);
	 * the stack VMA itself owns [stack_va, stack_va + RUN) (ELF:
	 * placed by the loader above the last region). */
	if (uml_nt_spawn_stub(&conn_parent, entry_va, stack_top,
			      &init_regs) < 0)
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
			rc = uml_nt_pump_conn(&conn_parent);
		else if (conn_child.alive)
			rc = uml_nt_pump_conn(&conn_child);
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

	/* M2 gate: the ROOT stub delivered write(1, "hi") through the
	 * full round-trip and its guest exited 0. (Printed only on the
	 * honest path — silent child deaths were reported above.) */
	if (conn_parent.exit_code == 0)
		os_info("[stubtest] ROUND-TRIP OK: write delivered, guest "
			"exit code 0\n");
	os_info("[stubtest] FORK OK: parent exit %lu, child exit %lu "
		"(want 0 / 7)\n", (unsigned long)conn_parent.exit_code,
		(unsigned long)conn_child.exit_code);

	/* S1 gate: the real mm-context lifecycle (the init_new_context/
	 * destroy_context path) — kzalloc conn, spawn a bare suspended
	 * stub on the fat thread, then tear it down (kill + unmap +
	 * close + kfree). No exec involved, so this exercises exactly
	 * the S1 machinery end to end. */
	{
		struct mm_id probe_mm_id;
		int rc, pid;

		memset(&probe_mm_id, 0, sizeof(probe_mm_id));
		rc = uml_nt_mmctx_init(&probe_mm_id);
		if (rc == 0) {
			pid = probe_mm_id.pid;
			uml_nt_mmctx_destroy(&probe_mm_id);
			os_info("[stubtest] MMCTX OK: conn spawn+destroy "
				"(pid was %d)\n", pid);
		} else {
			os_info("[stubtest] MMCTX FAILED rc=%d\n", rc);
		}
	}
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
