/* SPDX-License-Identifier: GPL-2.0 */
/*
 * syscall.h — guest syscall surface (M3.7), uml-nt.
 *
 * Upstream analogue: arch/um/kernel/skas/syscall.c handle_syscall()
 * — the ud2 trap becomes a sys_call_table call with the guest ABI
 * args and the return value goes back into the trap regs. On NT the
 * D10 protocol carries the same state in stub_data (d->args from the
 * stub's gp snapshot, d->retval back, ops may stream).
 *
 * What the surface IS on NT (D16): one conn = one guest process; the
 * handlers run in the SERVING context with the conn's uml_nt_mm
 * installed as the uaccess mm (D15). Syscalls the guest kernel must
 * serve through its own VFS (openat/fstat/getdents64/execve and
 * blocking waits) are NOT emulatable here — the rootfs bytes live
 * inside ext4 on ubda, only the guest VFS can read them; they arrive
 * with the task integration (M3.8: real kernel tasks running the
 * userspace() loop). Until then they fall through to the loud -ENOSYS
 * default — every M3.8 boot failure names the next missing syscall.
 */
#ifndef __UM_OS_WINDOWS_SYSCALL_H
#define __UM_OS_WINDOWS_SYSCALL_H

#include <ntabi.h>
#include <vma.h>
#include <fault.h>

/* One guest process (stub side of the D10 protocol). Lives in the
 * kernel — the conn table is owned by stub_ctl.c (spawn/fork machinery). */
struct uml_nt_stub_conn {
	struct uml_nt_stub_data *d;
	HANDLE evt_in, evt_out;
	HANDLE proc, thread;
	/* the stub_data section handle (kernel-side owner record —
	 * mmctx destroy closes it; spawn leaves it set as soon as it
	 * exists so a failed spawn cleans up without leaking). */
	HANDLE dsec;
	struct uml_nt_mm *mm;
	struct uml_nt_phys *ph; /* guest run refcount layer (mmap/brk) */
	/* M4.2: ph is the PARENT's table (fork shares it — refcount =
	 * mm contexts, S3); destroy must not free what it does not
	 * own. */
	int ph_shared;
	ULONG pid;
	int alive;
	ULONG exit_code;
	/* plan runner: ops stream one round-trip each */
	struct uml_nt_fault_plan plan;
	int plan_next, plan_left;
	/* M3.7: a syscall response may carry ops (mmap/munmap/
	 * mprotect) — the stub reports each op result THROUGH
	 * d->retval (do_action's 1/0), clobbering the syscall return
	 * value. Handlers park it here; the plan-empty PROT_DONE
	 * re-publishes it into d->retval before the final NONE. */
	int plan_has_retval;
	unsigned long long plan_retval;
	/* process identity for the syscall surface: ppid = the stub
	 * pid that forked us (0 for the root conn). */
	unsigned long long ppid;
	/* set_tid_address(2) target (clear-on-exit is M4 signals). */
	unsigned long long clear_tid_va;
	/* arch_prctl(ARCH_SET_FS) — the guest TLS pointer (S4c2/D18).
	 * Published to the stub via d->fs_base at the syscall and
	 * re-applied by the stub at every resume (Windows scheduling
	 * loses a user FS base). Fork copies it: the child shares the
	 * TLS block COW and musl never re-runs arch_prctl after
	 * fork. */
	unsigned long long fs_base;
	/* S2: the owning task's userspace() loop resumed the thread
	 * once (bootstrap: entry state + INIT plan streamed). A forked
	 * conn is resumed by its spawn (fork hook sets this too). */
	int resumed;
	/* M4.2: the conn is backed by a REAL kernel task (created by
	 * init_new_context — exec bprm or fork dup_mm) whose
	 * userspace() loop serves it. The probe's static conns
	 * (stub_ctl conn_parent/conn_child) keep the POC fork/wait4
	 * hooks; task-backed conns go through the generic fork/wait4
	 * (sys_call_table) so blocking waits ride schedule(). */
	int task_backed;
	/* S4d: the owning task's pt_regs (current->thread.regs.regs)
	 * — set by the userspace() loop each round. The FP/XSTATE
	 * round-trip pulls the trap capture into regs->fp and pushes
	 * it back before the answer releases; signal delivery (the
	 * next slice) reads/writes the same block. POC conns stay
	 * NULL — no task, no FP bookkeeping. */
	struct uml_pt_regs *owner_regs;
	/* S4d signal delivery state (uml_nt_signal_check):
	 * sig_regs_current = the dispatch already wrote the restored
	 * state into current->thread.regs (rt_sigreturn) — skip the
	 * trap-state pull; push_verbatim = the answer must resume the
	 * stub at d->regs.rip EXACTLY (no rip+2, no rax=retval) —
	 * forced by rt_sigreturn, implied by a delivered signal. */
	int sig_regs_current;
	int push_verbatim;
};

/* Dispatch one syscall trap served on `c` (d->regs.rax = nr, d->args
 * = the guest syscall ABI). Installs the uaccess mm for the handler,
 * writes d->retval (+ d->err/d->halt) and, when the handler produced
 * stub ops, primes c->plan streaming. */
void uml_nt_syscall_handle(struct uml_nt_stub_conn *c,
			   struct uml_nt_stub_data *d);

/* The mm of the syscall being served (uaccess translation, D15) —
 * NULL outside a handler. */
struct uml_nt_mm *uml_nt_syscall_mm(void);

/* Install the uaccess mm (the dispatch calls this around each
 * handler; uaccess.c reads it through uml_nt_syscall_mm). Returns the
 * PREVIOUS mm — dispatches nest on the one host thread (M4.2), save
 * at entry and restore at exit; see uaccess_walk.h. */
struct uml_nt_mm *uml_nt_uacc_set_mm(struct uml_nt_mm *mm);

/* Spawn one stub.exe process for this conn (S5 pattern, suspended,
 * bootstrap via inherited handles + value cmdline). Used by the probe
 * fork path AND the real mm-context lifecycle (mmctx.c) — one
 * machinery, one protocol. Returns 0, -1 on failure; conn fields
 * record handles as soon as they exist so a failed spawn cleans up
 * without leaking. */
int uml_nt_spawn_stub(struct uml_nt_stub_conn *c, unsigned long long entry_va,
		      unsigned long long stack_va,
		      const struct uml_nt_gp_regs *init);

/* The configured stub exe path (uml_nt_stub= / uml_nt_stubtest=
 * param), or NULL when neither was given. */
const char *uml_nt_stub_path(void);

/* Serve one signaled conn (S2 export of the probe's pump_conn):
 * seq-check, dispatch the published request, release the stub.
 * Returns 0 = served, 1 = the conn halted (kernel terminated the
 * stub — exit_code holds the guest retval), -1 = protocol error. */
int uml_nt_pump_conn(struct uml_nt_stub_conn *c);

/* Hooks implemented next to the conn table (stub_ctl.c):
 *  - fork/clone(!CLONE_VM): spawn the child stub from the parent's
 *    register snapshot (M3.3 machinery).
 *  - wait4: reap a DEAD child; a live child answers -EAGAIN (the
 *    guest retries the trap; true blocking needs the scheduler M4.2).
 * Both write d->retval/d->err. */
void uml_nt_sys_fork(struct uml_nt_stub_conn *c, struct uml_nt_stub_data *d);
void uml_nt_sys_wait4(struct uml_nt_stub_conn *c, struct uml_nt_stub_data *d,
		      const unsigned long long *a);

/* ---- M4.2: real fork through the scheduler (task-backed conns) ---- */

/* Arm the pending-fork handoff for the NEXT init_new_context: the
 * child mm's conn (spawned by copy_process → dup_mm → mmctx_init)
 * gets the parent's address space cloned into it at birth (mm_clone:
 * COW both sides, eager stack copy) — the window between conn spawn
 * and the child task's first INIT serve, all on the forking task's
 * stack. Call right before the generic fork, disarm right after. */
void uml_nt_fork_arm(struct uml_nt_stub_conn *parent, unsigned long long rsp);
void uml_nt_fork_disarm(void);

/* init_new_context (mmctx.c) calls this on the freshly spawned conn:
 * consumes a pending fork (nothing otherwise). Clones the parent's
 * uml_nt_mm into the child conn's (sharing the parent's phys table —
 * refcount = mm contexts, S3), eager-copies the private spans, and
 * inherits the TLS base (D18). Returns 0, -ENOMEM on clone failure
 * (the mm — and with it the fork — aborts). */
int uml_nt_fork_seed(struct uml_nt_stub_conn *child);

/* Queue the fork answer's re-protect ops on the PARENT (upstream fork
 * marks both pte tables RO): unmap + remap read-only every COW-flagged
 * writable VMA — the parent's next write faults into the COW machinery
 * instead of landing on a run the child still reads. */
void uml_nt_fork_reprotect_parent(struct uml_nt_stub_conn *c);

/* Copy the CURRENT trap's register state into the task's kernel-shadow
 * pt_regs (process.c, next to conn_pull_regs) — the generic fork's
 * copy_thread memcpy's current_pt_regs, which is otherwise one round
 * stale; rip lands +2 (resume past the ud2, matching what the stub
 * does for the parent's own resume). */
void uml_nt_sync_trap_regs(struct uml_pt_regs *regs,
			   const struct uml_nt_stub_data *d);

/* S4d: push the task's FP block (regs->fp) into the conn's stub_data
 * xstate[] and flag the stub to apply it at resume — the upstream
 * put_fp_registers half (the pull is conn_pull_regs, the get half).
 * Called by the pump before the answer releases the stub. */
void uml_nt_fp_push(struct uml_nt_stub_conn *c, struct uml_pt_regs *regs);

/* S4d: the signal delivery point (upstream interrupt_end() parity —
 * it runs between "trap served" and "stub resumed"): make
 * current->thread.regs this round's state, run the generic signal
 * machinery (get_signal → do_signal → the sigframe setup), and when
 * a signal was delivered push the rewritten regs verbatim + flag the
 * stub. POC conns never call this (no task, no signals). */
void uml_nt_signal_check(struct uml_nt_stub_conn *c);

/* S4d: publish one plan op into the conn's stub slot (the static
 * issue_plan_op's export — the pump-side signal delivery queues
 * COW-fixup ops mid-signal_check). */
void uml_nt_plan_issue_op(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op);

/* Append one stub op to the conn's plan for the current answer (the
 * syscall dispatch resets the plan at entry; ops accumulate and stream
 * after the handler, retval parked). Used by the syscall handlers and
 * the fork hook (parent-view re-protect). */
int uml_nt_sc_plan_add(struct uml_nt_stub_conn *c, unsigned op, unsigned prot,
		       unsigned long long va, unsigned long long len,
		       unsigned long long off);

/* Consume the execve conn-switch flag (serve_conn, right after the
 * handler): 1 = the syscall exec'd successfully — the conn (and its
 * stub_data d) were destroyed mid-round (exec_mmap → mmctx_destroy);
 * the caller must bail the protocol round without touching c/d, and
 * the userspace() loop restarts on the new conn. */
int uml_nt_syscall_consume_exec(void);

/* M5.1c.8 diag (bounded, syscall.c): the kernel-view qword at a guest
 * VA of this conn's mm, and the mm's VMA/run layout with refs. */
void uml_nt_diag_slot(const char *tag, struct uml_nt_stub_conn *c,
		      unsigned long long va);
void uml_nt_diag_mm(const char *tag, struct uml_nt_stub_conn *c);
void uml_nt_diag_qwords(const char *tag, struct uml_nt_stub_conn *c,
			unsigned long long va, int n);

#endif /* __UM_OS_WINDOWS_SYSCALL_H */
