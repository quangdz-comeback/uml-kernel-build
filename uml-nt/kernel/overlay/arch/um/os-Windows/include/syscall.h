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
 * handler; uaccess.c reads it through uml_nt_syscall_mm). */
void uml_nt_uacc_set_mm(struct uml_nt_mm *mm);

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
 *    guest retries the trap; true blocking needs the scheduler M3.8).
 * Both write d->retval/d->err. */
void uml_nt_sys_fork(struct uml_nt_stub_conn *c, struct uml_nt_stub_data *d);
void uml_nt_sys_wait4(struct uml_nt_stub_conn *c, struct uml_nt_stub_data *d,
		      const unsigned long long *a);

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

#endif /* __UM_OS_WINDOWS_SYSCALL_H */
