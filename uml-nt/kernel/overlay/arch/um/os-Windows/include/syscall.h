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
#include <uaccess_walk.h>

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
	/* mapcanary (M5.6a): single-outstanding-op save slot for the
	 * writable-MAP view-backing check — see stub_nt.h v7. mc_active
	 * marks the op at plan_next-1 as canaried; PROTDONE verifies
	 * mapcanary_got and flat-restores the saved qword. */
	unsigned long long mc_want, mc_off, mc_orig;
	int mc_active;
	/* binwatch (M5.6a, referee 37144114627): cached main_arena VA
	 * discovered once by heap scan (0 = not yet); the per-round
	 * arena-bin walk validates the glibc double-link invariant and
	 * tcache overlap. v3 (37177116246): per-bin member/link field
	 * snapshots — a transition into an ILLEGAL value names the
	 * exact qword + round (the foreign write itself). */
	unsigned long long bw_arena;
	unsigned long long bw_snap[16][8][5]; /* bin,slot,{va,fd,bk,
		fdbk,bkfd} */
	int bw_nslot[16];
	int bw_snap_valid;
	/* [replay-check] (M5.6a, referee 37179076089): a write fault's
	 * repair replays the faulting store on the fixed view — nothing
	 * today PROVES the replay landed. Arm at the fault (qword store
	 * decodable: 48/49/4c/4d 89 + 48/49 c7 forms), verify at the
	 * same conn's next syscall park: the qword still holding the
	 * BEFORE value one full round later = the swallowed replay —
	 * the lost-store class named at the store itself. */
	unsigned long long rp_va, rp_want, rp_before, rp_rip,
		rp_armrun;
	unsigned long long op_log[64][5];
	int op_log_n;
	/* whole-page snapshot at the arm (the (A)-vs-(B) rider):
	 * one reverted qword = the natural chunk cycle; a page full
	 * of reverted qwords = a wholesale rewrite by a sibling. */
	unsigned char rp_pagesnap[4096];
	/* The all-faults resume watchdog (M5.6a): every fault round
	 * records its rip; the next round compares d->resume_rip — a
	 * resume that is NOT the faulting rip is the broken-resume
	 * class (the replay-check only ever watched armed pages; the
	 * heap's mid-heap formation faults were never covered). */
	unsigned long long last_fault_rip, last_fault_addr;
	int last_fault_valid;
	int rp_active;
	int rp_pd_done; /* one [replay] PROTDONE print per arm (dl6
			 * storm lesson) */
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
	/* M5.4 c3 (systemd): per-process prctl state. comm shows up in
	 * the "Comm:" panic field (PR_SET_NAME); pdeathsig/dumpable/
	 * no_new_privs are recorded and served by PR_GET_*. */
	char comm[16];
	u32 pdeathsig;
	int dumpable;
	int no_new_privs;
	/* M5.4 c3 (systemd): personality(2) cell. journald/udevd ship
	 * LockPersonality=yes; execute.c locks via a
	 * personality(0xffffffff) read + set pair and kills the child
	 * (status 228/SECCOMP) on ENOSYS — run 36869737934 restart-
	 * looped journald on exactly that, keeping the M5.5a gate
	 * red with SIGSEGV=0. Get returns the stored persona, set
	 * stores and returns the previous (PER_LINUX=0 init: the
	 * persona bits are no-ops on this port — loads are
	 * fixed-position, so ADDR_NO_RANDOMIZE changes nothing). */
	unsigned long long persona;
	/* K6 (M5.6a, scrutiny fix): the nr of the handler CURRENTLY
	 * in flight on this conn — stamped at dispatch entry
	 * (uml_nt_uacc_nr_enter) and re-armed at the stack-switch
	 * boundary beside mm/sink (uml_nt_switch_trace →
	 * uml_nt_uacc_nr_switch, both uaccess_walk.h). last_nr below
	 * only names COMPLETED rounds (stamped at exit): without this
	 * stamp a parent woken inside its blocked wait4 (61) would
	 * hash/report a do_exit'd child's exit/exit_group nr (60/231)
	 * — that dispatch never unwinds to restore the global. kzalloc
	 * init = 0. */
	unsigned long long active_nr;
	/* M5.4 c3 diag: the last syscall round this conn served. The
	 * SIGSEGV print names it — a retval the guest consumed as a
	 * pointer/length is attributable at the death site without
	 * correlating census lines across the log. */
	unsigned long long last_nr;
	long long last_ret;
	/* M5.4 c3 diag (Astra request, archive
	 * astra-m55a-oneshot-blocked-d21 §2): the last 4 SUCCESSFUL
	 * mmap results of this conn. glibc __libc_message() mmaps the
	 * __abort_msg copy as the final mapping before abort() ->
	 * raise() reaches the tgkill trap (run 36891891282: the mmap
	 * landed at 0x605c0000); the ABRT tripwire reads its
	 * candidates from this ring — prefix-checked, so no hardcoded
	 * VA and no libc symbol table. kzalloc init is the reset. */
	unsigned long long mmap_recent[4];
	int mmap_recent_n, mmap_recent_head;
	/* M5.4 c3 (map 057): residue-watch. Armed by the fork seed
	 * with the parent's trap+2 (the fork-resume rip — a value no
	 * live frame may carry as data) and the fork rsp (names the
	 * stack VMA). The pump scans that VMA per round while armed;
	 * the FIRST round whose stack re-introduces the value is the
	 * cluster writer — log its nr/retval/regs, disarm (one-shot).
	 * The seed itself proved clean (below-rsp zero + live-window
	 * scan both read 0 in run 36850929441), so any hit here is
	 * strictly post-seed. Zero = disarmed (kzalloc init). */
	unsigned long long watch_val;
	unsigned long long watch_rsp;
	int watch_left;
	/* M5.6a WRITER-HUNT: the tcache canary watch fired once for
	 * this conn (per-conn one-shot; the watch re-validates every
	 * serve round until then). kzalloc init = armed. */
	int tcache_fired;
	/* M5.6a WRITER-HUNT (referee 37085373580 decode): the tcache
	 * entries delta-watch. The cowtrap on the tcache page retires
	 * at the page's FIRST write (glibc's own entry linking), so
	 * the 16-byte ASCII blob that killed three boots landed after
	 * the retirement, unwitnessed. This watch snapshots
	 * entries[0..3] every round; a change to a pointer-ILLEGAL
	 * value (top 16 bits set — no legit entry has them, safe-
	 * linked or not — or misaligned) names the round (last_nr)
	 * and the trap rip. Legit relinking stays silent, so the
	 * budget survives to the poison. kzalloc init = clean.
	 *
	 * WHOLE-STRUCT (K3 starhost, referee 37133302551 decode): the
	 * tcache watches went fully silent (POISON=0, tcdelta=0) while
	 * the boot still died "corrupted double-linked list" — the
	 * delta watch covered only entries[0..3] and the abort dump
	 * proved the visible entries raw-legal. Snapshot ALL 64
	 * entries + all 64 counts per round: a transition INTO an
	 * illegal state (pointer-illegal entry, count > 7) now names
	 * its round from ANY bin. The per-round read already copies
	 * the whole struct — the extension is compare-only. */
	unsigned long long tc_snap[64];
	unsigned short tc_counts_snap[64];
	int tc_snap_valid;
	/* M5.6a CHUNK WATCH (referee 37087346082 decode): [tcdelta]
	 * proved the entries[] text = glibc's own tcache_get revealing
	 * a freed chunk whose first 8 bytes held the literal ASCII
	 * "SYSTEMD_" (env-text class; the per-boot variant byte =
	 * the (chunk_addr>>12) reveal XOR). The store into the chunk
	 * itself is one event EARLIER than the get that reveals it —
	 * per watched bin (all 64 entries[] slots holding a legal
	 * in-heap pointer), snapshot the chunk's first 8 bytes
	 * (e->next) per serve round; a change names the write's round
	 * and trap rip. A popped chunk stops being the head (its slot
	 * re-arms on the entry change), so a stable head's e->next is
	 * stable under legit glibc — only a foreign write (or a
	 * double-free) moves it.
	 *
	 * DEPTH-4 (referee 37117711740 decode): the poison also lands
	 * in list members BELOW the stable head (37116465517:
	 * mid-list) — and the tcache list is LIFO, so a member's
	 * e->next is as stable as the head's while it sits in the
	 * list; push/pop only touch the head slot and any head change
	 * re-walks the bin. So each bin watches the first 4 members:
	 * slot [d] = the list member d steps from the head, snapshotted
	 * at (re)arm via the safe-linked decode (key = the member's
	 * own address). kzalloc init = disarmed. */
	unsigned long long tc_chunk_va[64][4];
	unsigned long long tc_chunk_snap[64][4];
	unsigned char tc_chunk_armed[64][4];
	unsigned char tc_chunk_valid;
	/* M5.6a POISON SWEEP (referees 37111253316 + 37112746470
	 * decode): the payload (literal "SYSTEMD_" qword,
	 * 0x5f444d4554535953 — reveal math exact across every boot)
	 * keeps landing in freed chunks while EVERY write witness
	 * stays negative: the writer strikes between rounds and each
	 * watched page retires at its first legit write. At [tcdelta]
	 * fire the WHOLE heap VMA is swept for the literal qword; up
	 * to 4 hit VAs go under per-round byte watch — the next
	 * content change to a watched chunk prints ITS round
	 * (nr/ret/rip): the writer's own round, not the surfacing
	 * pop. kzalloc init = disarmed. */
	unsigned long long posweep_va[4];
	unsigned long long posweep_snap[4];
	unsigned char posweep_armed[4];
	/* K6 step 2 (M5.6a decision-tree step 2): the [tcekey]
	 * syscall-park snapshot — the walked tcache chunks, bin
	 * heads/counts and heap-piece run_offs of the PREVIOUS park,
	 * the diff base for the STALE-KEY / DUP-CHUNK /
	 * HEAD-REENTRY / COUNT-MISMATCH / [tcekey-run] flags. The
	 * dedup ring (class, va) keeps a persistent torn state from
	 * eating the 64-line budgets. kzalloc init = no prev
	 * (ek_valid 0). */
	struct uml_nt_tce_snap ek_prev;
	unsigned short ek_prev_counts[64];
	unsigned long long ek_prev_entries[64];
	unsigned long long ek_want_key; /* the learned tcache_key (the
	 * STALE-KEY comparator — glibc 2.34+ stores a RANDOM value in
	 * e->key, so it is majority-voted from the walked chunks, not
	 * assumed; 0 = not yet learned (>=2 agreeing chunks). */
	unsigned long long ek_pv_start[UML_NT_TCE_PIECES];
	unsigned long long ek_pv_off[UML_NT_TCE_PIECES];
	int ek_pv_n;
	int ek_pv_valid;
	unsigned long long ek_parks;
	/* cumulative walked members DROPPED because a park's
	 * snapshot filled (UML_NT_TCE_MAX = 448 = the full healthy
	 * tcache, so a drop needs a bin deeper than healthy — the
	 * census/flag trunc disclosure; kzalloc init = 0 = every
	 * snapshot complete). */
	unsigned long long ek_trunc;
	unsigned long long ek_dedup_va[16];
	unsigned char ek_dedup_cls[16];
	int ek_dedup_head;
	int ek_valid;
	/* M5.6a TCACHE TRIP: set on the conn at its first fork seed —
	 * the poison window opens post-fork; the serve hook then arms
	 * the tcache struct page READ-ONLY (one live trip, re-armed
	 * per round within budget) so every write to the entries[]
	 * page faults and names its rip. The poison write = a direct
	 * store (bypasses every funnel); its rip = the hunt's end. */
	int tctrip_want;
	/* M5.4 c3 (048): destroy stamps DEAD before kfree; consumers
	 * that reach a conn through a RETAINED pointer (the switch
	 * hook's re-arm, the co-mapper census, the fork seed) refuse a
	 * stamped conn instead of walking its freed mm. kzalloc reuse
	 * zeroes the stamp (a fresh conn is the benign no-vma hole);
	 * non-zeroed reuse keeps it and is refused. The dispatch ENTRY
	 * deliberately does NOT check: that check runs out of order
	 * with the fork seed (d9808b9 regressed fork children into
	 * unseeded conns — run 36813545490 "INIT pid 4252: 0 map
	 * op(s)", stub rip=0 — reverted in 631632b). */
	u32 dead_magic;
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

/* K6 (M5.6a, scrutiny fix): the [uawrite] nr-context protocol
 * (nr_enter / set_nr / nr_switch / nr_current) lives in
 * uaccess_walk.h beside the witness helpers it feeds — it is
 * unit-tested standalone on Linux CI with the walker. During a
 * handler c->last_nr still names the PREVIOUS round (it is
 * stamped at the handler's EXIT); the dispatch hands the witness
 * the live nr at entry (nr_enter stamps c->active_nr) and
 * uml_nt_switch_trace re-arms it at the scheduler boundary
 * (nr_switch) beside mm/sink. */

/* Spawn one stub.exe process for this conn (S5 pattern, suspended,
 * bootstrap via inherited handles + value cmdline). Used by the probe
 * fork path AND the real mm-context lifecycle (mmctx.c) — one
 * machinery, one protocol. Returns 0, -1 on failure; conn fields
 * record handles as soon as they exist so a failed spawn cleans up
 * without leaking. */
#define UML_NT_CONN_DEAD 0xDEADC0DEu

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

/* WRITER-HUNT (068 suppl. 5): at the abort capture, scan the dying
 * task + PID 1 + the fork parent for the 8-byte TEXT fragment found
 * poisoning the tcache entries ("Z$UTMED_" class — runtime string,
 * matches no binary rodata). Read-only provenance scan (the valscan
 * machinery). */
void uml_nt_stub_frag_scan(struct uml_nt_stub_conn *c,
			   const unsigned char *pat);

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

/* [alias] census (M5.6a, decode 37095399220): walk every live conn's
 * VMA table for VMA run-ranges intersecting [run_off, run_off+len)
 * and log each FOREIGN mapper — a stale view over a recycled run is
 * the one writer class every kernel-side witness is blind to (views
 * are not refs). Callers: the [tcdelta] poison detection and the
 * [abrt] tcache dump. Log-only. */
void uml_nt_run_alias_census(struct uml_nt_stub_conn *c,
			     unsigned long long run_off,
			     unsigned long long len);

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

/* M5.6a root-cause fix (the table<->view swap window airtight): 0
 * when the conn's plan can hold `need` MORE ops, -1 when not. Every
 * handler that mutates the VMA table and queues view ops reserves
 * FIRST and refuses the syscall (Linux failure semantics) on a full
 * plan — a view op silently dropped by a full plan strands the
 * stub's view on a run the table no longer owns (the K3 uaccess-
 * fixup precedent, referee 37137513174; dl18 37512134759 named the
 * class as the heap-tear's formation window). */
int uml_nt_sc_plan_reserve(struct uml_nt_stub_conn *c, int need);

/* [cowtrap] (M5.6a): re-queue the armed poison-page NOACCESS op after
 * a plan reset (the syscall entry and the fault handler both call
 * this). Defined in stub_ctl.c next to the cowwatch machinery. */
void uml_nt_cowtrap_pending(struct uml_nt_stub_conn *c);

/* K6 [cowrace] (M5.6a, feature cowcopy-race-witness): the copy-vs-
 * in-flight-store witness's ARM — called at every run copy+re-home
 * (the [cowcopy] fault-path COW copy in stub_ctl.c and the brk
 * re-home here in syscall.c) with the copied range. Records the
 * src/dst run, va range, copying conn, the source's t0 hash +
 * gen/refs and the RUNNING-vs-PARKED sharer snapshot; the CHECK pass
 * (cowrace_round, stub_ctl.c) runs at the next syscall parks and
 * fires [cowrace] when a store landed in the source after the copy.
 * Read-only, budgeted; the pure logic is in uaccess_walk.c (host-
 * tested). */
void uml_nt_cowrace_arm(struct uml_nt_stub_conn *c,
			unsigned long long src_off,
			unsigned long long dst_off,
			unsigned long long len,
			unsigned long long va_base,
			const char *what);

/* [cowtrap] alloc-side arm (the closing slice): READ-ONLY the first
 * page of a freshly allocated multi-run anon span / re-homed heap so
 * the run's FIRST write faults back with the writer's live regs.
 * Call right after the alloc's MAP op is queued. */
void uml_nt_cowtrap_arm_alloc(struct uml_nt_stub_conn *c,
			      unsigned long long va,
			      unsigned long long len,
			      unsigned long long run_off);

/* [cowtrap] grow-side arm (run 37078256773): a re-home retires the
 * old span's slots and re-arms only the new head+tail — the previous
 * frontier pages drop out of coverage. Call right AFTER the main
 * arm_alloc on the new span; re-arms [old_end-16p, old_end). */
void uml_nt_cowtrap_arm_oldtail(struct uml_nt_stub_conn *c,
				unsigned long long heap_start,
				unsigned long long old_end,
				unsigned long long new_off);

/* [cowtrap] trip check at the fault handler: names the first write's
 * rip and retires the slot; the repair stays the normal flow. */
void uml_nt_cowtrap_trip(struct uml_nt_stub_conn *c,
			 struct uml_nt_stub_data *d);

/* [fork-entry] audit: the pid of the fork handoff pending right now
 * (-1 = none). mmctx's spawn print pairs it with the child's mm
 * nvma so an unseeded birth names its branch in the same boot. */
int uml_nt_fork_pending_pid(void);

/* [copyver] (run 37073260886 decode): every kernel-side bulk copy
 * into guest memory — COW repair, brk re-home fill, fork seed eager
 * copy — reads back byte-exact. The trap census only sees stub-view
 * (guest-CPU) writes; a kernel copy that lands stale bytes corrupts
 * guest allocator metadata with NO fault and NO catch (the task 49
 * "unaligned tcache chunk" boot had zero tcwatch/trap anomalies).
 * Mismatch = loud with the first differing byte; copy happened, the
 * caller's flow is untouched — log-only. */
int uml_nt_copy_verify(char *dst, const char *src, unsigned long long len,
		       const char *what);

/* Consume the execve conn-switch flag (serve_conn, right after the
 * handler): 1 = the syscall exec'd successfully — the conn (and its
 * stub_data d) were destroyed mid-round (exec_mmap → mmctx_destroy);
 * the caller must bail the protocol round without touching c/d, and
 * the userspace() loop restarts on the new conn. */
int uml_nt_syscall_consume_exec(void);

#endif /* __UM_OS_WINDOWS_SYSCALL_H */
