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

#define UML_NT_IMGWATCH_MAX 16

/* M5.6a login-depth follow-up (Shelley 149 [resume-regs]): one guest
 * resume as the kernel ANSWERED it. The witness's whole point is that
 * d->regs is the stub's resume state (gp_to_context applies it
 * verbatim), so the answer's rsp is directly comparable with the trap
 * capture of the same round — a syscall/fault fold touches rip and rax
 * only, and the single legitimate stack rewrite is a verbatim push
 * (sigframe placement / rt_sigreturn). The ring keeps the interval
 * tail for a conn whose next trap lands in image text; `last` is the
 * record right before that trap (the round the referee question
 * names). */
#define UML_NT_RRES_RING 16
/* M5.6a [pivot trace]: steps kept for the pivot line's call-site view
 * and the per-conn / per-arm step budgets (a bound on the boot cost). */
#define UML_NT_TF_RING 8
/* The traced intervals run 1-2k instructions (a 1129-step arm
 * ended at the next syscall in referee 40086019923), and the
 * login path reaches the pivot after a couple of close(3)s — so
 * an arm is 3000 steps and a conn may spend 15000 (~1.5 s of
 * single-stepping) before the instrument gives up. */
#define UML_NT_TF_STEPS_PER_ARM 3000u
#define UML_NT_TF_STEPS_PER_CONN 15000u
/* M5.6a [pivot-sample] (Shelley's ruling on to-shelley/150): the TF
 * single-step is retired — the Windows dispatcher eats TF on every
 * hop. The sampler reads the RUNNING stub thread's CONTEXT between two
 * rounds instead: per-arm / per-conn sample budgets (each sample is a
 * SuspendThread/GetThreadContext/ResumeThread round-trip, ~5-20 us, so
 * 400 samples cover several ms of guest execution). */
#define UML_NT_SMP_PER_ARM 2000u
#define UML_NT_SMP_PER_CONN 12000u
/* Suspension attempts per BURST (one burst = one answer release).
 * Samples taken while the stub is waking up / in its own dispatch path
 * are retried, not charged: 400 tries is ~4 ms of probing, far past
 * the ~50 us wake latency and enough to cover a whole long interval. */
#define UML_NT_SMP_TRIES 400u
/* The claimed pivot entry (Shelley 150's static walk):
 * _dl_find_dso_for_object's array-marshalling window in the interp
 * (entry 0xb490, the '-0x428/-0x430(%rbp,%rcx,1)' marshal at 0xc626). */
#define UML_NT_SMP_DLDSO_LO 0xb490ull
#define UML_NT_SMP_DLDSO_HI 0xc650ull
/* Longest exec path the conn records (gates the trace to the victim
 * binary class; also names the conn in the pivot lines). */
#define UML_NT_EXEC_PATH_MAX 48
struct uml_nt_rres_rec {
	unsigned long long seq;		/* the round's req_seq */
	unsigned long long rip, rsp, rbp, rbx, rax;
	unsigned long long trap_rip;	/* this round's capture */
	unsigned long long trap_rsp;
	unsigned long long last_nr;
	long long last_ret;
	unsigned int cmd;		/* UML_STUB_CMD_* of the round */
	unsigned int verbatim;		/* XS_VERBATIM on the answer */
	unsigned int wild;		/* rsp landed in an image run */
	unsigned int cls;		/* uml_nt_rres_class of the round */
};

struct file;

/* M5.6a D27 (Shelley 2026-10-23): a DEFERRED file mapping — the VMA is
 * registered here and gets runs + file bytes at the first fault
 * (upstream demand paging), not at mmap. Only run-aligned fresh
 * PROT_READ mappings that the eager sharing cache did not take (the
 * 13 MiB hwdb.bin single-mapper case) register. The region owns a
 * file reference; any structural op over it (munmap/mprotect/refill)
 * materializes it eagerly first. */
#define UML_NT_LAZY_MAX 4
struct uml_nt_lazy_region {
	unsigned long long start, end;	/* run-aligned VA span */
	unsigned long long file_off;	/* file offset of start */
	unsigned long long fsize;
	struct file *file;
	int used;
	unsigned long long touched_runs;
};

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
	/* [ss-stray] rows consumed from d->ss_stray_n (stub_nt.h v14) */
	unsigned int ss_stray_seen;
	/* plan runner: ops stream one round-trip each */
	struct uml_nt_fault_plan plan;
	int plan_next, plan_left;
	/* K6 (M5.6a, cowcopy-race-class-fix, dlW 37576991123 / dlX
	 * 37579340518 — the RETIRE-LOST verdict): the DEFERRED COPY
	 * descriptor. Every cowcopy/re-home copy the kernel owns —
	 * the fault-path COW repair (kind 1: D26 — the plan's copy
	 * directive is SNAPSHOTTED here at the arm; the plan struct
	 * is scratch a superseding mm_fault wipes) and the brk
	 * re-home bulk copy (kind 2: src/dst/len/va/gens below) —
	 * is DEFERRED to the
	 * teardown/re-map boundary of ITS OWN plan's drain (fault.c
	 * uml_nt_fault_copy_due decides when; stub_ctl.c
	 * deferred_copy_exec is the how): the copy runs after every
	 * release op of the plan applied (the conn's view of the
	 * source is torn down — no window in which the table says
	 * dst while the conn's view still maps src at copy time,
	 * and late stores ride into the live backing instead of
	 * retiring lost) and before the first re-MAP issues (the
	 * new views cannot race the snapshot). Set at the decision
	 * round (fault round / sys_brk); consumed once at the drain
	 * boundary. kzalloc init = 0/none. */
	int copy_pend_kind; /* 0 = none, 1 = fault COW, 2 = brk re-home */
	unsigned long long copy_pend_src;
	unsigned long long copy_pend_dst;
	unsigned long long copy_pend_len; /* 0 = none */
	unsigned long long copy_pend_va;  /* fault: the fault va base; brk: heap_start */
	unsigned long long copy_pend_gsrc; /* gens captured at the decision */
	unsigned long long copy_pend_gdst;
	/* K6 (M5.6a, cowcopy-race-class-fix): the per-conn VIEW LEDGER
	 * — every stub view this conn's op stream has issued (recorded
	 * at MAP issue in stub_ctl.c issue_plan_op, retired at UNMAP
	 * bases, prot-refreshed on PROTECTs). The prime-time release
	 * set (uml_nt_view_release_complete) gives every re-homing
	 * plan the COMPLETE per-view release set over the ranges it
	 * releases, and the drain-side census refuses loudly if any
	 * committed mapping over a released range survives outside the
	 * ledger — a writable view of an abandoned backing is the dl26
	 * 37539992560 conviction (the tcache_put pair in the
	 * abandoned source run), never again silent. kzalloc init =
	 * empty. */
	struct uml_nt_view views[UML_NT_VIEW_MAX];
	int nviews;
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
	/* K6 [flatwr] (feature flatwrite-retire-witness): the mapcanary
	 * plant→restore spans a stub round-trip (op issue → PROT_DONE) —
	 * the HIGHEST-risk flat-write window of the set. mc_gen/mc_va
	 * carry the (gen, va) captured at the plant; the restore
	 * compares them (a re-handed run or a re-homed va = the restore
	 * wrote through a stale translation). */
	unsigned long long mc_gen, mc_va;
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
	/* K6 [viewprobe] (M5.6a, feature viewprobe-witness): the
	 * drain record — the plan streams that DRAINED since this
	 * conn's previous syscall park ([fork-sync] re-protect/MAP
	 * streams and fault-repair streams alike: count, whether any
	 * carried PROTECT/MAP ops, whether the last was
	 * retval-carrying, and up to UML_NT_VP_DRAIN_OPS op
	 * summaries). The park pass and every VIEW-DIVERGED fire cite
	 * it — the formation window's re-protect stream names itself.
	 * Plus the probe state: the chunk-page rotation cursor and
	 * the census counters. kzalloc init = clean/zero. */
	int vp_drain_count;
	int vp_drain_pm;      /* any drained stream carried P/M ops */
	int vp_drain_retval;  /* the LAST drained stream was the
			       * retval-carrying [fork-sync] class */
	int vp_drain_nops;    /* ops recorded (<= UML_NT_VP_DRAIN_OPS) */
	int vp_drain_total;   /* the last stream's real n_ops (trunc
			       * disclosure) */
	struct uml_nt_fault_op
		vp_drain_ops[UML_NT_VP_DRAIN_OPS];
	unsigned int vp_rr;   /* chunk-page rotation cursor */
	unsigned long long vp_parks;
	unsigned long long vp_probed;  /* pages read through the stub */
	unsigned long long vp_expected; /* stub-unreadable pages that
					  * VQ explains (NOACCESS guards,
					  * released ranges) — never a
					  * fire, always counted */
	unsigned long long vp_raced;   /* raced double-reads (a
				       * concurrent sharer — never a
				       * fire, always counted) */
	unsigned long long vp_divseen; /* divergence sightings incl.
					* deduped repeats */
	unsigned long long vp_unledgered; /* watched vas with NO ledger
					   * view covering them */
	unsigned long long vp_dedup_va[16];
	unsigned char vp_dedup_cls[16];
	int vp_dedup_head;
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
	/* M5.6a IMGWATCH (why=p hunt, referee 39950787337 victim #3):
	 * fingerprints of this exec's pure-RO image runs (interp/exe
	 * region runs below the first writable PT_LOAD page), captured
	 * post-D20-patch at exec commit. The per-exec/exit/pressure
	 * census re-hashes every live conn's watched runs; a
	 * divergence names the run whose loaded text was rewritten —
	 * the zeroed-ld.so-page class that killed /bin/login. gen
	 * pins the entry to the run's handout epoch so a recycled run
	 * never false-fires; refs==0 entries are skipped (unmapped).
	 * Fork children inherit the array (same runs/gen/hashes — the
	 * writer-hunt follow-up: forked helpers were invisible at
	 * death). */
	unsigned long long imgw_run[UML_NT_IMGWATCH_MAX];
	unsigned long long imgw_gen[UML_NT_IMGWATCH_MAX];
	unsigned long long imgw_hash[UML_NT_IMGWATCH_MAX];
	/* Full-run FNV (every qword) captured once at exec — the cheap
	 * 16-sample imgw_hash can miss a write between samples; the
	 * death-time verdict uses this one (rf pair 40064950549/590:
	 * the interp run held sigcontext-shaped bytes at 0xb560). */
	unsigned long long imgw_full[UML_NT_IMGWATCH_MAX];
	int imgw_n;
	/* M5.6a writer-hunt follow-up: the park-time round-robin full
	 * hash (one image run per trap park) — the first park after a
	 * rewrite names the round (last_nr/last_ret/trap rip) that did
	 * it. imgw_div marks a run already reported. */
	unsigned int imgw_rr;
	unsigned char imgw_div[UML_NT_IMGWATCH_MAX];
	/* M5.6a writer-hunt follow-up: the wild-rsp witness — the last
	 * real trap's rip/rsp, so the first trap whose rsp lands in an
	 * image run names the interval that corrupted it ([rsp-image],
	 * stub_ctl.c). */
	unsigned long long last_trap_rip;
	unsigned long long last_trap_rsp;
	int last_trap_valid;
	/* M5.6a login-depth follow-up (to-shelley 148-UPDATE 9/10): the
	 * exec's AT_RANDOM bytes + the TLS guard probe. glibc derives
	 * fs:0x28 (stack canary) from bytes 0..7 and fs:0x30 (pointer
	 * guard) from bytes 8..15; a guard that changes between setjmp
	 * and longjmp demangles a jmp_buf into a foreign pointer (the
	 * wild-stack pivot class). Every real trap re-reads fs:0x30 and
	 * compares it with the first sight ([guard-init]/[guard-change],
	 * stub_ctl.c); the fire also re-checks the TCB against these
	 * bytes (uml_nt_guard_tcb_check). auxv_rand_valid = an exec
	 * filled them. kzalloc init = unseen/0. */
	unsigned char auxv_rand[16];
	int auxv_rand_valid;
	unsigned long long guard_init;
	unsigned long long guard_canary;
	int guard_seen;
	unsigned int guard_changes;
	/* The full previous-stack-run dump fires once per conn (the
	 * first wild-rsp trap): the catch frame the pivot restored lives
	 * above the previous rsp and is intact — the raw 64 KiB lets the
	 * offline scan try every guard/candidate without another boot. */
	int stack_run_dumped;
	/* The same one-shot for the text-stack frames themselves: at the
	 * first wild fire, everything above the pivot rsp is the caller
	 * chain the guest built on the image run. */
	int wild_text_dumped;
	/* M5.6a writer-hunt follow-up: the resume-boundary audit. The
	 * value the kernel EXPECTED the stub to resume at after the
	 * previous real trap round; the stub publishes its actual
	 * d->resume_rip, and the next trap compares them ([resume-
	 * diverge], stub_ctl.c). Covers syscall rounds too — the old
	 * check only watched faults. */
	unsigned long long exp_resume_rip;
	int exp_resume_valid;
	/* M5.6a login-depth follow-up (Shelley 149 [resume-regs]) — see
	 * struct uml_nt_rres_rec. res_trap_* hold the LAST real trap's
	 * capture (op rounds never touch d->regs, so the trap capture
	 * stays the round's origin until the guest resumes); res_last is
	 * the answer released after it. res_chk_* carry the rsp the stub
	 * must restore, compared against its own d->resume_rsp at the
	 * next real trap. kzalloc-zeroed: no init needed. */
	struct uml_nt_rres_rec res_ring[UML_NT_RRES_RING];
	unsigned int res_ring_next;
	unsigned int res_ring_n;
	struct uml_nt_rres_rec res_last;
	int res_last_valid;
	unsigned long long res_trap_rip;
	unsigned long long res_trap_rsp;
	int res_trap_valid;
	unsigned long long res_chk_rsp;
	int res_chk_valid;
	unsigned int res_wild_n;
	unsigned int res_rewrite_n;
	unsigned int res_applied_bad;
	unsigned int res_seen;
	/* M5.6a [pivot trace] (Shelley 149's verdict: the resume carried
	 * the trap's own rsp, so the pivot is guest code): a TF
	 * single-step trace of the interval after a successful close(3)
	 * on a login conn. tf_left = steps still allowed, the ring keeps
	 * the last few steps so the pivot line can show the call site.
	 * The binary name gates the trace to the victim class (the
	 * login NSS/dlopen path) — a whole-boot TF trace of every close
	 * would cost the boot its margin. */
	char exec_path[UML_NT_EXEC_PATH_MAX];
	unsigned int tf_left;
	unsigned int tf_used;
	unsigned int tf_arms;
	unsigned long long tf_prev_rsp, tf_prev_rip;
	int tf_prev_valid;
	struct uml_nt_rres_rec tf_ring[UML_NT_TF_RING];
	unsigned int tf_rr;
	unsigned int tf_n;
	/* M5.6a [pivot-sample]: armed at the same close(3) answer the TF
	 * trace used; a burst runs right after the release and stops the
	 * moment the next round is published. smp_prev_* keep the last
	 * sample so a hit can name the instruction and the state that
	 * produced it. */
	unsigned int smp_left;
	unsigned int smp_used;
	unsigned int smp_arms;
	unsigned int smp_n;
	unsigned long long smp_prev_rip, smp_prev_rsp, smp_prev_rbp;
	unsigned long long smp_prev_rdi, smp_prev_rsi, smp_prev_rbx;
	int smp_prev_valid;
	unsigned int smp_in_text;
	/* GetThreadContext target: 0x4d0 bytes (x64 CONTEXT), 16-aligned.
	 * Per-conn because two kernel tasks may serve two stubs at once —
	 * a shared static buffer would hand one conn's registers to the
	 * other's log. */
	unsigned char smp_ctx[0x4d0] __attribute__((aligned(16)));
	/* D27 lazy file regions (see struct uml_nt_lazy_region). Cloned
	 * on fork (a child's first touch materializes into its own mm),
	 * dropped at mmctx destroy. */
	struct uml_nt_lazy_region lazy[UML_NT_LAZY_MAX];
};

/* M5.6a writer-hunt follow-up (stub_ctl.c): re-hash the run the
 * victim died on against the post-load fingerprint, at death. */
void uml_nt_imgwatch_death_check(struct uml_nt_stub_conn *c,
				 unsigned long long run);
/* 1 when `run` is one of the conn's captured image runs. */
int uml_nt_imgwatch_is_image(struct uml_nt_stub_conn *c,
			     unsigned long long run);
/* The park-time round-robin full-hash check (one run per call). */
void uml_nt_imgwatch_park_check(struct uml_nt_stub_conn *c);

/* D27: materialize the faulting run from the file. 1 = handled (the
 * plan carries the MAP op; the caller resumes), 0 = not a lazy
 * address (the normal fault path decides), -1 = materialization
 * failed (the plan is set to kill). */
int uml_nt_lazy_fault(struct uml_nt_stub_conn *c, unsigned long long va,
		      unsigned type);
/* D27: eagerly materialize + unregister every lazy region overlapping
 * [start, end) — the structural-op fallback. 0 = ok, -1 = refused
 * (plan capacity / alloc / read). */
int uml_nt_lazy_eager(struct uml_nt_stub_conn *c, unsigned long long start,
		      unsigned long long end);
/* D27: does [start, end) overlap a lazy region? */
int uml_nt_lazy_overlap(struct uml_nt_stub_conn *c, unsigned long long start,
			unsigned long long end);
/* D27 fork/exit lifetime. clone returns 0 or -1 (refusal — the fork
 * fails loud rather than leave a child with unmapped regions). */
int uml_nt_lazy_clone(struct uml_nt_stub_conn *child,
		      struct uml_nt_stub_conn *parent);
void uml_nt_lazy_drop(struct uml_nt_stub_conn *c);
/* D28 instrument: live deferred regions + their file/touched run
 * totals (the census prints the ratio the lazy win quantifies). */
void uml_nt_lazy_stats(int *regions, unsigned long long *file_runs,
		       unsigned long long *touched);

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

/* M5.6a [pivot trace]: record the path being exec'd (sys_execve, right
 * before kernel_execve) so the conn that birth creates names its
 * binary — the TF trace arms only for the login class, and every
 * pivot line can say WHICH binary pivoted. Fork children inherit the
 * parent's name (same binary). */
void uml_nt_exec_path_set(const char *path);
/* 1 when the conn's binary is the login class (basename "login"). */
int uml_nt_conn_is_login(const struct uml_nt_stub_conn *c);

/* M5.6a [pivot-sample]: one sampling burst of the conn's RUNNING
 * stub thread - called by the pump right after the answer release.
 * Returns the number of samples taken. */
unsigned int uml_nt_sample_burst(struct uml_nt_stub_conn *c);

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
 * stub. POC conns never call this (no task, no signals).
 * Returns 1 when the verbatim push happened (the kernel's exact resume
 * target is then regs->gp.ip — the resume audit uses it). */
int uml_nt_signal_check(struct uml_nt_stub_conn *c);

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

/* K6 (M5.6a, cowcopy-race-class-fix, dl26 37539992560): the
 * release-set completeness pass — call at every PRIME site (the
 * fault repair's prime, the syscall tail, the pump-side signal
 * delivery) before op 0 issues. Augments c->plan with the COMPLETE
 * per-view release set for every range the plan's UNMAPs release
 * (each release at the stranded view's OWN base — the ledger is
 * the enumeration), then ARMS the stream (plan_next = 0,
 * plan_left = n_ops) so every queued op streams even when the
 * round queued only uaccess fixup ops (the eaten-swap class: ops
 * queued without arming never streamed, and the whole table<->view
 * swap silently never applied). Returns 0, or -1 with the conn
 * already KILLED loud (release-set overflow — a dropped release is
 * the stranding class itself; the D22/D25 invariant is never left
 * to chance). */
int uml_nt_view_release_complete(struct uml_nt_stub_conn *c);

/* D26 (to-shelley 144): the single deferred-copy execution entry —
 * clears copy_pend_kind first, then dispatches on it (1 = the fault
 * COW repair, 2 = the brk re-home). Called by the drain hook, the
 * MAP-hold gate, the drain-end orphan fail-safe, and INLINE at the
 * decision when the src had no sharer (refs<=1). `when` tags the
 * provenance line ("inline"/"deferred"/"maphold"/"orphan"/"double").
 * Returns 0, or -1 with the conn already KILLed loud. */
int uml_nt_copy_pend_exec(struct uml_nt_stub_conn *c, const char *when);

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

/* K6 [flatwr] (M5.6a, feature flatwrite-retire-witness): the kernel
 * flat-write staleness witness — candidate (b) of the 139a dead-end
 * (a kernel-side flat write of guest content through a translation
 * OLDER than the current table: the store lands in an abandoned
 * source run, the dl26 content shape). uml_nt_flatwr_check is the
 * SITE hook: `off`/`gen_old` are the (run, gen) captured at
 * TRANSLATE time; the check compares them with the phys gen AND the
 * CURRENT table translate of `va` (run-granular; tbl_expect < 0 or
 * va == 0 = gen-only) AT WRITE TIME and records a mismatch into a
 * small ring — bookkeeping only, never printed at the site.
 * uml_nt_flatwr_report runs at syscall parks only (the placement
 * rule) and drains the ring. */
void uml_nt_flatwr_check(struct uml_nt_stub_conn *c, int site,
			 unsigned long long va,
			 unsigned long long len,
			 unsigned long long off,
			 unsigned long long gen_old,
			 long long tbl_expect);
void uml_nt_flatwr_report(struct uml_nt_stub_conn *c);

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
