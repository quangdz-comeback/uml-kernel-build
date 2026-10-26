/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub_nt.h — uml-nt stub protocol (kernel ↔ stub.exe shared memory).
 *
 * Upstream 6.18 seccomp stub (arch/um/include/shared/skas/stub-data.h)
 * synchronizes via a futex inside stub_data plus a unix socket for FD
 * passing; both are same-host-clone tricks that do not exist across
 * real processes (D3: stub.exe is a separate PE process, and
 * WaitOnAddress/NtAlertThreadByThreadId are same-process only —
 * verified M0/S2). The NT protocol replaces them with:
 *
 *   - two auto-reset event handles, inherited by the stub and passed
 *     by VALUE on its command line (S5 bootstrap pattern);
 *   - a monotonic request sequence (Interlocked64 on the shared
 *     section — cross-process coherent, S2) so a command can never be
 *     executed twice (M0 pitfall 4.4: dedupe by monotonic id).
 *
 * One instance of `struct uml_nt_stub_data` lives in its own 64 KiB
 * pagefile section per stub (the stub_data analogue). The kernel owns
 * the section + events; it writes the bootstrap block before
 * ResumeThread.
 *
 * This header is included by BOTH the kernel ELF (freestanding, no
 * host headers) and stub.exe (mingw PE, windows.h available) — same
 * dual-mode pattern as ntabi.h. Layout drift between the two sides
 * fails loudly at handshake (magic/version check).
 */
#ifndef __UML_STUB_NT_H
#define __UML_STUB_NT_H

#ifdef _WIN64
#include <windows.h>
#define UML_STUB_CC /* ms ABI is the default under mingw/PE */
typedef unsigned int u32_nt;
typedef unsigned long long u64_nt;
typedef long long s64_nt;
#else
#define UML_STUB_CC __attribute__((ms_abi))
typedef unsigned int u32_nt;
typedef unsigned long long u64_nt;
typedef long long s64_nt;
#endif

/* "USTB". */
#define UML_STUB_MAGIC   0x42545355u
#define UML_STUB_VERSION 6u /* v6: + xstate FP round-trip (S4d) */
/* Section size (also the map granularity guard). */
#define UML_STUB_SECTION_SIZE 0x10000u

/* Bootstrap block offset: the first cache line of the section. The
 * kernel fills it before ResumeThread; the stub maps the section and
 * validates it before doing anything else. */
#define UML_STUB_BOOT_OFFSET 0

/* Requests (stub → kernel, slot.cmd). The kernel dispatches syscalls
 * on regs.rax (upstream parity — the cmd only classifies the trap);
 * faults carry their own fault_addr/fault_type fields. */
#define UML_STUB_CMD_SYSCALL   1u /* ud2 trap: guest syscall (v1 name
				   * was WRITE — misleading, the kernel
				   * never dispatched on it) */
#define UML_STUB_CMD_EXIT      2u /* reserved numbering; the halt flag
				   * is the real transport (M2.2) */
#define UML_STUB_CMD_FAULT     3u /* AV in guest code → fault round-trip */
#define UML_STUB_CMD_PROT_DONE 4u /* result of the last ACTION_* (retval) */
#define UML_STUB_CMD_INIT      5u /* first request: stream the initial
				   * per-VMA map plan before guest entry */

/* Answers (kernel → stub, slot.action). */
#define UML_STUB_ACTION_NONE 0u /* handled — resume the guest */
#define UML_STUB_ACTION_PROT 1u /* stub: VirtualProtect(page, prot) */
#define UML_STUB_ACTION_KILL 2u /* fatal: park, kernel terminates us */
#define UML_STUB_ACTION_MAP  3u /* stub: map section view [map_va,
				 * map_len) from offset map_off with
				 * map_prot (per-VMA view, M3 model) */
#define UML_STUB_ACTION_UNMAP 4u /* stub: unmap [map_va, map_len) */

/* Guest virtual address space, M2 edition: the stub maps the whole
 * physmem section at ram_base and the static init runs in that view,
 * so guest VA == ram_base + guest physical offset. M3's VMA manager
 * replaces this with per-VMA views at real guest VAs. */
#define UML_STUB_RAM_BASE 0x60000000ULL /* == launcher GUEST_RAM_VA */

/*
 * GP register snapshot at the trap (stub → kernel), explicit-field —
 * no layout tricks: both sides write every member by name.
 */
struct uml_nt_gp_regs {
	unsigned long long rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
			   r8, r9, r10, r11, r12, r13, r14, r15,
			   rip, rflags;
};

/*
 * One command slot. M2 has a single outstanding request at a time
 * (the whole stub blocks until the kernel answers); the seq makes the
 * slot safe to reuse in order and leaves room for batching later.
 */
struct uml_nt_stub_data {
	/* -- cache line 0: handshake + protocol state ---------------- */
	u32_nt magic;   /* UML_STUB_MAGIC, written by kernel */
	u32_nt version; /* UML_STUB_VERSION */
	/* Monotonic request id, bumped (Interlocked) by the stub when
	 * it publishes a command. Kernel waits for seq > done_seq,
	 * answers, then bumps done_seq. 0 = nothing yet. */
	volatile u64_nt req_seq;
	volatile u64_nt done_seq;
	u32_nt cmd;      /* UML_STUB_CMD_* */
	u32_nt err;      /* kernel → stub: 0 = ok, else -errno-style */
	unsigned long long args[6]; /* syscall args (guest VA space) */
	unsigned long long retval;  /* kernel → stub: syscall return */
	u32_nt halt;                /* kernel → stub: 1 = ExitProcess now */
	struct uml_nt_gp_regs regs; /* full GP snapshot at the trap */

	/* -- bootstrap (written by kernel pre-ResumeThread) ---------- */
	/* M3 model: the stub has NO flat physmem view — its address
	 * space is built by per-VMA views streamed over CMD_INIT
	 * before entry. entry_va/stack_va are real guest VAs (the
	 * probe uses RAM_BASE + phys offset, identity by convention).
	 * init_regs are applied before the jump — fork hands the
	 * child the parent's register snapshot with rax = 0. The
	 * stub_data section itself maps at the FIXED va 0x10000000
	 * (below the guest span) so the NT allocator never lands
	 * inside [ram_base, ram_base+ram_size). */
	unsigned long long ram_base;  /* guest VA span base (fault filter) */
	unsigned long long ram_size;  /* guest VA span bytes */
	unsigned long long entry_va;  /* guest entry VA */
	unsigned long long stack_va;  /* guest stack top VA */
	struct uml_nt_gp_regs init_regs; /* applied pre-jump */

	/* -- bookkeeping (kernel-only use, kept here for parity) ----- */
	u32_nt exit_code; /* observed via GetExitCodeProcess */
	u32_nt pid;       /* stub process id (kernel-side record) */

	/* -- v2: page-fault round-trip (M3.1) ------------------------ */
	/* Filled by the stub for CMD_FAULT: ExceptionInformation[0] is
	 * the access class (0=read, 1=write, 8=DEP execute),
	 * [1] the faulting guest VA. The kernel answers with an
	 * action; the stub executes it and reports via CMD_PROT_DONE
	 * (retval = 1 ok / 0 failed), then resumes on ACTION_NONE. */
	unsigned long long fault_addr;
	u32_nt fault_type;
	u32_nt action; /* UML_STUB_ACTION_* */
	u32_nt prot;   /* ACTION_PROT: NT PAGE_* constant */
	u32_nt _pad_fault;

	/* -- v3: ACTION_MAP/UNMAP/PROT operands ---------------------- */
	/* One op per round-trip (the slot is single-outstanding by
	 * design — M3.2). MAP: [map_va, map_va+map_len) is a fresh
	 * view of the physmem section from offset map_off (64K
	 * aligned) with map_prot; UNMAP releases that range; PROT
	 * protects [map_va, map_va+map_len) to prot (fault fix-ups
	 * and INIT-plan guard pages alike — not only fault_addr). */
	u32_nt map_prot;
	u32_nt _pad_map;
	unsigned long long map_va;
	unsigned long long map_len;
	unsigned long long map_off;

	/* -- v5: guest TLS base (D18, S4c2) -------------------------- */
	/* arch_prctl(ARCH_SET_FS) records the pointer kernel-side (conn
	 * fs_base) and publishes it here; the stub re-applies it with
	 * wrfsbase at every resume into guest code and repairs
	 * fs-prefixed faults mid-run. Windows scheduling does not
	 * preserve a user-set FS base (probes/fsgsbase, S4c evidence:
	 * wrfsbase ok, VEH round-trip preserves, scheduling loses) —
	 * upstream never re-applies because Linux/Ptrace keeps the
	 * base in the task regs. */
	unsigned long long fs_base;

	/* -- v6: FP/XSTATE round-trip (S4d) -------------------------- */
	/* Upstream UML syncs the guest FP state at EVERY trap:
	 * get_fp_registers(pid, regs->fp) after each stop,
	 * put_fp_registers before each continue (os-Linux/skas/
	 * process.c). Signals copy regs->fp into the sigframe
	 * (copy_sc_to_user) and sigreturn copies it back. The NT
	 * analogue: the stub snapshots the at-exception FP state into
	 * xstate[] at every trap, and applies xstate[] back at resume
	 * when the kernel flags a restore. Format = XSAVE_FORMAT
	 * (FXSAVE, 512 bytes) — exactly the x64 CONTEXT.FloatSave
	 * layout, so capture is a plain copy (probes/xstate, S4d
	 * evidence: the exception CONTEXT carries the at-exception
	 * XMM state under CONTEXT_FLOATING_POINT, the dispatcher
	 * clobbers the LIVE registers before the handler runs, and a
	 * FloatSave write-back sticks through
	 * EXCEPTION_CONTINUE_EXECUTION). 512 bytes covers x87 + SSE;
	 * AVX/YMM state is not in the x64 CONTEXT (extended-context
	 * API only) — a documented fidelity limit, guest musl/busybox
	 * code is SSE-only. */
#define UML_STUB_XS_CAPTURED 0x1u /* stub: xstate[] holds the trap FP state */
#define UML_STUB_XS_RESTORE  0x2u /* kernel: apply xstate[] at resume */
#define UML_STUB_XS_VERBATIM 0x4u /* kernel (syscall resume): d->regs.rip is
				   * the EXACT resume target — no +2, no
				   * rax=retval override (a signal handler
				   * was installed over the trap regs) */
#define UML_STUB_XS_SIZE     512u /* XSAVE_FORMAT bytes */
	u32_nt xstate_flags;
	u32_nt _pad_xs;
	unsigned char xstate[UML_STUB_XS_SIZE]
		__attribute__((aligned(16)));

	/* -- v7: MAP backing canary (M5.6a, referee 37140517824) ------- */
	/* verify_prot proves a fresh view's PROTECTION, never its
	 * BACKING: a MAP carrying a stale run offset verifies green and
	 * the guest then reads/writes the wrong run — the lost-tcache-
	 * store shape (a tcache_put's e->next store vanished from every
	 * run in physmem). For a writable MAP the kernel now plants a
	 * nonce flat-side at the VMA TABLE's run for the view's tail-8
	 * and ships it here; the stub reads the tail-8 through the fresh
	 * view into mapcanary_got; the kernel compares at PROTDONE and
	 * restores the original qword. Mismatch = the view is not backed
	 * by the run the VMA table owns — the divergence named at the
	 * op that created it. 0 = no canary this op (RO maps, short
	 * maps, shared-run targets: no shared run is ever clobbered). */
	unsigned long long mapcanary;
	unsigned long long mapcanary_got;

	/* -- v8: the resume witness (M5.6a, referee 37184498411) --- */
	/* The stub records the FINAL guest resume target at every
	 * answer return (the trampoline target when wrapped). The
	 * kernel's [replay-lost] fire prints it against the faulting
	 * rip: equal = the store should have re-executed; anything
	 * else names the exact skip path (signal handler entry,
	 * rip+2, ...). */
	unsigned long long resume_rip;

	/* -- v17: the resume RSP witness (M5.6a, Shelley 149) --------
	 * v8 published the resume TARGET, never the stack pointer the
	 * restore actually carried. The login-depth pivot's referee
	 * question is exactly that: after round close(3) (trap
	 * rsp=0x6005d258, clean) the next trap reports rsp=0x6001c228
	 * inside the interp text. Either the kernel's answer already
	 * rewrote rsp, or the stub's CONTEXT restore did not apply the
	 * value it was handed, or the guest pivoted on its own. The
	 * stub records the CONTEXT rsp it is about to return
	 * EXCEPTION_CONTINUE_EXECUTION with (after gp_to_context, the DR
	 * re-arm and the xstate restore — what Windows will really
	 * load); the kernel compares it with the rsp it put in d->regs
	 * at the answer. Equal + a clean answer rsp = the guest's own
	 * arithmetic (pivot in guest code); a mismatch names the
	 * restore, not the guest. */
	unsigned long long resume_rsp;

	/* -- v18: the TF single-step trace (M5.6a, Shelley 149) --------
	 * The [resume-regs] verdict (two referees, [40083772914] and
	 * [40083780256]) proved the answer carried the trap's OWN rsp
	 * after round close(3) and the stub restored exactly that — the
	 * pivot is guest code in the interval close(3) return →
	 * fstatat trap. This is the only instrument that can name the
	 * instruction: nonzero makes the stub raise EFLAGS.TF at every
	 * resume (fault trampoline, so the TLS base is live) and report
	 * each #DB as cmd FAULT with fault_type = UML_NT_FAULT_STEP; the
	 * kernel logs the step and decrements. 0 = not tracing. TF is
	 * never visible to the guest: the capture and the resume both
	 * strip it (ss_model.h), the trampoline raises it itself. */
	u32_nt tf_trace;
	/* Why the stub stopped tracing (0 = still tracing / never armed):
	 * 1 = the traced instruction faulted on a wiped TLS base (the D18
	 * fs fixup re-executes it with the base live, but TF is spent —
	 * the interval needs another arm). Read by the kernel's trace-end
	 * line so an early end is never silent. */
	u32_nt tf_stop;

	/* -- v9: the view readback (M5.6a, referee 37197703025) ------- */
	/* The twin scan stayed ambiguous across same-VA-space fork
	 * children (an inherited tcache copy at the same in-run offset
	 * is indistinguishable from a stale view's landing). Settle it
	 * directly: the kernel sets viewprobe_addr to the fault VA when
	 * arming replay-check; the stub, after a PROTECT op applies,
	 * reads the qword THROUGH ITS OWN VIEW into viewprobe_got. The
	 * kernel compares with the VMA-table-side value: a mismatch is
	 * the wrong-backed view itself, no scanning. */
	unsigned long long viewprobe_addr;
	unsigned long long viewprobe_got;

	/* -- v10: the replay single-step (M5.6a) -------------------- */
	/* replay-check proved the repair's view is correct (viewprobe)
	 * and the resume targets the store (resume_rip), yet the qword
	 * reads back as the pre-fault value one park later. Between
	 * those witnesses the store either never ran or was overwritten
	 * back. The single-step settles the order: nonzero ss_page makes
	 * the fault resume trap exactly once after the replayed store;
	 * the stub re-arms the page NOACCESS, so the next write to the
	 * page faults into the kernel's cowtrap with its rip. */
	unsigned long long ss_page;
	/* The fault VA (for the post-store readback) and its result.
	 * At the real #DB (rip past the store) the stub reads ss_va
	 * through ITS OWN view into ss_got. The kernel sets ss_got to
	 * ~0 at the arm; at the verify: ss_got==~0 means the #DB never
	 * came (the store never ran); ss_got==want while the table run
	 * lacks want is the wrong-backed twin proven at the qword —
	 * content-equality at probe time can no longer fake it (the
	 * view-ok content-match hole, referee 37201936990: a stale view
	 * backing an old COW copy of the same page reads identical
	 * bytes). */
	unsigned long long ss_va;
	unsigned long long ss_got;
	/* VirtualQuery(ss_va).AllocationBase captured at the same #DB:
	 * the base VA of the view that actually backs the fault address.
	 * Matched against the conn's MAP-op history it names the exact
	 * stream that left the wrong-backed view in place. */
	unsigned long long ss_viewbase;
	/* ss-regs (v11): the fault's full GP file, snapshotted by the
	 * kernel at the arm. The post-store #DB compares the live
	 * context against it: a pure store changes NO register, and
	 * the trampoline touches only r11 (saved/restored), so ANY
	 * mismatch is the register-tear class — the guest computing
	 * with wrong inputs (a store to a computed-and-wrong VA never
	 * faults and is invisible to every page witness). ss_regdiff
	 * = the mismatch bitmask, ss_reglive[] = the live values. */
	unsigned long long ss_regs[16];
	unsigned long long ss_rflags;
	unsigned long long ss_regdiff;
	unsigned long long ss_reglive[16];
	/* The covering region's Type (MEM_IMAGE/MAPPED/PRIVATE) and
	 * RegionSize at the same #DB: referee 37209966901 proved the
	 * store lands view-side yet its value exists in NO physmem run —
	 * the covering view may not be the physmem section at all (a
	 * MEM_PRIVATE allocation squatting on the guest VA). */
	unsigned long long ss_vtype;
	unsigned long long ss_vrsize;
	/* The kernel plants ss_flatoff = the fault VA's byte offset in
	 * the physmem section per the VMA table; the stub's #DB reads
	 * flat_view[ss_flatoff] into ss_flat. view vs flat at the same
	 * instant: divergent = the covering view is not the section. */
	unsigned long long ss_flatoff;
	unsigned long long ss_flat;
	/* The same-conn stale-view census (M5.6a, oracle k3 pass 2):
	 * at the post-store #DB the stub VirtualQuery-walks the whole
	 * guest span and dumps every MEM_MAPPED region here; the
	 * kernel's fire checks each against the conn's VMA table — a
	 * region no VMA admits is a stale view (a dropped UNMAP in the
	 * cross-round plan stream), the last channel every per-view
	 * witness is blind to. */
	unsigned int ss_ndump;
	unsigned long long ss_dump[48][3]; /* base, len, prot|type */
	/* -- v12: the tctrip RO re-arm (M5.6a) -------------------------
	 * tctrip-emulate covers the five tcache-struct store shapes;
	 * a CHUNK-data write on the same page (heap page 0 holds the
	 * first ~3.5KB of chunks past the struct) matches none of
	 * them. For those the kernel repairs normally and sets
	 * ss_rearm_ro = the armed page: the post-store #DB re-applies
	 * READONLY to it before continuing — the free-run hole shrinks
	 * from "until the next serve round" to "one store". 0 = none. */
	unsigned long long ss_rearm_ro;
	/* Shelley 166: the protection the re-arm must put back — the
	 * VMA's, not a constant. Restoring PAGE_READONLY on a text page
	 * makes the next fetch fault, which is indistinguishable from a
	 * lost resume. 0 means "legacy: PAGE_READONLY". */
	unsigned ss_rearm_prot;
	/* [prot-truth]: what Windows ACTUALLY has at the two pages that
	 * matter when a fault round arrives — the resume target and the
	 * fs trampoline — against what the ledger claims. */
	unsigned fault_page_prot, fault_page_state;
	/* 1 = VirtualQuery answered. Without this the "actual=0x0" of a
	 * FAILED query reads as "Windows says the page is not executable"
	 * — label bug #8, referee 40253591749. */
	unsigned fault_page_ok, tramp_page_ok;
	/* Shelley 168: the committed bottom of the run the TRAP's rsp sits
	 * in, straight from VirtualQuery. The kernel's own VMA scan did not
	 * match (referee 40262318084: [stack-pre] never fired while
	 * headroom was 0x258), and Windows is the authority on what is
	 * committed — the probe publishes it every round. */
	unsigned long long stack_bottom;
	/* the top of that same committed run, and the reservation base —
	 * the kernel's own stack_top/stack_limit are 0 for a conn whose
	 * mm never went through the ELF image path (referee 40266736890:
	 * NO GROW top=0x0 limit=0x0), and the stub is the side that can
	 * ask Windows. */
	unsigned long long stack_top_hint, stack_alloc_hint;
	unsigned tramp_page_prot, tramp_page_state;
	unsigned long long prot_truth_bad; /* ledger exec but actual is not */
	/* the last protection operation this run performed, for decoding
	 * a downgrade offline */
	unsigned long long prot_op_va, prot_op_prot, prot_op_seq;
	/* Shelley 171 [map-truth]: every run-backed MAP must leave Windows
	 * holding the whole run the ledger claims. */
	unsigned long long map_truth_ok, map_truth_bad;
	/* Shelley 172: the CONTEXT we actually hand the dispatcher back —
	 * Rip/Rsp/EFlags and the whole debug state — ring 8, dumped at
	 * death. The question it answers: what distinguishes the 449 #DB
	 * rounds that survive from the one that does not. Alpha = we keep
	 * the breakpoint armed at the very rip we are resuming to (it
	 * would fire again at once); beta = the returned EFlags still has
	 * TF set or RF clear, so the kernel-side resume raises the #DB
	 * itself before user mode can dispatch.
	 */
	/* Shelley 173 (1)/(2): EVERY VEH entry, stamped at the FIRST line of
	 * the handler — before anything can overwrite d->cmd or done_seq.
	 * The index is taken atomically so two nested entries can never
	 * share a slot (a shared slot would hide data, not just a label).
	 * If the dying #DB is followed by a fault that appears here and
	 * nowhere else, that fault never reached a handler we own — it is a
	 * nested exception outside our coverage, and the fix is a catch-all
	 * at dispatcher level. */
	struct uml_nt_entry_ring {
		unsigned long long n, seq, cmd, code, rip, rsp;
		unsigned long long in_body, slot;
	} entry_ring[16];
	volatile long entry_ring_at; /* InterlockedIncrement */
	unsigned long long ret_stamped_n; /* Shelley 174: one stamp per entry */
	/* Shelley 175: the explicit NtContinue. Success does not return; if
	 * it does, the NTSTATUS IS the answer we could never read before.
	 * Two shapes are recorded: how many calls, how many came back, and
	 * the last status + the context it refused. */
	/* 1 = this conn resumes through NtContinue (set by the kernel for
	 * the login conn only). The unconditional version broke the native
	 * boot test outright — "console: stdin status c000014b
	 * (class=fatal)" — so the discriminator is scoped to the conn whose
	 * death we are chasing, and every other round keeps the proven
	 * path. */
	unsigned ntc_enable;
	unsigned long long ntc_calls, ntc_returned, ntc_last_status;
	unsigned long long ntc_rip, ntc_rsp, ntc_dr7, ntc_flags;
	struct uml_nt_ret_ring {
		unsigned long long seq, rip, rsp, eflags, cs, ss;
		unsigned long long dr0, dr1, dr2, dr3, dr6, dr7, ctx_flags;
		unsigned long long cmd, action, resuming; /* resuming=1 nac */
	} ret_ring[8];
	unsigned ret_ring_at;
	/* -- v13: DR watchpoints on the tcache entries[] (M5.6a) ------
	 * Page traps can't isolate the tcache struct from its page-mate
	 * chunks (the dl6 storm: 38k faults on ONE hot qword, 19.4M
	 * log lines, boot starved). Hardware watchpoints can: the
	 * kernel fills dr_watch[0..3] with the watched qword VAs
	 * (entries[0..3] = heap+0x90+i*8; 0 = slot off) and
	 * dr_heap_lo/hi with the conn's heap span; the stub loads
	 * Dr0-3/Dr7 at every resume. A write hit (#DB, Dr6.Bn) lands
	 * AFTER the store; the stub reads the qword: 0 or heap-shaped
	 * = legit tcache_put/get churn (silent continue, no
	 * round-trip); anything else = the tear — reported as cmd
	 * FAULT with fault_type = UML_NT_FAULT_WATCHPT, the post-store
	 * rip in regs.rip. The store stays landed (native semantics;
	 * the witness observes, never alters). */
	unsigned long long dr_watch[4];
	unsigned long long dr_heap_lo, dr_heap_hi;
	/* -- v19: the EXECUTE breakpoint (M5.6a [pivot-dr]) -----------
	 * The sampler proved the pivot interval is ~1-2 us of guest
	 * time — far shorter than one SuspendThread/GetThreadContext
	 * probe (~10 us) — so sampling cannot land inside it. A DR
	 * EXECUTE breakpoint can: armed on the interp's
	 * _dl_find_dso_for_object entry (file offset 0xb490), it fires
	 * BEFORE the first instruction of every call, which is exactly
	 * the state the pivot hunt needs (rdi = the addr argument, and
	 * the caller's return address on the stack). dr_exec_mask = 1
	 * bit per slot: set = that slot is an execute breakpoint
	 * (Dr7 RW=00 LEN=00), clear = the v13 write watchpoint
	 * (RW=01 LEN=10). */
	u32_nt dr_exec_mask;
	u32_nt _pad_dr_exec;
	/* -- v20: the DR hit's OWN address (Shelley 152/153) ----------
	 * The v13 write-watch path published fault_addr = the armed slot
	 * VA, which is right only when the store lands exactly on it. A
	 * store that lands elsewhere in the 8-byte slot (or a write whose
	 * reported address differs) then mislabels both the value read
	 * and the code dumped around the store — referees
	 * 40118595476/40122644293 hit exactly that ambiguity (the dump
	 * around "the store" fell inside the module's PLT while the
	 * surrounding qwords were ld.so vfprintf arg-array slots).
	 * dr_hit_va = ExceptionInformation[1] (the address actually
	 * accessed), dr_hit_type = ExceptionInformation[0] (0 read /
	 * 1 write / 8 execute). fault_addr keeps its v13 meaning so the
	 * tcache watch is unchanged. */
	unsigned long long dr_hit_va;
	unsigned long long dr_hit_type;
	/* -- v14: the stray #DB ledger (M5.6a K7 slice D) --------------
	 * A #DB the replay window does not admit — nothing armed, or a
	 * rip neither inside the TF trampoline, at the store's door, nor
	 * one instruction past the store — used to fall through to the
	 * VEH's unowned path and kill the stub (0x80000004, silent:
	 * referees 39798056175/39809900440). Now the stub drops TF,
	 * abandons the arm, records the event here and continues; the
	 * kernel prints [ss-stray] when ss_stray_n moves (the rows name
	 * the path: rip, eflags, dr6, ss_page, the trampoline target,
	 * kind | code<<32). kind 0 = the stray #DB itself; kind 1 = a
	 * trap captured with EFLAGS.TF live (the leak's source: the
	 * kernel never sees that TF any more, this row names where it
	 * would have come from). ss_model.h is the classifier. */
	u32_nt ss_stray_n;
	u32_nt _pad_ss_stray;
	unsigned long long ss_stray[8][8];
	/* -- v15 (D28 follow-up, login-depth corruption): the unowned-
	 * exception record. report_unowned's 512-byte console line loses
	 * everything past its first 19 bytes at the death site ("stub:
	 * UNOWNED exce" — referees 39993301942 lazy?/40001382875), i.e.
	 * the exception code, the faulting VA and the op are invisible
	 * exactly where the next class lives (0xC0000096 PRIVILEGED_
	 * INSTRUCTION at login). The stub records the complete exception
	 * here BEFORE it dies; the kernel's "died silently" print reads
	 * it. unowned_seq written last: 0 = none, 1 = complete. */
	u32_nt unowned_code;
	u32_nt unowned_last_cmd;
	unsigned long long unowned_rip;
	unsigned long long unowned_rsp;
	unsigned long long unowned_op;   /* ExceptionInformation[0] */
	unsigned long long unowned_addr; /* ExceptionInformation[1] */
	unsigned long long unowned_seq;
	/* -- v16 (resume-boundary milestone): the state that produced
	 * the unowned exception, from the STUB's own view. v15 named
	 * the RIP; the byte-shifted-class investigation needs the
	 * register file (which pointer produced the entry), the 8
	 * bytes at that RIP as the stub actually sees them (0f 0b =
	 * laundered syscall site; foreign bytes = view/table
	 * divergence), and the top of the stack (a corrupted return
	 * address names the transfer). unowned_v16 written LAST. */
	unsigned long long unowned_regs[16]; /* rax rcx rdx rbx rsp rbp rsi
					      * rdi r8 r9 r10 r11 r12 r13
					      * r14 r15 */
	unsigned long long unowned_flags;
	unsigned long long unowned_insn;   /* [rip, rip+8), stub view */
	unsigned long long unowned_stk[16];/* [rsp, rsp+128), stub view */
	unsigned int unowned_insn_ok;
	unsigned int unowned_stk_n;        /* readable qwords captured */
	unsigned long long unowned_v16;
	/* v16 trap-site witness: the 8 bytes at THIS trap's RIP through
	 * the stub's own view, published on every accepted syscall/
	 * fault round. The kernel diffs them against its table view at
	 * the same VA — a mismatch is a stale view at the exact place
	 * the guest executed. */
	unsigned long long trap_insn;
	unsigned int trap_insn_ok;
	unsigned int trap_pad;
	/* -- v21: the UNHANDLED-exception record (M5.6a STOP-POINT 155,
	 * Shelley's witness-first ruling). "died silently (0xC0000005)"
	 * names no address: the AV that killed the stub never reached
	 * the VEH's unowned path. A SetUnhandledExceptionFilter hook
	 * (last chance, any thread, including an AV inside a handler)
	 * publishes the raw facts here and the KERNEL classifies them,
	 * because only the kernel has the VMA tree and the view ledger:
	 *   (a) faulting VA inside a guest VMA but no stub view
	 *       -> VIEW-HOLE, with the VMA's run/prot/gen and the
	 *          ledger/window occupancy,
	 *   (b) outside every VMA   -> a guest garbage pointer,
	 *   (c) outside the guest span -> a real stub code bug.
	 * seq is written LAST. */
	volatile u64_nt unhandled_seq;
	unsigned long long unhandled_code;      /* NTSTATUS of the AV */
	unsigned long long unhandled_type;      /* ExceptionInformation[0] */
	unsigned long long unhandled_addr;      /* ExceptionInformation[1] */
	unsigned long long unhandled_rip;       /* STUB-side rip */
	unsigned long long unhandled_rsp;       /* STUB-side rsp */
	unsigned long long unhandled_insn;      /* 16 bytes at that rip */
	unsigned long long unhandled_insn2;
	unsigned long long unhandled_cmd;       /* the round in flight */
	unsigned long long unhandled_nr;        /* its syscall number */
	unsigned long long unhandled_args[4];   /* its first four args */
	unsigned long long unhandled_tid;
	unsigned long long unhandled_flags;
	/* The STUB's own stack, sampled on every published round: the
	 * death in 40147747626 leaves no exception record at all, which
	 * on Windows is what a stack exhausted enough to prevent the
	 * dispatcher from pushing a frame looks like (the process dies
	 * with the raw exception code and NO handler runs — not even
	 * SetUnhandledExceptionFilter). 0/0 = never sampled. */
	unsigned long long stub_sp;      /* rsp of the stub thread */
	unsigned long long stub_sp_lim;  /* TEB stack limit */
	unsigned long long stub_sp_base; /* TEB stack base */
	unsigned long long stub_sp_min;  /* lowest rsp seen */
	/* The dispatch-stack self-check, published so the KERNEL prints it
	 * (the stub's own stderr is not in the referee log): phase 1 =
	 * entered, 2 = thunk returned, 3 = disarmed (see veh_model.h). */
	unsigned long long veh_phase;
	unsigned long long veh_sc_sp_in;
	unsigned long long veh_sc_sp_out;
	unsigned long long veh_sc_sp_body;
	unsigned long long veh_sc_r10;
	unsigned long long veh_sc_r11;
	unsigned long long veh_sc_ret;
	unsigned long long veh_sc_want;
	unsigned long long veh_sc_buf;
	/* [crumbs] (Shelley 157 follow-up): where the stub was when it
	 * died, and whether the VEH saw anything at all. round_step walks
	 * the serve loop 1..6; veh_entries counts every VEH entry (normal
	 * and nested); unhandled_calls counts last-chance publishes. */
	unsigned long long round_step;
	unsigned long long veh_entries;
	unsigned long long unhandled_calls;
	/* [ctx-ring] (Shelley 158 step 1): the CONTEXT handed to
	 * KiUserExceptionDispatcher's continue path, last
	 * UML_NT_CTX_RING resumes, with the dispatcher's own
	 * CONTEXT_EX header numbers read back verbatim. If the death
	 * carries no exception record, this is the last thing WE
	 * pushed — the only evidence left. */
	struct uml_nt_ctx_ring {
		unsigned long long seq;
		unsigned long long step;	/* round_step at push */
		unsigned long long kind;	/* 0 syscall 1 fault 2 verbatim */
		unsigned long long rip, rsp, eflags, cs, ss, ctx_flags;
		unsigned long long mxcsr;
	unsigned long long grip; /* guest rip the stub resumes to */
	unsigned long long gsp;  /* guest rsp the stub resumes on */
	unsigned long long gseq; /* done_seq the stub read it under */
	unsigned long long gtgt; /* rip+2: where the trampoline jumps */
	unsigned long long hop_pre;  /* entered the fs hop */
	unsigned long long hop_post; /* cleared wrfsbase, about to jmp */
	unsigned long long ent_rsp;  /* rsp at guest entry (after the hop) */
	unsigned long long ent_fl;   /* rflags at guest entry */
	unsigned long long ent_id;   /* the round's done_seq at the hop */
		unsigned long long have_ex;
		unsigned long long all_size, all_area, all_off;
		unsigned long long leg_size, leg_area, leg_off;
		unsigned long long xsa_size, xsa_area, xsa_off;
		unsigned long long host_xcr0;	/* what this CPU can save */
		unsigned long long host_xs_max;	/* CPUID.0xD:0 sizes */
		unsigned long long host_xs_lo;
		unsigned long long ex_back;	/* bytes before the context */
	} ctx_ring[16];
	/* Shelley 167 (1)+(2): EVERY exception entry, not just the fault
	 * round. For an AV the access type ([0] = 0 read / 1 write / 8
	 * DEP-execute) and the faulting VA ([1]) are the two facts that
	 * separate a guest dereference from the hop jumping somewhere it
	 * should not; headroom_run/headroom_res are the stack question —
	 * rsp minus the bottom of the committed run it sits in, and minus
	 * the bottom of the whole reservation (which is a HOLE: unmapped).
	 * If the ntdll dispatcher has to build a frame with almost no
	 * committed page under rsp, it writes into that hole, takes a
	 * second AV on a thread with no handler, and dies exactly like
	 * this. */
	struct uml_nt_exc_ring {
		unsigned long long seq;
		unsigned long long code, i0, i1;
		unsigned long long rip, rsp, csp;
		unsigned long long headroom_run; /* rsp - committed bottom */
		unsigned long long headroom_res; /* rsp - reservation base */
		unsigned long long tgt, dtarget; /* tramp target vs probe va */
		unsigned long long fq_ok, fq_prot, fq_state;
	} exc_ring[16];
	unsigned exc_ring_at;
	unsigned long long ctx_ring_at;
	/* [xstate] (Shelley 158 step 2): what the OS wants for a CONTEXT
	 * with CONTEXT_XSTATE (InitializeContext: 1 ok / 2 failed / 0 no
	 * API), the mask it will honour, and how many resume paths we
	 * took with the claim dropped (cleared) or kept (kept). */
	unsigned long long xstate_api;
	unsigned long long xstate_want;
	unsigned long long xstate_mask;
	/* M5.6a A/B (Shelley 161 item 4, sharper than a sampler): the last
	 * hop between the answer and the guest is the stub's own
	 * fs_trampoline (wrfsbase + jmp *target) running on the GUEST
	 * stack. Everything before it is now measured clean — target
	 * patched, VMA exec, three rips equal — so the hop itself is what
	 * is left. 1 = kernel asks the stub to resume PLAIN (no
	 * trampoline), logging every resume that would have used it. */
	u32_nt fs_tramp_off;
	unsigned long long fs_tramp_skipped; /* resumes that would have used it */
	unsigned long long drex_hits; /* execute-breakpoint hits */
	/* Shelley 164 (3): the block is a ONE-slot register file. Every
	 * publish overwrites d->regs wholesale, so a register snapshot
	 * taken at answer time is only meaningful until the next one.
	 * The stub bumps this at every publish; the death dump compares
	 * it with the answer's copy and says STALE instead of reporting
	 * 17 "MOVED" registers that are simply the NEXT round's trap
	 * state (referee 40236214578 read exactly that way). */
	unsigned long long pub_seq;
	/* Shelley 165 (gamma): "did the dispatcher APPLY the context we
	 * handed back?" The stub never calls SetThreadContext — the VEH
	 * return is the apply — so the only honest witness is the NEXT
	 * entry's own ContextRecord compared with what we asked for.
	 * asked_* is stamped at the resume, got_* at the next entry, and
	 * the verdict ring keeps the last 16 rounds. */
	unsigned long long ask_rip, ask_rsp, ask_dr2, ask_dr7, ask_flags;
	unsigned long long ask_round;
	unsigned long long got_rip, got_rsp, got_dr2, got_dr7, got_flags;
	unsigned long long ctx_check_ok, ctx_check_bad;
	unsigned long long dr_mismatch; /* DR silently dropped by the OS */
	unsigned long long dr_applied; /* resumes that carried DR state */
	unsigned long long d20_guarded; /* answers whose rip held 0f 05 */
	unsigned long long xstate_cleared;
	unsigned long long xstate_kept;
	unsigned long long veh_sc_size;
};

#endif /* __UML_STUB_NT_H */
