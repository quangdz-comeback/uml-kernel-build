// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/process.c — the UML scheduler core, ported.
 * Upstream: linux v6.18.37 arch/um/os-Linux/skas/process.c
 *          (the setjmp/longjmp dispatcher half + the seccomp
 *          userspace loop, S2)
 *
 * UML 6.18 kernel tasks are STACKS, not host threads: every task has a
 * jmp_buf (switch_buf); scheduling = switch_threads(me, you) which
 * setjmp-saves the outgoing stack and longjmps into the incoming one.
 * start_idle_thread hosts the central dispatcher (initial_jmpbuf):
 * cold contexts are just {IP=handler, SP=stack_top} — new_thread fills
 * them, nothing is spawned. This is 100% host-thread agnostic, so the
 * NT port is a verbatim copy minus: set_handler(SIGWINCH) (D7 — no
 * signals), and the fatal_sigsegv path (os_dump_core instead).
 *
 * The userspace side (S2) mirrors upstream seccomp shape:
 *   init_new_context (mmctx.c, S1) spawned this mm's stub suspended;
 *   start_userspace = readiness (same call order as upstream);
 *   userspace(regs) = the per-task loop: interrupt_end → first round
 *   hands the conn its entry state and resumes the thread (the stub
 *   publishes CMD_INIT and the INIT plan streams back through the
 *   slot) → wait on THIS conn's evt_in (the D10 turnstile, per-conn —
 *   upstream blocks on the stub's futex/socket instead) → serve via
 *   uml_nt_pump_conn (the probe's machinery, one protocol) → pull
 *   the trap regs back → repeat. Syscall dispatch is the D16 surface
 *   for now; the upstream-parity handle_syscall path (sys_call_table
 *   + real VFS) lands with the task integration (S3+). The M3.7
 *   probe keeps its own service loop — two paths, one protocol.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <as-layout.h>
#include <kern_util.h>
#include <longjmp.h>
#include <mm_id.h>
#include <skas.h>
#include <deathsit_model.h>
#include <user.h>
#include <stub-panic.h>
#include <stub_nt.h>
#include <ss_model.h>
#include <prot_restore_model.h>
#include <regshape_model.h>
#include <syscall.h>
#include <bench.h>
#include <os.h>
#include <uaccess_walk.h>
#include "internal.h"

int is_skas_winch(int pid, int fd, void *data)
{
	stub_panic("skas/process.c: is_skas_winch — no SIGWINCH on NT (D7)");
}

/* ---- S2: start_userspace + the per-task userspace loop ------------- */

/* NtWaitForSingleObject timeout status (win32 WAIT_TIMEOUT == 258). */
#define UML_NT_STATUS_TIMEOUT ((NTSTATUS)0x00000102)
/* GetExitCodeProcess: 259 = STILL_ACTIVE (win32). */
void uml_nt_dbg_summary(void);
void dbg_drain(void);
void uml_nt_death_scan_exec(struct uml_nt_stub_conn *c);
/* Shelley 216: the launcher installs this if dbghelp is available; a weak
 * default keeps the kernel linkable on its own. */
extern int (*uml_nt_dump_hook)(unsigned long pid)
	__attribute__((weak));
void uml_nt_host_mod(unsigned long long va, char *out, int len);
void uml_nt_death_rip_vma(struct uml_nt_stub_conn *c);

/* Shelley 232: exec_path is empty at spawn (ruling 199), so the flag that
 * actually names the login chain is chain_login — set at fork and at exec. */
int uml_nt_login_chain(const struct uml_nt_stub_conn *c);
#define login_conn(c) uml_nt_login_chain(c)
void uml_nt_sample_push(struct uml_nt_stub_conn *c);
void uml_nt_sample_dump(const struct uml_nt_stub_conn *c);
void uml_nt_death_exit_check(struct uml_nt_stub_conn *c);
extern unsigned long long uml_nt_tick_spawn, uml_nt_tick_dbg;
extern unsigned long long uml_nt_tick_round;
extern unsigned long long uml_nt_qpc_ms(unsigned long long, unsigned long long);
extern unsigned long long uml_nt_qpc_us(unsigned long long, unsigned long long);
extern unsigned long long uml_nt_resume_to_exit_us(HANDLE, unsigned long long);
/* Shelley 195: the debug lever lives in stub_ctl.c; this file only needs
 * to know whether rounds are slow by design. Declared here to keep the two
 * translation units honest without a header churn. */
extern int uml_nt_dbg_on;
static int uml_nt_dbg_mode(void)
{
	return uml_nt_dbg_on == 1;
}

#define UML_NT_STILL_ACTIVE 259u

/* S4d: one XSTATE-CAPTURED line per boot (the CI gate's evidence). */
static int xstate_pull_logged;

int start_userspace(struct mm_id *mm_id)
{
	struct uml_nt_stub_conn *c;

	/* Upstream: init_new_context ran first and start_userspace
	 * cloned the stub process. NT: uml_nt_mmctx_init (S1) already
	 * spawned the stub suspended; readiness = the conn carries a
	 * live stub_data view. The owning task's first userspace()
	 * round hands over the entry state and resumes the thread. */
	if (mm_id == NULL || mm_id->nt_conn == NULL) {
		os_warn("start_userspace: mm without an NT conn\n");
		return -EINVAL;
	}
	c = mm_id->nt_conn;
	if (c->d == NULL || !c->alive) {
		os_warn("start_userspace: conn pid %d not ready "
			"(d=%p alive=%d)\n", mm_id->pid, (void *)c->d,
			c->alive);
		return -EINVAL;
	}
	return 0;
}

/* First round bootstrap: the task's pt_regs (binfmt wrote the guest
 * entry there) become the stub's jump state — the stub applies
 * init_regs and jumps AFTER its INIT plan streams back. */
/* [ctx-ring] (Shelley 158 step 1): the last CONTEXTs we handed to the
 * continue path, with the VMA verdict for rip and rsp (resuming into an
 * unmapped page, or at a non-executable rip, is OUR bug, not the
 * guest's) and the CONTEXT_EX header the dispatcher itself built. */
/* [ripvma] Where was the GUEST when the stub died? "no VMA" is a
 * verdict, not a detail: executing in a hole is a loader/mapping bug on
 * our side, executing in a mapped-but-non-exec page is a permission
 * bug, and either one explains a death with no user-mode dispatch
 * without any more guessing. */
static void uml_nt_guestsite(const char *what, unsigned long long va,
			     struct uml_nt_stub_conn *c)
{
	int i;
	int found = 0;
	unsigned long long nb = 0, ne = 0;

	if (c->mm != NULL) {
		for (i = 0; i < c->mm->nvma; i++) {
			struct uml_nt_vma *v = &c->mm->vma[i];

			if (va >= v->start && va < v->end) {
				os_info("[site] %s=0x%llx in [0x%llx,"
					"0x%llx) prot=0x%x flags=0x%x "
					"off=0x%llx\n", what, va,
					v->start, v->end, v->prot,
					v->flags, v->run_off);
				found = 1;
				break;
			}
			if (v->end <= va) {
				nb = v->end;
				ne = v->end;
			} else if (nb == 0 && v->start > va) {
				ne = v->start;
			}
		}
	}
	if (!found)
		os_info("[site] %s=0x%llx NO VMA (gap after 0x%llx, "
			"before 0x%llx) nvma=%d\n", what, va, nb, ne,
			c->mm != NULL ? c->mm->nvma : -1);
}

/* [death-site] (Shelley 159): three hypotheses, three different fixes,
 * and exactly one set of numbers separates them.
 *
 *   (i)   corruption in transit — the answer the kernel published, the
 *         block as it stands now, and the value the stub itself read
 *         under its seq disagree. Fix = the copy path (length,
 *         overlap, torn write), never the guest.
 *   (ii)  stale view — the kernel's table calls the VA a hole while the
 *         STUB still has it mapped (VirtualQueryEx on the live
 *         process), i.e. the guest kept running in a range the table
 *         already unmapped. Fix = the unmap lifecycle (never release a
 *         range the guest's rip still sits in).
 *   (iii) guest jump — table AND process both empty, and the rip equals
 *         (or sits next to) the value the kernel just returned: the
 *         guest jumped to a return value. Fix = whoever computed the
 *         target.
 */
static void uml_nt_death_site(struct uml_nt_stub_conn *c)
{
	unsigned long long rip = c->d->regs.rip;
	unsigned long long xor_ans = c->ans_rip ^ rip;
	int vi = uml_nt_vp_view_find(c->views, c->nviews, rip);
	int ri = (c->d->ctx_ring_at > 0) ?
		(int)((c->d->ctx_ring_at - 1) % 16) : -1;
	int stub_has = 0;

	/* (ii) the ledger, then the live process itself */
	if (vi >= 0)
		os_info("[ledger] rip=0x%llx VIEW #%d base=0x%llx len=0x%llx "
			"off=0x%llx prot=0x%x (%d views)\n", rip, vi,
			c->views[vi].va, c->views[vi].len,
			c->views[vi].off, (unsigned)c->views[vi].prot,
			c->nviews);
	else
		os_info("[ledger] rip=0x%llx NO VIEW (%d views)\n",
			rip, c->nviews);

	if (c->proc != NULL) {
		MEMORY_BASIC_INFORMATION mbi;

		{
			unsigned char *z = (unsigned char *)&mbi;
			unsigned i;

			for (i = 0; i < sizeof(mbi); i++)
				z[i] = 0;
		}
		if (nt->VirtualQueryEx(c->proc, (void *)(uintptr_t)rip,
				       &mbi, sizeof(mbi)) > 0) {
			stub_has = (mbi.State == MEM_COMMIT);
			os_info("[stubview] rip=0x%llx state=0x%lx prot=0x%lx "
				"type=0x%lx base=0x%llx alloc=0x%llx ==> %s\n",
				rip, (unsigned long)mbi.State,
				(unsigned long)mbi.Protect,
				(unsigned long)mbi.Type,
				(unsigned long long)(uintptr_t)mbi.BaseAddress,
				(unsigned long long)mbi.AllocationBase,
				stub_has ? "the STUB still maps it" :
				"the stub does NOT map it");
		} else {
			os_info("[stubview] rip=0x%llx QUERY FAILED\n", rip);
		}
	}

	/* (i) the three rips */
	os_info("[rip3] answered=0x%llx(seq=%llu step=%llu) "
		"shared=0x%llx(req_seq=%llu step=%llu) "
		"stub_read=0x%llx(seq=%llu) xor=0x%llx\n",
		c->ans_rip, c->ans_seq, c->ans_step,
		rip, c->d->req_seq, c->d->round_step,
		ri >= 0 ? c->d->ctx_ring[ri].grip : 0ull,
		ri >= 0 ? c->d->ctx_ring[ri].gseq : 0ull,
		xor_ans);
	{
		/* The ring entry is written BEFORE the hop runs, so the hop's
		 * snapshot lands in the NEXT entry — an ordering artifact of
		 * my own instrument (third one today: label, round kind, now
		 * order). Look the round up by the id the hop itself
		 * stamped; no match = genuinely not comparable. */
		unsigned long long hid = ri >= 0 ?
			c->d->ctx_ring[ri].ent_id : 0ull;
		int hi = -1;
		int k;

		for (k = 0; k < 16; k++)
			if (c->d->ctx_ring[k].seq == hid && hid != 0)
				hi = k;
		os_info("[hop-entry] ent_id=%llu matched_ring=%d "
			"ent_rsp=0x%llx ctx_rsp=0x%llx ent_fl=0x%llx "
			"ctx_fl=0x%llx ==> %s\n",
			hid, hi,
			hid ? c->d->ctx_ring[ri].ent_rsp : 0ull,
			hi >= 0 ? c->d->ctx_ring[hi].gsp : 0ull,
			hid ? c->d->ctx_ring[ri].ent_fl : 0ull,
			hi >= 0 ? c->d->ctx_ring[hi].eflags : 0ull,
			hi < 0 ? "not comparable (the hop's round is not in "
				 "the ring)" :
			(c->d->ctx_ring[ri].ent_rsp !=
			 c->d->ctx_ring[hi].gsp ?
			 "the HOP changed rsp — fix the hop" :
			 "rsp survived the hop intact"));
	}
	os_info("[hop] entered=%llu cleared_wrfsbase=%llu (last ring "
		"entry: pre=%llu post=%llu) ==> %s\n",
		ri >= 0 ? c->d->ctx_ring[ri].hop_pre : 0ull,
		ri >= 0 ? c->d->ctx_ring[ri].hop_post : 0ull,
		ri >= 0 ? c->d->ctx_ring[ri].hop_pre : 0ull,
		ri >= 0 ? c->d->ctx_ring[ri].hop_post : 0ull,
		(ri >= 0 && c->d->ctx_ring[ri].hop_pre !=
		 c->d->ctx_ring[ri].hop_post) ?
		"died INSIDE the hop (after wrfsbase, before the jmp)" :
		"the hop completed; the death is at or after the jmp target");
	os_info("[rip3] req=0x%llx(seq=%llu) ans_rsp=0x%llx "
		"ans_rax=0x%llx ans_retval=0x%llx\n",
		c->req_rip, c->req_seq_seen, c->ans_rsp,
		c->ans_rax, c->ans_retval);

	/* the verdicts, one line each, so the class is never inferred from
	 * a reader's arithmetic again (the choice itself is pure logic,
	 * red-first in test_resume.c section 12) */
	/* MY OWN correction (Shelley 161): ans_rip belongs to the round kind
	 * we answered. A PROT_DONE round legitimately carries the PREVIOUS
	 * fault round's regs in the block (the stub does not republish them
	 * for an op), so comparing across kinds invents a TRANSIT that
	 * never happened — it did, once, in referee 40214141627. Only
	 * compare when the block still holds the round we answered. */
	if (c->ans_cmd != c->d->cmd || c->ans_seq != c->d->req_seq) {
		os_info("[verdict] (i) not comparable: the block holds a "
			"%u round (seq %llu), we answered a %u round (seq "
			"%llu) — the rip difference is the round kind, not a "
			"corruption\n", (unsigned)c->d->cmd, c->d->req_seq,
			c->ans_cmd, c->ans_seq);
		xor_ans = 0;
	}
	switch (uml_nt_deathsit_verdict(xor_ans == 0 ? rip : c->ans_rip,
					rip, vi >= 0, stub_has)) {
	case UML_NT_DS_TRANSIT:
		os_info("[verdict] (i) TRANSIT-CORRUPT: the block no longer "
			"holds what we answered (xor=0x%llx) — fix the copy "
			"path\n", xor_ans);
		break;
	case UML_NT_DS_STALE:
		os_info("[verdict] (ii) STALE VIEW: table says hole, the "
			"stub still maps it — the guest ran in a released "
			"range; fix the unmap lifecycle\n");
		break;
	case UML_NT_DS_JUMP:
		os_info("[verdict] (iii) GUEST JUMP: no table entry, no "
			"view, and the answer we gave was rip=0x%llx / "
			"retval=0x%llx%s — trace the target's source\n",
			c->ans_rip, c->ans_retval,
			uml_nt_deathsit_near_retval(rip, c->ans_retval,
						    0x10000) ?
			" (rip is WITHIN 64K of the retval we just "
			"returned)" : "");
		break;
	default:
		os_info("[verdict] SANE: guest rip sits in a mapped VMA "
			"AND a live view (prot=0x%x) — the death is not a "
			"mapping hole\n", (unsigned)c->views[vi].prot);
		break;
	}
}

static void uml_nt_ctx_ring_dump(struct uml_nt_stub_conn *c)
{
	unsigned long long n = c->d->ctx_ring_at;
	unsigned long long first = n > 16 ? n - 16 : 0;
	unsigned long long k;

	for (k = first; k < n; k++) {
		struct uml_nt_ctx_ring *r = &c->d->ctx_ring[k % 16];
		int rip_ok = 0, rsp_ok = 0, i;

		if (c->mm != NULL) {
			for (i = 0; i < c->mm->nvma; i++) {
				struct uml_nt_vma *v = &c->mm->vma[i];

				if (r->rip >= v->start && r->rip < v->end)
					rip_ok = (v->prot & 0xf0u) ? 1 : 3;
				if (r->rsp >= v->start && r->rsp < v->end)
					rsp_ok = (v->prot & 0x0fu) ? 1 : 3;
			}
		}
		os_info("[ctx] #%llu step=%llu kind=%llu rip=0x%llx"
			"(vma=%d) rsp=0x%llx(vma=%d) fl=0x%llx cs=%llu "
			"ss=%llu cf=0x%llx mxcsr=0x%llx ex=%llu "
			"all=[%llu/%llu/%llu] leg=[%llu/%llu/%llu] "
			"xsa=[%llu/%llu/%llu] back=%llu "
			"xcr0=0x%llx xsmax=%llu\n",
			r->seq, r->step, r->kind, r->rip, rip_ok,
			r->rsp, rsp_ok, r->eflags, r->cs, r->ss,
			r->ctx_flags, r->mxcsr, r->have_ex,
			r->all_size, r->all_area, r->all_off,
			r->leg_size, r->leg_area, r->leg_off,
			r->xsa_size, r->xsa_area, r->xsa_off,
			r->ex_back, r->host_xcr0, r->host_xs_max);
	}
}

static void conn_bootstrap(struct uml_nt_stub_conn *c,
			   struct uml_pt_regs *regs)
{
	struct uml_nt_gp_regs *g = &c->d->init_regs;

	/* Shelley 164: the slot ledger starts empty, and "no slot" is -1,
	 * not 0 — a conn that has never armed must not look like it owns
	 * slot 0. */
	uml_nt_drs_init(&c->drs);
	c->drex_slot = -1;

	/* No guest code yet: entry/stack/init stay zero until the
	 * owning task hands the conn its first state. __builtin_memset:
	 * linux/string.h collides with user.h's sized_strscpy here. */
	__builtin_memset(g, 0, sizeof(*g));
	g->rax = REGS_AX(regs->gp);
	g->rcx = REGS_CX(regs->gp);
	g->rdx = REGS_DX(regs->gp);
	g->rbx = REGS_BX(regs->gp);
	g->rsp = REGS_SP(regs->gp);
	g->rbp = REGS_BP(regs->gp);
	g->rsi = REGS_SI(regs->gp);
	g->rdi = REGS_DI(regs->gp);
	g->r8 = REGS_R8(regs->gp);
	g->r9 = REGS_R9(regs->gp);
	g->r10 = REGS_R10(regs->gp);
	g->r11 = REGS_R11(regs->gp);
	g->r12 = REGS_R12(regs->gp);
	g->r13 = REGS_R13(regs->gp);
	g->r14 = REGS_R14(regs->gp);
	g->r15 = REGS_R15(regs->gp);
	g->rip = REGS_IP(regs->gp);
	g->rflags = REGS_EFLAGS(regs->gp);
	/* M5.4 c3 (map 059, fix F): the fork seed's rcx is the parent's
	 * live rcx at the clone trap — ABI garbage (the syscall
	 * contract clobbers rcx; no code past the fork-resume rip
	 * reads it). Upstream inherits the same garbage harmlessly:
	 * nothing snapshots registers onto the guest stack on a
	 * syscall. Here EVERY trap leaves Windows' dispatch state
	 * (EXCEPTION_RECORD + full CONTEXT + xstate, ~12KB below the
	 * trap rsp — see uml_nt_signal_check's exc_stack note) on the
	 * guest stack, carrying the seed rcx at the CONTEXT's rcx
	 * slot: the fork-resume rip (_Fork+0x23 = 0x606a4353)
	 * re-entered the child's stack as data at its FIRST syscall
	 * (nr=273 set_robust_list, residue-watch run 36856047706) and
	 * the deterministic env-merge depth read it as a strv entry.
	 * Zero it at the seed so no VEH CONTEXT ever carries the
	 * poison: exec conns arrive with rcx=0 anyway (ELF_PLAT_INIT
	 * parity, 9fcdb9a) and POC conns memset it — this is the
	 * fork-child half of the same contract. Callee-saved stay
	 * verbatim (fork semantics); r11 stays as-is until the watch
	 * names it (only rcx is implicated by the decode). */
	g->rcx = 0;
	c->d->entry_va = REGS_IP(regs->gp);
	c->d->stack_va = REGS_SP(regs->gp);
	/* D18 fork: the fork seed records the inherited base in the
	 * CONN — the stub_data view does not exist yet (the stub is
	 * born suspended), so nothing published it to d. The exec path
	 * never notices (glibc calls arch_prctl before its first
	 * fs-relative access), the fork path does: glibc's struct
	 * pthread lives at NEGATIVE offsets from the TCB pointer, so
	 * a zero base faults at tiny-negative addresses (-408 = -0x198
	 * killed the sd-executor in run 36777774115). Publish the
	 * conn's base for the stub's first resume. */
	c->d->fs_base = c->fs_base;
	/* M5.4 c3 (map 053 item 1): the entry state every conn is
	 * born with. A fork child's line carries the parent's
	 * fork-round snapshot (rip = _Fork+0x23 + the live
	 * callee-saved — correct fork semantics). An EXEC conn's line
	 * must show ZEROES in rbx/rbp/r12-r15 (ELF_PLAT_INIT parity,
	 * binfmt.c) — any cluster value there = the entry-regs
	 * residue vector alive. (c->pid = the stub pid — unique per
	 * conn; task-backed conns report the kernel pid via getpid.) */
	/* map 059: seed vs residue byte-compare needs the FULL gp row
	 * the watch's callee line prints (r12-r15) plus rcx (the
	 * ABI-garbage slot zeroed above). */
	os_info("conn_bootstrap: stub-pid %lu rip=0x%llx rcx=0x%llx "
		"rbx=0x%llx r12=0x%llx r13=0x%llx r14=0x%llx "
		"r15=0x%llx\n", (unsigned long)c->pid,
		g->rip, g->rcx, g->rbx, g->r12, g->r13, g->r14, g->r15);
}

/* get_stub_state analogue: pull the trap regs back into the task.
 * The stub's VEH wrote d->regs at the trap; a syscall round carries
 * the return value in d->retval (the stub folds it into its own rax
 * on resume — mirror it here so the guest task sees the retval). */
static void conn_pull_regs(struct uml_pt_regs *regs,
			   const struct uml_nt_stub_data *d, unsigned cmd)
{
	const struct uml_nt_gp_regs *g = &d->regs;

	REGS_AX(regs->gp) = g->rax;
	REGS_CX(regs->gp) = g->rcx;
	REGS_DX(regs->gp) = g->rdx;
	REGS_BX(regs->gp) = g->rbx;
	REGS_SP(regs->gp) = g->rsp;
	REGS_BP(regs->gp) = g->rbp;
	REGS_SI(regs->gp) = g->rsi;
	REGS_DI(regs->gp) = g->rdi;
	REGS_R8(regs->gp) = g->r8;
	REGS_R9(regs->gp) = g->r9;
	REGS_R10(regs->gp) = g->r10;
	REGS_R11(regs->gp) = g->r11;
	REGS_R12(regs->gp) = g->r12;
	REGS_R13(regs->gp) = g->r13;
	REGS_R14(regs->gp) = g->r14;
	REGS_R15(regs->gp) = g->r15;
	REGS_IP(regs->gp) = g->rip;
	/* TF is the stub's replay instrument (ss_model.h): the guest
	 * never owns it, pt_regs never carries it. */
	REGS_EFLAGS(regs->gp) = uml_nt_ss_capture_flags(g->rflags);
	regs->is_user = 1;
	if (cmd == UML_STUB_CMD_SYSCALL) {
		UPT_SYSCALL_NR(regs) = (long)g->rax; /* the trap's nr */
		REGS_AX(regs->gp) = d->retval; /* guest-visible retval */
	} else {
		/* upstream: "assume it's not a syscall" */
		UPT_SYSCALL_NR(regs) = -1;
	}
	/* S4d: a fault round records the fault itself — copy_sc_to_user
	 * builds the sigframe's cr2/err/trapno from thread faultinfo
	 * (upstream fills it via get_skas_faultinfo at the SIGSEGV
	 * trap). NT mapping: cr2 = the faulting VA, trap 14 (page
	 * fault), x86 error-code bits (user | write | instruction). */
	if (cmd == UML_STUB_CMD_FAULT) {
		regs->faultinfo.cr2 = (unsigned long)d->fault_addr;
		regs->faultinfo.trap_no = 14;
		regs->faultinfo.error_code = 0x4 /* user */ |
			(d->fault_type == 1 ? 0x2 /* write */ :
			 d->fault_type == 8 ? 0x10 /* exec */ : 0);
	}
	/* S4d: the FP half of get_fp_registers — the stub captured the
	 * at-exception XSAVE_FORMAT block into d->xstate (context
	 * flags gated); the task's fp block is the kernel's live copy
	 * (signal setup copies it into the sigframe, sigreturn writes
	 * it back). Zero-size while no capture: INIT rounds and POC
	 * conns (no task) never wrote it. One log line per boot: the
	 * CI gate greps it as the round-trip-live evidence. */
	if (d->xstate_flags & UML_STUB_XS_CAPTURED) {
		__builtin_memcpy(regs->fp, (const void *)d->xstate,
				 host_fp_size);
		if (!xstate_pull_logged) {
			xstate_pull_logged = 1;
			os_info("[stubtest] XSTATE-CAPTURED: %lu fp bytes "
				"round-trip live (fcw=0x%04x)\n",
				host_fp_size,
				(unsigned short)*(u16 *)regs->fp);
		}
	}
}

/* S4d: the put_fp_registers half — publish the task's FP block to
 * the stub and flag the restore. Today the bytes are the capture's
 * own (the kernel changes regs->fp only via signal delivery /
 * sigreturn, the next slice); running the identity every round
 * exercises the full capture→pull→push→restore loop with zero
 * behavior change. */
void uml_nt_fp_push(struct uml_nt_stub_conn *c, struct uml_pt_regs *regs)
{
	struct uml_nt_stub_data *d = c->d;

	if (!(d->xstate_flags & UML_STUB_XS_CAPTURED))
		return;
	__builtin_memcpy((void *)d->xstate, regs->fp, host_fp_size);
	d->xstate_flags |= UML_STUB_XS_RESTORE;
}

/* D15's guest-write (uaccess.c; linux/uaccess.h can't be included
 * here — it collides with user.h's sized_strscpy). */
extern unsigned long raw_copy_to_user(void *to, const void *from,
				      unsigned long n);

/* S4d: signal delivery between "trap served" and "stub resumed" —
 * the position upstream gets from interrupt_end() at the bottom of
 * every userspace() iteration (the stub is STOPPED there; the
 * rewritten regs ride the next iteration's SETREGS push). The NT
 * pump answers in one go, so this runs in pump_conn before the
 * evt_out release:
 *
 * 1. make current->thread.regs THIS round's state (rt_sigreturn
 *    already wrote the restored state into it — skip the pull);
 * 2. interrupt_end(): the generic machinery runs get_signal →
 *    do_signal → setup_signal_stack_si — the sigframe (GP snapshot
 *    + FP block from regs->fp + siginfo) is written through the D15
 *    walker and regs become the HANDLER's entry state; with no
 *    handler the default action kills the task right here (do_exit
 *    → exit_mm → mmctx_destroy terminates the stub — no leak);
 * 3. a delivered signal (or the sigreturn's restored state) is
 *    pushed VERBATIM: the stub must not do its own rip+2/rax=retval
 *    syscall resume over it.
 *
 * The delivery here is the task's own — force_sig_fault (the fault
 * path's SIGSEGV) and the generic send-signal syscalls mark
 * TIF_SIGPENDING on THIS task; the POC conns never reach this. */
int uml_nt_signal_check(struct uml_nt_stub_conn *c)
{
	struct uml_pt_regs *regs = c->owner_regs;
	struct uml_nt_stub_data *d = c->d;
	struct uml_nt_uacc_sink sink;
	struct uml_nt_mm *prev_mm;
	struct uml_nt_uacc_sink prev_sink;
	unsigned long long rip_before;
	unsigned long long true_sp;
	int pushed = 0;

	if (!c->sig_regs_current) {
		/* Syscall-shaped rounds resume past the ud2 (the stub
		 * does rip+2) — the completed-syscall state is what a
		 * signal frame must record. Fault rounds are
		 * mid-instruction: pull verbatim, no +2. */
		if (d->cmd == UML_STUB_CMD_FAULT)
			conn_pull_regs(regs, d, d->cmd);
		else
			uml_nt_sync_trap_regs(regs, d);
	}
	c->sig_regs_current = 0;

	/* The signal machinery WRITES GUEST MEMORY (the sigframe: GP
	 * snapshot + FP block + siginfo — copy_to_user/__put_user all
	 * walk through the D15 walker). The dispatch restored the
	 * uaccess globals at its exit; install THIS conn's mm + a sink
	 * for the duration (the dispatch's own pattern), so the frame
	 * setup cannot hit the null-mm fail-safe EFAULT — which would
	 * force_sigsegv the task to death with SIG_DFL (found on the
	 * first wine run: handler installed, delivery took the default
	 * action). COW fixups from the frame writes queue into the
	 * conn's plan and stream with this answer. */
	sink.ph = c->ph;
	sink.plan = &c->plan;
	prev_mm = uml_nt_uacc_set_mm(c->mm);
	prev_sink = uml_nt_uacc_set_sink(&sink);

	/* The previous ops (if any) streamed to completion (the pump
	 * gates this call on plan_left == 0) — queue fresh.
	 * M5.6a (140): if that gate ever breaks, MERGE — never wipe
	 * a live stream (the reset class: orphaned MAPs + a floating
	 * copy). Loud, the gate's name is wanted. */
	if (c->plan_left != 0) {
		static int sigmid_budget = 4;

		if (sigmid_budget > 0) {
			sigmid_budget--;
			os_info("[streamsync] pid %lu signal delivery "
				"MID-DRAIN (left=%d next=%d n=%d) — "
				"MERGE, the queue wipe is forbidden\n",
				(unsigned long)c->pid, c->plan_left,
				c->plan_next, c->plan.n_ops);
		}
	} else {
		c->plan.n_ops = 0;
	}

	rip_before = REGS_IP(regs->gp);

	/* Wine builds the exception dispatch state (EXCEPTION_RECORD +
	 * full CONTEXT + xstate — the exc_stack) ON THE GUEST STACK,
	 * just below the trap rsp (~12KB with the xstate area), and
	 * the context buffer LIVES there while our VEH runs. The
	 * upstream frame placement (at the interrupted rsp, growing
	 * down) lands inside that window and corrupts the dispatch
	 * context mid-round-trip: the handler resumed with wine's
	 * saved registers replaced by sigframe bytes (rdx read as
	 * 0xD), and NtSetContextThread rejected the context
	 * (C000000D) — the dispatch fell to the SEH walk and died.
	 * Deliver the frame 8KB deeper instead, then patch the frame's
	 * saved mcontext rsp back to the TRUE trap rsp: rt_sigreturn
	 * restores the guest exactly where it was, and the handler's
	 * own execution (plus any wine dispatch below IT) stays inside
	 * the 64KB stack run, away from everything else. Upstream
	 * delivers at the interrupted rsp; the sigreturn path derives
	 * the frame from the live rsp (frame = sp - 8 after the
	 * handler's ret), so the frame position is free for us to
	 * choose. */
	true_sp = REGS_SP(regs->gp);
	REGS_SP(regs->gp) = true_sp - 0x2000;

	interrupt_end();

	if (REGS_IP(regs->gp) == rip_before) {
		/* Nothing delivered: the deep sp was only a frame
		 * placement. Put the real one back — after rt_sigreturn
		 * the verbatim push below resumes the guest at exactly
		 * this sp, and a 0x2000-deep one made its next `ret` pop
		 * stale stack (the net gate's sh died at rip 0 right
		 * after its first SIGCHLD). */
		REGS_SP(regs->gp) = true_sp;
	} else {
		/* Post-setup: SP = the frame (the handler's entry rsp,
		 * kept for the verbatim push). The setup saved the DEEP
		 * sp into the frame's mcontext — patch the saved rsp
		 * back to the true one (frame + pretcode 8 + uc_flags 8
		 * + uc_link 8 + uc_stack 24 = the mcontext;
		 * sigcontext_64's sp = its 16th qword = +120 → +168
		 * total). Through the walker while the mm/sink window is
		 * still open. */
		unsigned long *sp_slot =
			(unsigned long *)(REGS_SP(regs->gp) + 168);
		unsigned long true_rsp = (unsigned long)true_sp;

		if (raw_copy_to_user(sp_slot, &true_rsp, sizeof(true_rsp)))
			os_info("[stubtest] signal frame rsp fixup "
				"EFAULT (frame %llx)\n",
				(unsigned long long)REGS_SP(regs->gp));

		/* M5.6a writer-hunt follow-up: the frame (GP snapshot +
		 * fpstate, ~1KiB) must NEVER land in an image run. A
		 * stack/image run alias puts it into read-only text;
		 * the guest then executes the sigcontext as code — the
		 * login-depth wild entries (saved rip/eflags found at
		 * ld-linux 0xb560). Log-only, budgeted. */
		{
			static int sigimg_budget = 16;
			long long fo = uml_nt_vma_translate(c->mm,
					REGS_SP(regs->gp), 1);

			if (fo >= 0 && sigimg_budget > 0) {
				unsigned long long fr =
					((unsigned long long)fo) &
					~(UML_NT_PHYS_RUN_SIZE - 1);

				if (uml_nt_imgwatch_is_image(c, fr)) {
					sigimg_budget--;
					os_info("[sigframe-image] pid %lu "
						"frame=0x%llx run=0x%llx "
						"true-sp=0x%llx nr=%llu — "
						"the sigframe landed in "
						"an image run (stack/"
						"image alias)\n",
						(unsigned long)c->pid,
						REGS_SP(regs->gp), fr,
						true_sp, c->last_nr);
				}
			}
		}
	}

	uml_nt_uacc_set_mm(prev_mm);
	uml_nt_uacc_set_sink(&prev_sink);

	/* The frame setup queued stub ops (a COW-shared run went
	 * private mid-write): prime the plan streaming — the answer
	 * becomes the first op, the rest stream on the PROT_DONE
	 * rounds, and the VERBATIM push below survives until the
	 * stub's final resume (it clears the flags only there).
	 * K6 (cowcopy-race-class-fix): uml_nt_view_release_complete
	 * gives this re-homing stream its COMPLETE per-view release
	 * set and arms it — a fixup stream that never applied left
	 * the table moved and the stale view serving guest stores
	 * into the abandoned backing (dl26 37539992560). On refusal
	 * the conn is already KILLED loud — skip the prime. */
	if (c->plan.n_ops > 0 &&
	    uml_nt_view_release_complete(c) == 0)
		uml_nt_plan_issue_op(c, &c->plan.ops[c->plan_next]);

	/* M5.4 c3 (map 057): a delivery ON A WATCHED CONN is one of
	 * the two candidate writers of the fork-residue cluster (the
	 * sigframe's mcontext records trap+2 = the fork-resume rip
	 * when the interrupted state is still the seed). rip_before
	 * IS the value that landed in uc_mcontext.rip; REGS_SP is
	 * the frame placement. Correlate with the residue-watch
	 * scan's first-hit round in the same log. */
	if (REGS_IP(regs->gp) != rip_before && c->watch_val != 0)
		os_info("[sig] delivered on watched conn pid %lu: "
			"trap-rip=0x%llx frame=0x%llx true-sp=0x%llx\n",
			(unsigned long)c->pid, rip_before,
			(unsigned long long)REGS_SP(regs->gp),
			true_sp);

	if (REGS_IP(regs->gp) != rip_before || c->push_verbatim) {
		/* Delivered (or restored): regs = the exact resume
		 * state. Push the GP snapshot verbatim — the FP push
		 * follows in the pump (regs->fp is what setup copied
		 * into the frame, or what sigreturn restored). */
		struct uml_nt_gp_regs *g = &d->regs;

		g->rax = REGS_AX(regs->gp);
		g->rcx = REGS_CX(regs->gp);
		g->rdx = REGS_DX(regs->gp);
		g->rbx = REGS_BX(regs->gp);
		g->rsp = REGS_SP(regs->gp);
		g->rbp = REGS_BP(regs->gp);
		g->rsi = REGS_SI(regs->gp);
		g->rdi = REGS_DI(regs->gp);
		g->r8 = REGS_R8(regs->gp);
		g->r9 = REGS_R9(regs->gp);
		g->r10 = REGS_R10(regs->gp);
		g->r11 = REGS_R11(regs->gp);
		g->r12 = REGS_R12(regs->gp);
		g->r13 = REGS_R13(regs->gp);
		g->r14 = REGS_R14(regs->gp);
		g->r15 = REGS_R15(regs->gp);
		g->rip = REGS_IP(regs->gp);
		g->rflags = uml_nt_ss_resume_flags(REGS_EFLAGS(regs->gp));
		d->xstate_flags |= UML_STUB_XS_VERBATIM;
		pushed = 1;
	}
	c->push_verbatim = 0;
	return pushed;
}

/* M4.2 fork prep: the generic fork's copy_thread memcpy's
 * current_pt_regs — which on this port is one round STALE (the
 * current trap lives in d->regs until conn_pull_regs runs after the
 * handler). Sync the trap state in, with rip +2: the child's first
 * conn_bootstrap jumps to shadow.rip, and it must resume PAST the
 * ud2 (the stub does the same +2 for the parent's own resume).
 * copy_thread then sets the child's syscall retval 0 — fork
 * semantics. */
void uml_nt_sync_trap_regs(struct uml_pt_regs *regs,
			   const struct uml_nt_stub_data *d)
{
	conn_pull_regs(regs, d, UML_STUB_CMD_SYSCALL);
	REGS_IP(regs->gp) += 2;
}

void userspace(struct uml_pt_regs *regs)
{
	interrupt_end();

	while (1) {
		struct mm_id *mm_id = current_mm_id();
		struct uml_nt_stub_conn *c;
		unsigned cmd;
		int rc;

		if (mm_id == NULL || mm_id->nt_conn == NULL) {
			printk(UM_KERN_ERR "userspace: task without an "
			       "NT mm conn\n");
			os_dump_core();
		}
		c = mm_id->nt_conn;
		/* S4d: the FP round-trip runs in the pump (before the
		 * answer releases the stub) and needs THIS task's
		 * pt_regs — record it on the conn every round (the mm
		 * can switch under execve; the conn dies with it). */
		c->owner_regs = regs;

		/* current_mm_sync() upstream flushes the pte batch into
		 * the stub; on NT the conn's VMA tree IS the truth —
		 * ops stream back through the slot at serve time. The
		 * first round hands over the entry state and starts
		 * the suspended thread. */
		if (!c->resumed) {
			conn_bootstrap(c, regs);
			c->resumed = 1;
			nt->ResumeThread(c->thread);
		}

		/* Turnstile (D10): block on THIS conn's evt_in — the
		 * per-task wait (upstream blocks on the stub's futex).
		 * M5.1c: the net reader thread also wakes us (the D19
		 * wake event) so RX IRQs run between stub traps — the
		 * upstream shape (SIGIO interrupts the blocking poll,
		 * the handler runs, delivery returns). The timeout
		 * keeps a dead/hung stub loud instead of a silent
		 * boot hang (M1.9 lesson). */
		{
		unsigned int wait_tmo = 0;

		for (;;) {
			HANDLE waits[3], hnet, hcon;
			ULONG w, code;
			int nwait = 1, idx_net = -1, idx_con = -1;

			waits[0] = c->evt_in;
			hnet = uml_nt_net_wake_event();
			hcon = uml_nt_console_wake_event();
			if (hnet != NULL) {
				idx_net = nwait;
				waits[nwait++] = hnet;
			}
			/* M5.6a slice A: the console input wake — the
			 * stdin reader thread edge-captures into the
			 * ring and SetEvents; the drain (tty feed)
			 * runs on THIS thread (D19). Absent stdin
			 * (closed/parked) leaves the event NULL and
			 * the wait is the old shape. */
			if (hcon != NULL) {
				idx_con = nwait;
				waits[nwait++] = hcon;
			}
			/* Shelley 232: for the login chain the wait is also the
			 * sampler clock — 50 ms gives three or four mid-compute
			 * samples inside the window the death comes out of, and
			 * it sharpens the detection from one second to fifty
			 * milliseconds as a bonus. */
			w = nt->WaitForMultipleObjects(nwait, waits, 0,
						       login_conn(c) ? 50 : 1000);
			if (w == 0)
				break; /* stub trap ready */
			if (idx_net >= 0 && w == (ULONG)idx_net) {
				/* A frame was staged: run the SIGIO
				 * machinery (registry flush → the net
				 * IRQ) on THIS thread, then re-wait. */
				uml_nt_sigio_flush();
				continue;
			}
			if (idx_con >= 0 && w == (ULONG)idx_con) {
				/* Console input staged: drain the
				 * edge-capture ring into the tty core
				 * on THIS thread, then re-wait. */
				uml_nt_console_flush();
				continue;
			}
			if (w == 258u /*WAIT_TIMEOUT*/) {
				/* Shelley 233: the sample must be taken on every
				 * tick, before anything looks at the exit code —
				 * placed after the death block it could only run
				 * once the death was already found (calls=0).
				 * The tick line is the positive counter that
				 * proves this clock runs at all. */
				if (login_conn(c)) {
					uml_nt_sample_push(c);
					if ((c->d->smp_calls % 200u) == 0)
						os_info("[tick] pid %d n=%u "
							"step=%u last=%llu\n",
							(int)c->pid,
							(unsigned)c->d->smp_calls,
							(unsigned)c->d->round_step,
							c->d->done_seq);
				}
				/* Shelley 202: the last poll happens BEFORE we
				 * read the exit code. An event raised in the
				 * five milliseconds we just spent in the wait
				 * is still queued, and the death path used to
				 * walk past it. */
				if (uml_nt_dbg_mode() != 0)
					dbg_drain();
				code = 0;
				nt->GetExitCodeProcess(c->proc, &code);
					/* v21 (Shelley 155, witness-first): the
					 * LAST-CHANCE record. Classification
					 * happens HERE because only the kernel
					 * owns the VMA tree and the view
					 * ledger. Three branches, three
					 * different fixes:
					 *  (a) inside a guest VMA + no such
					 *      view in the ledger = VIEW-HOLE
					 *  (b) outside every VMA = a guest
					 *      garbage pointer
					 *  (c) outside the guest span = a
					 *      real stub-code bug            */
					if (c->d->unhandled_seq == 1) {
						unsigned long long ua =
							c->d->unhandled_addr;
						unsigned long long ur =
							c->d->unhandled_rip;
						struct uml_nt_vma *uv =
							uml_nt_vma_find(c->mm, ua);
						struct uml_nt_vma *rv =
							uml_nt_vma_find(c->mm, ur);
						int vi, have_view = 0;

						for (vi = 0; vi < c->nviews; vi++)
							if (ua >= c->views[vi].va &&
							    ua < c->views[vi].va +
								 c->views[vi].len)
								have_view = 1;
						os_info("[unhandled] pid %d "
							"code=%08llx type=%llu "
							"addr=0x%llx rip=0x%llx "
							"rsp=0x%llx tid=%llu "
							"cmd=%llu args0=%llu "
							"a1=0x%llx a2=0x%llx\n",
							mm_id->pid,
							c->d->unhandled_code,
							c->d->unhandled_type,
							ua, ur,
							c->d->unhandled_rsp,
							c->d->unhandled_tid,
							c->d->unhandled_cmd,
							c->d->unhandled_nr,
							c->d->unhandled_args[1],
							c->d->unhandled_args[2]);
						os_info("[unhandled] insn "
							"0x%llx: %016llx %016llx "
							"(rip in %s)\n",
							ur, c->d->unhandled_insn,
							c->d->unhandled_insn2,
							rv ? "a guest VMA" :
							"NO guest VMA (stub "
							"code or table hole)");
						if (uv != NULL) {
							os_info("[unhandled] "
								"CLASS=VIEW-HOLE "
								"addr 0x%llx is in "
								"vma [0x%llx,0x%llx"
								") prot=0x%x "
								"flags=0x%x run=0x%llx "
								"gen=0x%llx — "
								"ledger says %s "
								"(%d/%d views, "
								"plan_left=%d, "
								"nvma=%d)\n",
								ua, uv->start,
								uv->end, uv->prot,
								uv->flags,
								uv->run_off, uv->gen,
								have_view ?
								"a view EXISTS (stale/wrong prot?)" :
								"NO VIEW was issued",
								c->nviews,
								(int)UML_NT_VIEW_MAX,
								c->plan_left,
								c->mm->nvma);
						} else if (ua < (1ull << 47)) {
							os_info("[unhandled] "
								"CLASS=GUEST-PTR "
								"addr 0x%llx is "
								"outside every VMA "
								"(guest passed a bad "
								"pointer) — %d/%d "
								"views, plan_left=%d, "
								"nvma=%d\n",
								ua, c->nviews,
								(int)UML_NT_VIEW_MAX,
								c->plan_left,
								c->mm->nvma);
						} else {
							os_info("[unhandled] "
								"CLASS=STUB-BUG "
								"addr 0x%llx is "
								"outside the guest "
								"span — stub code "
								"faulted; %d/%d "
								"views, plan_left=%d\n",
								ua, c->nviews,
								(int)UML_NT_VIEW_MAX,
								c->plan_left);
						}
					}
				if (code != UML_NT_STILL_ACTIVE) {
					/* The last published trap is the
					 * last state the kernel handed or
					 * saw — after a verbatim push it
					 * is the resume target itself. */
					os_info("[ctx-audit] pid %d rounds=%lu "
						"snapshots=%lu dirty_max=%lu "
						"xs_changed=%lu xs_hdr=0x%llx "
						"stage=%u ==> %s\n",
						c->pid,
						(unsigned long)c->d->ctx_rounds,
						(unsigned long)c->d->ctx_snapshots,
						(unsigned long)c->d->ctx_dirty_max,
						(unsigned long)c->d->ctx_xs_changed,
						c->d->ctx_xs_hdr,
						(unsigned)c->d->vstage,
						c->d->ctx_rounds == 0 ?
						"NEVER RAN — no truth, not a verdict" :
						c->d->ctx_dirty_max == 0 ?
						"ran and never found a dirty word"
						: "WE DIRTIED THE RECORD");
					os_info("[census] pid %d guest_tid=%u "
						"other_tid_entries=%lu tids=[%u,%u,%u,%u] "
						"==> %s\n",
						c->pid,
						(unsigned)c->d->guest_tid,
						(unsigned long)c->d->census_other,
						(unsigned)c->d->census_tids[0],
						(unsigned)c->d->census_tids[1],
						(unsigned)c->d->census_tids[2],
						(unsigned)c->d->census_tids[3],
						c->d->census_other > 0 ?
						"EXCEPTIONS ARRIVE ON OTHER THREADS (veh_body assumes the guest thread)" :
						"every exception was the guest thread");
					os_info("[xs-diff] pid %d flags=0x%lx xstate=%u "
						"BV=0x%llx "
						"XCOMP=0x%llx xmm_diff=%llu "
						"first=%llu ==> %s\n",
						c->pid,
						(unsigned long)c->d->ctx_flags,
						(unsigned)c->d->ctx_xstate_claim,
						c->d->xs_bv,
						c->d->xs_xcomp,
						c->d->xs_xmm_diff,
						c->d->xs_xmm_first,
						!c->d->ctx_xstate_claim ?
						"NO CONTEXT_XSTATE — 0x100 is FltSave, not a header (not evidence)"
						: (c->d->xs_xcomp >> 63) ?
						"COMPACTED format (XCOMP_BV bit 63 set)"
						: "standard format");
					os_info("[stage] pid %d last_stage=%u (%s)\n",
						c->pid, (unsigned)c->d->vstage,
						c->d->vstage == 1 ?
						"snapshot taken, body entered" :
						c->d->vstage == 2 ?
						"about to publish" :
						c->d->vstage == 3 ?
						"PUBLISHED — died while waiting for the answer" :
						c->d->vstage == 4 ?
						"answer in, before the register apply" :
						c->d->vstage == 5 ?
						"registers+watchpoints applied, before the record check" :
						c->d->vstage == 6 ?
						"record check reached (the round lived)" :
						"no stage");
					/* (alpha, Shelley 186): the number below
					 * IS GetExitCodeProcess's — the death
					 * line's source is named here so it can
					 * never be read as "an exception code we
					 * guessed". 0xC0000005 as an exit code
					 * means the thread died from an AV no
					 * handler took; TerminateThread would
					 * leave a different number. */
					{
						LARGE_INTEGER q;
						unsigned long long now;

					 nt->QueryPerformanceCounter(&q);
					 now = (unsigned long long)q.QuadPart;

					 os_info("[when] death tick=%llu "
						"since spawn=%llu ms "
						"since attach=%llu ms "
						"since last round=%llu ms\n",
						now,
						uml_nt_qpc_ms(uml_nt_tick_spawn,
							      now),
						uml_nt_qpc_ms(uml_nt_tick_dbg,
							      now),
						uml_nt_qpc_ms(uml_nt_tick_round,
							      now));
					 os_info("[gaps] pid %d "
						"now-publish=%llu us "
						"now-resume=%llu us "
						"veh_entries=%llu "
						"ts_publish=0x%llx ts_resume=0x%llx\n",
						c->pid,
						uml_nt_qpc_us(c->d->ts_publish,
							      now),
						uml_nt_qpc_us(c->d->ts_resume,
							      now),
						c->d->veh_entries,
						c->d->ts_publish,
						c->d->ts_resume);
					 os_info("[exit-when] pid %d "
						"resume->exit=%llu us "
						"(ts_resume=0x%llx)\n",
						c->pid,
						uml_nt_resume_to_exit_us(
							c->proc,
							c->d->ts_resume),
						c->d->ts_resume);
					}
					{
						int ei;
						long at =
						 c->d->entry_ring_at;

					 for (ei = 3; ei >= 1; ei--) {
						struct uml_nt_entry_ring *
						 e = &c->d->entry_ring[
						 (unsigned)(at - ei) & 15];

						os_info("[edge] -%d n=%llu "
							"seq=%llu cmd=%u "
							"code=0x%llx "
							"rip=0x%llx "
							"in_body=%llu\n",
							ei, e->n, e->seq,
							(unsigned)e->cmd,
							e->code, e->rip,
							e->in_body);
					 }
					}
					{
						int ri;
						char mo[64], mo2[64];
						unsigned rat =
						 c->d->ret_ring_at;

					 for (ri = 3; ri >= 1; ri--) {
						struct uml_nt_ret_ring *
						 r = &c->d->ret_ring[
						 (rat - ri) & 7];

						os_info("[ret3] -%d seq=%llu "
							"rip=0x%llx rsp=0x%llx "
							"eflags=0x%llx dr6=0x%llx "
							"dr7=0x%llx cmd=%llu "
							"action=%llu resuming=%llu\n",
							ri, r->seq, r->rip, r->rsp,
							r->eflags, r->dr6, r->dr7,
							r->cmd, r->action,
							r->resuming);
					 }
					 uml_nt_host_mod(c->d->regs.rip, mo,
							 sizeof(mo));
					 uml_nt_host_mod(c->d->regs.rsp, mo2,
							 sizeof(mo2));
					 os_info("[mods] death rip %s ; rsp %s "
						"(guest space is 0x60xxxxxx)\n",
						mo, mo2);
					 /* the eflags/DR state the guest was resumed
					  * WITH on the very last round */
					 os_info("[veh] first=%llu entries=%llu "
						"%s ; guest sp [0x%llx,0x%llx] "
						"death sp=0x%llx\n",
						c->d->veh_first,
						c->d->veh_entries,
						c->d->veh_first >
						  c->d->veh_entries ?
						  "==> AN EXCEPTION ENTERED AND DIED BEFORE THE RING"
						  : "==> every entry was recorded",
						c->d->guest_sp_min,
						c->d->guest_sp_max,
						c->d->regs.rsp);
					 os_info("[tf] tramp_arm=%llu ",
						c->d->tramp_arm);
					 os_info("[tf] hop_armed=%llu step_armed=%llu "
						"tramp_va=0x%llx (the ret3 rip above "
						"is the trampoline iff it matches)\n",
						c->d->tf_armed_hop,
						c->d->tf_armed_step,
						c->d->tramp_va);
					 os_info("[dr-now] eflags=0x%llx tf=%d "
						"got_dr7=0x%llx ask_dr7=0x%llx "
						"got_dr6=0x%llx\n",
						c->d->regs.rflags,
						(int)((c->d->regs.rflags >> 8) & 1),
						c->d->got_dr7, c->d->ask_dr7,
						c->d->got_flags);
					}
					/* Shelley 229: the death line above is long
					 * enough to be cut mid-print in the log, so the
					 * hop stage gets a line of its own — it is the
					 * whole point of this measurement. */
					{
						/* Shelley 231: the stage byte is sticky
						 * from the previous hop unless the seq
						 * names this round — and the TSC stamped
						 * just before the jmp says whether the
						 * thread even reached the hop. */
						unsigned long long now =
							__builtin_ia32_rdtsc();
						unsigned long long dt = 0, us = 0;

						if (c->d->hop_ts != 0 &&
						    now > c->d->hop_ts)
							dt = now - c->d->hop_ts;
						if (c->d->tsc_per_us != 0)
							us = dt / c->d->tsc_per_us;
						os_info("[grow] pid %d calls=%u mapped=%u\n",
						mm_id->pid,
						(unsigned)c->d->grow_calls,
						(unsigned)c->d->grow_mapped);
					os_info("[term-audit] pid %d "
						"in-tree kills=%u last_pid=%llu "
						"%s\n", mm_id->pid,
						(unsigned)c->d->term_calls,
						c->d->term_last_pid,
						c->d->term_calls == 0 ?
						"==> the killer is NOT in this tree" :
						"==> we killed something");
					uml_nt_sample_dump(c);
					os_info("[hop] pid %d stage=%llu "
							"seq=%llu round=%llu "
							"veh=%llu steps=%u "
							"dtsc=%llu us=%llu "
							"tsc_per_us=%llu\n",
							mm_id->pid,
							c->d->hop_stage,
							c->d->hop_seq,
							c->d->req_seq,
							c->d->veh_entries,
							(unsigned)c->d->round_step,
							dt, us,
							c->d->tsc_per_us);
					}
					/* ruling 223: the lever is only worth
					 * anything if it says it acted */
					os_info("[xs-lever] pid %d armed=%u "
						"dropped=%u\n",
						mm_id->pid,
						(unsigned)c->d->xs_lever,
						(unsigned)c->d->xs_dropped);
					/* Shelley 226: three victims, three rips, one
					 * class — the question is whether they sit in
					 * one library or anywhere at all. Name the VMA
					 * that holds the dying rip, with the offset. */
					uml_nt_death_rip_vma(c);
					uml_nt_death_exit_check(c);
					uml_nt_death_scan_exec(c);
					os_info("userspace: stub pid %d "
						"died silently (%lu from "
						"GetExitCodeProcess) — last "
						"cmd=%u rip=%llx rsp=%llx "
						"rax=%llx xs_flags=%x "
						"stub-stk=[%llx,%llx) "
						"sp=0x%llx min=0x%llx "
						"headroom=0x%llx "
						"retval=0x%llx err=%d "
						"step=%u halt=%u action=%u\n",
						mm_id->pid,
						(unsigned long)code,
						(unsigned)c->d->cmd,
						c->d->regs.rip,
						c->d->regs.rsp,
						c->d->regs.rax,
						(unsigned)c->d->xstate_flags,
						c->d->stub_sp_lim,
						c->d->stub_sp_base,
						c->d->stub_sp,
						c->d->stub_sp_min,
						c->d->stub_sp >
						  c->d->stub_sp_lim ?
						  c->d->stub_sp -
						  c->d->stub_sp_lim : 0,
						c->d->retval,
						(int)c->d->err,
						(unsigned)c->d->round_step,
						(unsigned)c->d->halt,
						(unsigned)c->d->action);
					uml_nt_dbg_summary();
					/* Shelley 219: the dump goes LAST. It used
					 * to run before the death line, and when
					 * MiniDumpWriteDump blocked the log simply
					 * stopped — an instrument that hides the
					 * observation it was meant to serve. */
					os_info("[dump] begin pid %d (all "
						"diagnostics above are already "
						"out)\n", mm_id->pid);
					if (uml_nt_dump_hook != NULL)
						os_info("[dump] returned %d\n",
							uml_nt_dump_hook(
							  (unsigned long)
							  mm_id->pid));
					else
						os_info("[dump] no hook\n");

					uml_nt_death_site(c);
					uml_nt_guestsite("rip", c->d->regs.rip, c);
					uml_nt_guestsite("rsp", c->d->regs.rsp, c);
					os_info("[site] last rax=0x%llx a0=0x%llx a1=0x%llx "
					        "a2=0x%llx nr=%llu\n",
					        c->d->regs.rax, c->d->args[0], c->d->args[1],
					        c->d->args[2], c->d->req_seq);
					os_info("[crumbs] pid %d "
						"round_step=%llu veh_entries=%llu "
						"unhandled_calls=%llu "
						"unhandled_seq=%llu "
						"action=%u cmd=%u\n",
						c->pid, c->d->round_step,
						c->d->veh_entries,
						c->d->unhandled_calls,
						c->d->unhandled_seq,
						(unsigned)c->d->action,
						(unsigned)c->d->cmd);
					uml_nt_ctx_ring_dump(c);
					os_info("[fs-tramp] pid %d off=%u "
						"skipped=%llu\n", c->pid,
						(unsigned)c->d->fs_tramp_off,
						c->d->fs_tramp_skipped);
					os_info("[ans-shape] pid %d cls=%u "
						"restarts=%llu other=%llu "
						"ring=%u%u%u%u%u%u%u%u trap=0x%llx\n",
						c->pid, c->ans_cls,
						c->ans_restarts, c->ans_other,
						c->ans_cls_ring[0],
						c->ans_cls_ring[1],
						c->ans_cls_ring[2],
						c->ans_cls_ring[3],
						c->ans_cls_ring[4],
						c->ans_cls_ring[5],
						c->ans_cls_ring[6],
						c->ans_cls_ring[7],
						c->res_trap_valid ?
						c->res_trap_rip : 0ull);
					{
		/* [regs-16] (Shelley 163): all sixteen, answered vs shared.
		 * A PROT_DONE round keeps the block invariant (no republish),
		 * so a register that MOVED between answer and death was
		 * written by somebody else — the op stream, a torn write, or
		 * the restore. '*' marks the movers. */
		const struct uml_nt_gp_regs *g = &c->d->regs;
		unsigned long long now[17];
		const char *nm[17] = { "rax", "rcx", "rdx", "rbx", "rsp",
			"rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
			"r12", "r13", "r14", "r15", "rip" };
		int i, nmoved = 0;

		now[0] = g->rax;  now[1] = g->rcx;  now[2] = g->rdx;
		now[3] = g->rbx;  now[4] = g->rsp;  now[5] = g->rbp;
		now[6] = g->rsi;  now[7] = g->rdi;  now[8] = g->r8;
		now[9] = g->r9;   now[10] = g->r10; now[11] = g->r11;
		now[12] = g->r12; now[13] = g->r13; now[14] = g->r14;
		now[15] = g->r15; now[16] = g->rip;
		for (i = 0; i < 17; i++)
			if (c->ans_regs[i] != now[i])
				nmoved++;
		if (nmoved >= 0 && c->d->pub_seq == c->ans_pub)
			nmoved = nmoved; /* same round: the count is real */
		if (c->d->pub_seq != c->ans_pub) {
			/* a NEW round was published after our answer: the
			 * block holds that round's trap state, and "moved"
			 * says nothing about who wrote what. */
			os_info("[regs-16] pid %d ans_cmd=%u now_cmd=%u "
				"STALE ans_pub=%llu now_pub=%llu — the block "
				"moved on to a later round; these are that "
				"round's registers, NOT a torn write\n",
				c->pid, c->ans_cmd, (unsigned)c->d->cmd,
				c->ans_pub, c->d->pub_seq);
			nmoved = -1;
		}
		os_info("[regs-16] pid %d ans_cmd=%u now_cmd=%u moved=%d\n",
			c->pid, c->ans_cmd, (unsigned)c->d->cmd, nmoved);
		for (i = 0; i < 17; i++)
			os_info("[regs-16] %s %-4s ans=0x%llx now=0x%llx%s\n",
				c->ans_regs[i] != now[i] ? "*" : " ", nm[i],
				c->ans_regs[i], now[i],
				c->ans_regs[i] != now[i] ? "  <-- MOVED" : "");
	}
	/* Shelley 177 (milestone): the register file at a FAULT round, with
	 * the shape of every value and which of them moved since the answer.
	 * The two garbage shapes have different sources and only a per-
	 * register reading can tell them apart. */
	if (c->d->cmd == UML_STUB_CMD_FAULT) {
		const struct uml_nt_gp_regs *g = &c->d->regs;
		unsigned long long now[17];
		const char *nm[17] = { "rax", "rcx", "rdx", "rbx", "rsp",
			"rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
			"r12", "r13", "r14", "r15", "rip" };
		int i, nshape = 0;

		now[0] = g->rax;  now[1] = g->rcx;  now[2] = g->rdx;
		now[3] = g->rbx;  now[4] = g->rsp;  now[5] = g->rbp;
		now[6] = g->rsi;  now[7] = g->rdi;  now[8] = g->r8;
		now[9] = g->r9;   now[10] = g->r10; now[11] = g->r11;
		now[12] = g->r12; now[13] = g->r13; now[14] = g->r14;
		now[15] = g->r15; now[16] = g->rip;
		for (i = 0; i < 17; i++)
			if (uml_nt_reg_shape(now[i]))
				nshape++;
		if (nshape > 0 && c->rg_logged < 12) {
			c->rg_logged++;
			/* Shelley 179: the REAL access type and address.
			 * fault_addr kept its v13 meaning (the armed slot
			 * VA); the pair (dr_hit_type, dr_hit_va) is what
			 * says whether this fault is a read, a write or a
			 * DEP/execute — and 0x601dce67 above was a RIP,
			 * never a fault VA. The 16 bytes at rip name the
			 * instruction (a `mov [reg],…` reads very
			 * differently from a `call` to a bad target). */
			/* The AV's OWN pair: stub.c publishes
			 * fault_type = ExceptionInformation[0] and
			 * fault_addr = ExceptionInformation[1] for every
			 * plain AV. dr_hit_* is the DR-hit publication and
			 * is meaningless on this path (label bug #10 —
			 * printed here as "(DR-only)" so it can never be
			 * read as this fault's truth again). */
			os_info("[fault-where] pid %d AV i0=%u (%s) "
				"i1=0x%llx | dr-only i0=%llu i1=0x%llx | "
				"rip=0x%llx nr=%llu rsp=0x%llx garbage=%d "
				"same_round=%s\n",
				c->pid,
				(unsigned)c->d->fault_type,
				c->d->fault_type == 0 ? "READ" :
				c->d->fault_type == 1 ? "WRITE" :
				c->d->fault_type == 8 ? "EXEC/DEP" :
				c->d->fault_type == UML_NT_FAULT_STEP ? "STEP" :
				c->d->fault_type == UML_NT_FAULT_WATCHPT ?
					"WATCHPT" :
				c->d->fault_type == UML_NT_FAULT_DREXEC ?
					"DREXEC" : "?",
				(unsigned long long)c->d->fault_addr,
				(unsigned long long)c->d->dr_hit_type,
				(unsigned long long)c->d->dr_hit_va,
				(unsigned long long)now[16],
				(unsigned long long)c->d->args[0],
				(unsigned long long)now[4], nshape,
				c->d->pub_seq == c->ans_pub ? "yes" : "STALE");
			os_info("[fault-where] (DR-only) i0=%llu i1=0x%llx "
				"ignored-for-AV\n",
				(unsigned long long)c->d->dr_hit_type,
				c->d->dr_hit_type == 0 ? "READ" :
				c->d->dr_hit_type == 1 ? "WRITE" :
				c->d->dr_hit_type == 8 ? "EXEC/DEP" : "?",
				(unsigned long long)c->d->dr_hit_va,
				(unsigned long long)now[16],
				(unsigned long long)c->d->args[0],
				(unsigned long long)now[4], nshape,
				c->d->pub_seq == c->ans_pub ? "yes" : "STALE");
			{
				unsigned char ib[16];
				int k, got = 0;

				MEMORY_BASIC_INFORMATION mbi;
				int ok, pprot;
				(void)pprot;

				for (k = 0; k < 16; k++)
					ib[k] = 0;
				ok = nt->VirtualQueryEx(c->proc,
						    (void *)(uintptr_t)now[16],
						    &mbi, sizeof(mbi)) > 0 &&
				     mbi.State == 0x1000 /* MEM_COMMIT */ &&
				     ((mbi.Protect & 0x0ff) == 0x20 /* EXECUTE_READ */ ||
				      (mbi.Protect & 0x0ff) == 0x40 /* EXECUTE_READWRITE */ ||
				      (mbi.Protect & 0x0ff) == 0x80 /* EXECUTE_WRITECOPY */ ||
				      (mbi.Protect & 0x0ff) == 0x02 /* READONLY */ ||
				      (mbi.Protect & 0x0ff) == 0x04 /* READWRITE */ ||
				      (mbi.Protect & 0x0ff) == 0x08 /* WRITECOPY */);
				if (ok) {
					SIZE_T got_n = 0;

					/* another process's memory: the host
					 * pointer is not ours to read */
					if (!nt->ReadProcessMemory(c->proc,
					    (void *)(uintptr_t)now[16],
					    ib, 16, &got_n) || got_n != 16) {
						for (k = 0; k < 16; k++)
							ib[k] = 0;
						ok = 0;
					}
				}
				for (k = 0; k < 16; k++)
					if (ib[k])
						got++;
				os_info("[fault-where] insn @0x%llx read=%s = "
					"%02x %02x %02x %02x %02x %02x %02x %02x"
					" %02x %02x %02x %02x %02x %02x %02x %02x"
					" (nonzero=%d)\n",
					(unsigned long long)now[16],
					ok ? "ok" : "NO-TRUTH",
					ib[0], ib[1], ib[2], ib[3], ib[4], ib[5],
					ib[6], ib[7], ib[8], ib[9], ib[10],
					ib[11], ib[12], ib[13], ib[14], ib[15],
					got);
			}
			os_info("[reg-fault] pid %d fault_addr=0x%llx nr=%llu "
				"garbage=%d same_round=%s\n",
				c->pid, (unsigned long long)c->d->fault_addr,
				(unsigned long long)c->d->args[0], nshape,
				c->d->pub_seq == c->ans_pub ? "yes" : "STALE");
			for (i = 0; i < 17; i++)
				os_info("[reg-fault] %-4s = 0x%016llx %-12s%s\n",
					nm[i], now[i],
					uml_nt_reg_shape_name(
						uml_nt_reg_shape(now[i])),
					(c->d->pub_seq == c->ans_pub &&
					 c->ans_regs[i] != now[i]) ?
					" <-- MOVED since answer" : "");
		}
	}
	/* Shelley 173: every VEH entry, stamped at the handler's first
	 * line. An exception here with no counterpart elsewhere is an
	 * exception that arrived while we were inside the dispatch. */
	{
		long at = c->d->entry_ring_at;
		unsigned i, n = at < 16 ? (unsigned)at : 16;

		os_info("[entry-ring] pid %d entries=%ld\n", c->pid, at);
		for (i = 0; i < n; i++) {
			struct uml_nt_entry_ring *r =
				&c->d->entry_ring[
					((unsigned long)(at - 1 - (long)i)) & 15u];

			os_info("[entry-ring] #%u n=%llu seq=%llu cmd=%llu "
				"code=0x%llx rip=0x%llx rsp=0x%llx\n",
				i, r->n, r->seq, r->cmd, r->code, r->rip,
				r->rsp);
		}
	}
	/* Shelley 172: the returned contexts, newest first — TF/RF and the
	 * DR state at each resume. The live #DB rounds and the fatal one are
	 * in here; the diff is the answer. */
	{
		unsigned at = c->d->ret_ring_at;
		unsigned i, n = at < 8 ? at : 8;

		os_info("[ret-ring] pid %d rounds=%u\n", c->pid, at);
		for (i = 0; i < n; i++) {
			struct uml_nt_ret_ring *r =
				&c->d->ret_ring[(at - 1 - i) & 7u];

			os_info("[ret-ring] #%u seq=%llu cmd=%llu act=%llu "
				"rip=0x%llx rsp=0x%llx rflags=0x%llx TF=%d RF=%d "
				"IF=%d dr0=0x%llx dr2=0x%llx dr6=0x%llx "
				"dr7=0x%llx ctx=0x%llx\n",
				i, r->seq, r->cmd, r->action, r->rip, r->rsp,
				r->eflags, (int)((r->eflags >> 8) & 1),
				(int)((r->eflags >> 16) & 1),
				(int)((r->eflags >> 9) & 1), r->dr0, r->dr2,
				r->dr6, r->dr7, r->ctx_flags);
		}
	}
	/* Shelley 170: the last grow decisions, in order — the one that
	 * matters is the round that died. */
	{
		unsigned at = c->sg_ring_at;
		unsigned i, n = at < 8 ? at : 8;

		os_info("[sg-ring] pid %d rounds=%u\n", c->pid, at);
		for (i = 0; i < n; i++) {
			int k = (int)((at - 1 - i) & 7u);

			os_info("[sg-ring] #%u rsp=0x%llx bottom=0x%llx "
				"top=0x%llx nvma=%d find=%s(0x%llx,0x%llx) "
				"sg=%d headroom=0x%llx\n",
				i, c->sg_ring[k].rsp, c->sg_ring[k].bottom,
				c->sg_ring[k].top, c->sg_ring[k].nvma,
				c->sg_ring[k].found ? "YES" : "NULL",
				c->sg_ring[k].find_start,
				c->sg_ring[k].find_end, c->sg_ring[k].sg,
				(c->sg_ring[k].rsp > c->sg_ring[k].bottom) ?
				c->sg_ring[k].rsp - c->sg_ring[k].bottom : 0);
		}
	}
	/* Shelley 167: the last exception entries, with the two numbers
	 * that decide between (a) a guest dereference, (b) the hop jumping
	 * to the wrong place, and (c) the dispatcher building a frame into
	 * the hole under a nearly-exhausted stack. */
	{
		unsigned at = c->d->exc_ring_at;
		unsigned i, n = at < 16 ? at : 16;

		os_info("[exc-ring] pid %d entries=%u\n", c->pid, at);
		for (i = 0; i < n; i++) {
			struct uml_nt_exc_ring *r =
				&c->d->exc_ring[(at - 1 - i) & 15u];

			os_info("[exc-ring] #%u seq=%llu code=0x%llx "
				"i0=%llu i1=0x%llx rip=0x%llx rsp=0x%llx "
				"headroom_run=0x%llx headroom_res=0x%llx "
				"fault_va(ok=%llu prot=0x%llx state=0x%llx) "
				"tramp_tgt=0x%llx dr0=0x%llx\n",
				i, r->seq, r->code, r->i0, r->i1, r->rip,
				r->rsp, r->headroom_run, r->headroom_res,
				r->fq_ok, r->fq_prot, r->fq_state, r->tgt,
				r->dtarget);
		}
	}
	/* Shelley 166 [prot-truth]: the ledger against Windows, at the
	 * two pages that decide the story. `bad` counts rounds where the
	 * ledger said the page is executable and Windows disagreed — the
	 * upgrade is the only thing that can make a fetch fault look like
	 * a resume that never happened. */
	{
		const struct uml_nt_vma *dv =
			c->mm ? uml_nt_vma_find(c->mm, c->d->regs.rip) : NULL;
		int ledger_exec = dv != NULL && (dv->prot & 0x60);
		int queried = c->d->fault_page_ok != 0;
		int actual_exec = queried && uml_nt_prot_executable(
			c->d->fault_page_prot);

		if (ledger_exec && queried && !actual_exec)
			c->d->prot_truth_bad++;
		os_info("[prot-truth] pid %d resume_page(vma prot=0x%x) "
			"actual=0x%x state=0x%x %s | trampoline actual=0x%x "
			"state=0x%x | bad=%llu last_prot_op va=0x%llx "
			"prot=0x%llx seq=%llu\n",
			c->pid, dv ? dv->prot : 0, c->d->fault_page_prot,
			c->d->fault_page_state,
			!queried ? "(VirtualQuery FAILED — no truth, not a "
				   "verdict: state=0 is what an unanswered "
				   "query looks like)" :
			(ledger_exec && !actual_exec) ?
			"<-- LEDGER SAYS EXEC, WINDOWS DOES NOT" : "",
			c->d->tramp_page_prot, c->d->tramp_page_state,
			c->d->prot_truth_bad, c->d->prot_op_va,
			c->d->prot_op_prot, c->d->prot_op_seq);
	}
	/* Shelley 165: the gamma witness — did the dispatcher apply the
	 * context we handed back? ask_* is what the stub requested at the
	 * last resume, and the counters say how often the next entry saw
	 * exactly that. A nonzero bad count with dr7 dropped is the OS
	 * refusing the debug state; a death with ask_round unattended is
	 * a resume that never reached a next entry. */
	os_info("[ctx-apply] pid %d asks=%llu ok=%llu bad=%llu dr_dropped=%llu "
		"last(ask rip=0x%llx rsp=0x%llx dr7=0x%llx flags=0x%llx)\n",
		c->pid, c->d->ask_round, c->d->ctx_check_ok,
		c->d->ctx_check_bad, c->d->dr_mismatch, c->d->ask_rip,
		c->d->ask_rsp, c->d->ask_dr7, c->d->ask_flags);
	os_info("[dr-exec] pid %d armed=%lu hits=%lu last_target=0x%llx "
		"==> %s\n", c->pid, c->drex_rounds, c->drex_hits_seen,
		c->drex_va,
		c->drex_hits_seen ? "the guest ran after at least one resume"
				  : "no armed resume was ever executed");
	os_info("[dr-exec] pid %d hits=%llu "
						"armed=%u va=0x%llx ==> %s\n",
						c->pid, c->d->drex_hits,
						c->drex_armed, c->drex_va,
						c->d->drex_hits ?
						"the guest RAN (death is at or after its first instruction)" :
						c->drex_armed ?
						"ARMED but never fired: the death happened BEFORE the guest executed anything" :
						"not armed this round");
					os_info("[d20-guard] pid %d guarded=%llu "
						"checks=%llu last rip=0x%llx "
						"vma=%u prot=0x%x off=0x%llx "
						"bytes=%02x%02x view=%u "
						"voff=0x%llx vbyte=%02x\n",
						c->pid, c->d->d20_guarded,
						c->gd_n, c->gd_rip, c->gd_vma,
						c->gd_prot, c->gd_off,
						c->gd_b0, c->gd_b1, c->gd_view,
						c->gd_voff, c->gd_vb0);
					os_info("[xstate] pid %d api=%llu want=%llu "
					        "mask=0x%llx cleared=%llu kept=%llu\n",
					        c->pid, c->d->xstate_api,
					        c->d->xstate_want, c->d->xstate_mask,
					        c->d->xstate_cleared, c->d->xstate_kept);
					os_info("[veh] pid %d phase=%llu "
						"in=0x%llx body=0x%llx "
						"out=0x%llx buf=0x%llx "
						"size=0x%llx ret=0x%llx "
						"want=0x%llx r10=0x%llx "
						"r11=0x%llx\n",
						c->pid, c->d->veh_phase,
						c->d->veh_sc_sp_in,
						c->d->veh_sc_sp_body,
						c->d->veh_sc_sp_out,
						c->d->veh_sc_buf,
						c->d->veh_sc_size,
						c->d->veh_sc_ret,
						c->d->veh_sc_want,
						c->d->veh_sc_r10,
						c->d->veh_sc_r11);
					/* v15 (D28 follow-up): the complete
					 * unowned-exception record — the
					 * console line that named it was cut
					 * to 19 bytes at the previous death
					 * sites. */
					if (c->d->unowned_seq == 1) {
						long long uo = -1;
						unsigned long long urun = 0;

						os_info("[stubtest] UNOWNED "
							"code=%08x last_cmd=%u "
							"rip=%llx rsp=%llx "
							"op=%llu addr=%llx\n",
							(unsigned)c->d->
								unowned_code,
							(unsigned)c->d->
								unowned_last_cmd,
							c->d->unowned_rip,
							c->d->unowned_rsp,
							c->d->unowned_op,
							c->d->unowned_addr);
						/* D28 follow-up: the exception
						 * RIP's backing run + the
						 * TO_GUEST ledger for it —
						 * the writer of a corrupted
						 * code page names itself. */
						if (c->mm != NULL)
							uo = uml_nt_vma_translate(
								c->mm,
								c->d->unowned_rip,
								1);
						if (uo >= 0) {
							struct uml_nt_vma *uv =
								uml_nt_vma_find(
								  c->mm,
								  c->d->unowned_rip);

							urun = ((unsigned long long)uo) &
								~(UML_NT_PHYS_RUN_SIZE - 1);
							if (uv != NULL)
								os_info("[stubtest] UNOWNED "
									"rip in vma [0x%llx,0x%llx) "
									"prot=0x%x flags=0x%x run=0x%llx\n",
									uv->start, uv->end,
									uv->prot, uv->flags,
									urun);
							uml_nt_uacc_towrite_dump(urun);
							/* Death-time imgwatch: is
							 * this run still the loaded
							 * image? MATCH = the wild
							 * entry came from control
							 * flow or a view/table
							 * divergence; MISMATCH =
							 * a rewritten page. */
							uml_nt_imgwatch_death_check(c,
										    urun);
						}
						/* v16 (resume-boundary
						 * milestone): the state the
						 * STUB itself saw. The
						 * kernel's table view is
						 * printed next to it — a
						 * divergence names the
						 * stale view; the stack
						 * ledger names a funnel
						 * write into the transfer's
						 * return slot. */
						if (c->d->unowned_v16 == 1) {
							unsigned long long *r =
								c->d->unowned_regs;
							unsigned long long *sk =
								c->d->unowned_stk;
							unsigned long long tq0 = 0, tq1 = 0,
								tq2 = 0, tq3 = 0;
							unsigned long long tins = 0;

							os_info("[stubtest] UNOWNED "
								"regs(stub) rax=%llx "
								"rcx=%llx rdx=%llx "
								"rbx=%llx rbp=%llx "
								"rsi=%llx rdi=%llx\n",
								r[0], r[1], r[2], r[3],
								r[5], r[6], r[7]);
							os_info("[stubtest] UNOWNED "
								"regs(stub) r8=%llx "
								"r9=%llx r10=%llx "
								"r11=%llx r12=%llx "
								"r13=%llx r14=%llx "
								"r15=%llx flags=%llx\n",
								r[8], r[9], r[10], r[11],
								r[12], r[13], r[14],
								r[15],
								c->d->unowned_flags);
							if (c->mm != NULL) {
								long long ti =
									uml_nt_vma_translate(
										c->mm,
										c->d->unowned_rip, 8);

								if (ti >= 0)
									__builtin_memcpy(&tins,
									       (char *)uml_boot.physmem_base +
									       ti, 8);
							}
							os_info("[stubtest] UNOWNED "
								"insn(stub)=%016llx "
								"table=%016llx ok=%u\n",
								c->d->unowned_insn, tins,
								c->d->unowned_insn_ok);
							if (c->mm != NULL) {
								long long si =
									uml_nt_vma_translate(
										c->mm,
										c->d->unowned_rsp, 8);

								if (si >= 0) {
									char *bp =
										(char *)uml_boot.physmem_base + si;

									__builtin_memcpy(&tq0, bp, 8);
									__builtin_memcpy(&tq1, bp + 8, 8);
									__builtin_memcpy(&tq2, bp + 16, 8);
									__builtin_memcpy(&tq3, bp + 24, 8);
								}
							}
							os_info("[stubtest] UNOWNED "
								"stk(stub) 0x%llx (%u): "
								"%016llx %016llx "
								"%016llx %016llx "
								"%016llx %016llx "
								"%016llx %016llx\n",
								c->d->unowned_rsp,
								c->d->unowned_stk_n,
								sk[0], sk[1], sk[2], sk[3],
								sk[4], sk[5], sk[6], sk[7]);
							os_info("[stubtest] UNOWNED "
								"stk(table) 0x%llx: "
								"%016llx %016llx "
								"%016llx %016llx\n",
								c->d->unowned_rsp,
								tq0, tq1, tq2, tq3);
							if (c->mm != NULL) {
								long long so =
									uml_nt_vma_translate(
										c->mm,
										c->d->unowned_rsp, 1);

								if (so >= 0)
									uml_nt_uacc_towrite_dump(
										((unsigned long long)so) &
										~(UML_NT_PHYS_RUN_SIZE - 1));
							}
						}
					}
					os_dump_core();
				}
				wait_tmo++;
				/* Shelley 195: under the debugger every round is
				 * slower by design — the debuggee is frozen
				 * between events — so the same second counts must
				 * not scream at a valid slow round. The report
				 * moves out to 20/60/120s on that path. */
				if (uml_nt_dbg_mode() ?
				    (wait_tmo == 20 || wait_tmo == 60 ||
				     wait_tmo == 120) :
				    (wait_tmo == 5 || wait_tmo == 15 ||
				     wait_tmo == 30)) {
					os_info("[userspace-tmo] stub pid %d "
						"wait=%us cmd=%u req=%llu "
						"done=%llu action=%u left=%d "
						"next=%d last_nr=%llu "
						"rip=0x%llx rsp=0x%llx "
						"ss_page=0x%llx\n",
						mm_id->pid, wait_tmo,
						(unsigned)c->d->cmd,
						c->d->req_seq,
						c->d->done_seq,
						(unsigned)c->d->action,
						c->plan_left,
						c->plan_next,
						c->last_nr,
						c->d->regs.rip,
						c->d->regs.rsp,
						c->d->ss_page);
				}
				continue;
			}
			if (w == 0xFFFFFFFFu /*WAIT_FAILED*/) {
				os_info("userspace: wait failed "
					"win32=%lu\n",
					nt->RtlGetLastWin32Error());
				nt->NtDelayExecution(0, &(LARGE_INTEGER){
					.QuadPart = -100000LL /*10ms*/ });
				continue;
			}
			/* Any other wait outcome: treat as the trap
			 * being ready (defensive; not reachable). */
			break;
		}
		}

		cmd = c->d->cmd;
		rc = uml_nt_pump_conn(c);
		/* M4.1 bench: one QPC timestamp per round — the delta
		 * from the previous round is the full syscall RTT and
		 * is recorded only while the bench window is open
		 * (bench.c; nothing logs here per round). */
		uml_nt_bench_sample();
		if (rc == 2) {
			/* execve conn switch: the old conn (and its d)
			 * were destroyed mid-round — no reg pull (d is
			 * gone). The loop re-reads current_mm_id(); the
			 * NEW conn bootstraps from current_pt_regs,
			 * where binfmt's start_thread wrote the entry. */
			os_info("userspace: exec conn switch → new mm "
				"pid %d\n",
				current_mm_id() ? current_mm_id()->pid :
						  -1);
			continue;
		}
		/* The INIT round carries no trap regs (d->regs is still
		 * the zeroed bootstrap state — the stub publishes INIT
		 * before its first VEH trap); pulling there would wipe
		 * the task's pt_regs with zeros. Every LATER publish
		 * (VEH syscall/fault) wrote d->regs for real. */
		if (cmd != UML_STUB_CMD_INIT)
			conn_pull_regs(regs, c->d, cmd);

		if (rc < 0) {
			printk(UM_KERN_ERR "userspace: stub protocol "
			       "error (pid %d)\n", mm_id->pid);
			os_dump_core();
		}
		if (rc == 1) {
			/* The guest exited (halt) or died (KILL): the
			 * stub is already terminated. M4.2: THIS task
			 * exits kernel-side — do_exit runs the full
			 * teardown (exit_mm → destroy_context closes
			 * the conn, exit_notify wakes a wait4 parent,
			 * the scheduler moves on). The init task dying
			 * here panics generically ("Attempted to kill
			 * init") — same loud exit-1 the gates assert.
			 * Signal-death fidelity (which signal, core
			 * dump semantics) is the M4 signals slice;
			 * the wait status carries the exit code only. */
			os_info("userspace: guest pid %d halted "
				"(exit %lu) — task exit\n",
				mm_id->pid,
				(unsigned long)c->exit_code);
			do_exit((long)(c->exit_code & 0xffu) << 8);
		}
	}
}

void new_thread(void *stack, jmp_buf *buf, void (*handler)(void))
{
	(*buf)[0].JB_IP = (unsigned long) handler;
	(*buf)[0].JB_SP = (unsigned long) stack + UM_THREAD_SIZE -
		sizeof(void *);
}

void switch_threads(jmp_buf *me, jmp_buf *you)
{
	if (UML_SETJMP(me) == 0)
		UML_LONGJMP(you, 1);
}

static jmp_buf initial_jmpbuf;

static void (*cb_proc)(void *arg);
static void *cb_arg;
static jmp_buf *cb_back;

#define INIT_JMP_NEW_THREAD 0
#define INIT_JMP_CALLBACK 1
#define INIT_JMP_HALT 2
#define INIT_JMP_REBOOT 3

int start_idle_thread(void *stack, jmp_buf *switch_buf)
{
	int n;

	/*
	 * Raw setjmp (no UML_SETJMP): this context is jumped back to
	 * from arbitrary stacks — signals state must not be restored
	 * here (same reasoning as upstream).
	 */
	n = setjmp(initial_jmpbuf);
	switch (n) {
	case INIT_JMP_NEW_THREAD:
		(*switch_buf)[0].JB_IP = (unsigned long) uml_finishsetup;
		(*switch_buf)[0].JB_SP = (unsigned long) stack +
			UM_THREAD_SIZE - sizeof(void *);
		break;
	case INIT_JMP_CALLBACK:
		(*cb_proc)(cb_arg);
		longjmp(*cb_back, 1);
		break;
	case INIT_JMP_HALT:
		kmalloc_ok = 0;
		return 0;
	case INIT_JMP_REBOOT:
		kmalloc_ok = 0;
		return 1;
	default:
		printk(UM_KERN_ERR "Bad setjmp return in %s - %d\n",
		       __func__, n);
		os_dump_core();
	}
	longjmp(*switch_buf, 1);

	/* unreachable */
	printk(UM_KERN_ERR "impossible long jump!");
	os_dump_core();
	return 0;
}

void initial_thread_cb_skas(void (*proc)(void *), void *arg)
{
	jmp_buf here;

	cb_proc = proc;
	cb_arg = arg;
	cb_back = &here;

	block_signals_trace();
	if (UML_SETJMP(&here) == 0)
		UML_LONGJMP(&initial_jmpbuf, INIT_JMP_CALLBACK);
	unblock_signals_trace();

	cb_proc = 0;
	cb_arg = 0;
	cb_back = 0;
}

void halt_skas(void)
{
	longjmp(initial_jmpbuf, INIT_JMP_HALT);
}

void reboot_skas(void)
{
	longjmp(initial_jmpbuf, INIT_JMP_REBOOT);
}
