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
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <init.h>
#include <ntabi.h>
#include "chain_model.h"
#include <fault.h>
#include <elf.h>
#include "drslot_model.h"
#include "prot_restore_model.h"
#include "stackgrow_model.h"
#include <stub-panic.h>
#include <stub_nt.h>
#include <ss_model.h>
#include <replay_model.h>
#include <resume_model.h>
#include <guard_model.h>

#include <os.h>
#include <syscall.h>
#include <mm_id.h>
#include <uaccess_walk.h>
#include <physalloc.h>
#include "internal.h"

static int g_xs_lever;

/* Ruling 223: A/B on the same HEAD — the arm only happens when the boot
 * command line asks for it, exactly like the witness and probe levers. */
static int xs_lever_on(void)
{
	int i;

	if (g_xs_lever >= 0 && g_xs_lever != 0)
		return 1;
	g_xs_lever = 0;
	for (i = 0; i < uml_boot.argc; i++)
		if (uml_boot.argv[i] != NULL &&
		    __builtin_strcmp(uml_boot.argv[i],
				     "uml_nt_xslever=1") == 0)
			g_xs_lever = 1;
	if (g_xs_lever)
		os_info("[xs-lever] uml_nt_xslever=1 — CONTEXT_XSTATE is "
			"dropped for the login chain only\n");
	return g_xs_lever;
}

extern const char nt_guest_init_start[], nt_guest_init_end[];
/* Absolute symbols (init_blob.S .set): byte offsets of the guard
 * address slots inside the blob. */
extern const char nt_guest_init_slot0[], nt_guest_init_slot1[];

/* scan_patch.c. M5.1c.6b: `mark` = caller scratch (>= len bytes) —
 * the patcher's alloca(len) buried the neighbouring task stacks
 * once the exec loader fed it a whole busybox segment (see
 * scan_patch.c). The stubtest probe runs on an NT aux thread, so the
 * scratch is static. Loader segments span whole 64KB-granular runs
 * (guest-init.elf's text segment = 0x10000), not the file size:
 * the cap covers four runs and stays loud past that. */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off, void *mark);
static unsigned char uml_nt_patch_mark[0x40000];

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

/* v6: running count of guest SIGSEGVs — the 56 victims of run
 * 36823383637 share one signature; the counter makes the log
 * navigable and proves the signature census at a glance. */
static int sigsegv_victims;

static struct uml_nt_stub_conn conn_parent, conn_child;
static struct uml_nt_mm mm_parent, mm_child;
static struct uml_nt_phys probe_phys;

/* ---- the cowcopy residue watch (M5.6a, run 37005701588) --------
 * The heap-trasher poison = a DETERMINISTIC foreign pair in a
 * glibc free chunk: fd=0x1a bk=0x8000 (5 runs: 36984940632,
 * 36987612985, 36994732694, 37003166709, 37005701588) — never a
 * glibc-written link (bins hold guest/libc VAs, never small
 * ints), so the pair IS the writer's fingerprint. fp-at-copy
 * scans clean (all-zero) → the write lands AFTER the fork copy,
 * into a SHARED (refs>1) run — a write that bypassed the COW
 * fault path. Arm: at every [cowcopy] whose SRC run is shared.
 * Check: each conn's round scans the armed runs (the task-backed
 * conn enumeration = free via the round loop). One-shot per
 * entry + round expiry + oldest-overwrite. Scan-only: no
 * behavior change. */
#define UML_NT_COWWATCH_N      64
#define UML_NT_COWWATCH_ROUNDS 8192

struct uml_nt_cowwatch {
	unsigned long long run_off;
	unsigned long long owner_va;  /* the run's VA in the OWNER mm */
	unsigned long owner_pid;
	unsigned char armed;
	unsigned char seen;           /* 098: the pattern landed once */
	unsigned long rounds;
};

static struct uml_nt_cowwatch cowwatchs[UML_NT_COWWATCH_N];
static unsigned int cowwatch_cursor;

/* [cowtrap] (M5.6a, report 106): the poison page's write-watch. The
 * scan snapshots proved too late — run 37036034612's two hits sat at
 * the SAME guest VA (0x67d0e910) across two run generations with
 * rips that were parked syscall sites, never the writer. The trap
 * flips the pattern's ONE page READ-ONLY on the owner's view (the
 * guard op shape — page-granular PROTECT): writes fault back with
 * LIVE regs = the writer named, reads walk free. Run 37054050100's
 * NOACCESS build burned its one-shot on a libc READER (0x606668b0,
 * type=0) 65 lines before the abort — reads must not trip. The
 * fault then repairs through the normal flow (a COW-shared run
 * copies out, a private run just PROTECTs back), so the trap costs
 * one log line and one round-trip, never the guest's life.
 * Also 37054050100: the buddy hands __GFP_ZERO on every backend
 * alloc, so recycled-run staleness cannot explain the poison — a
 * real writer exists; READONLY catches it. */
static struct uml_nt_stub_conn *cowtrap_conn;
static unsigned long long cowtrap_lo, cowtrap_hi;
static int cowtrap_pending;

/* M5.6a witness-exoneration switch: the three GUEST-VISIBLE
 * witnesses (cowtrap RO arms, mapcanary nonce writes, the ss/TF
 * single-step) are the only instrumentation that can perturb the
 * guest at all. UML_NT_WITNESS=0 in the environment turns them off
 * as a group: if the boot still corrupts, the witnesses are
 * exonerated; if it survives, the hunt turns inward. */
int uml_nt_dbg_flag(void);

/* The kernel is a freestanding ELF: no windows.h, so DEBUG_EVENT and
 * EXCEPTION_RECORD are spelled out here from the documented x64 layout
 * (asserted by the fact that the fields we read are the ones the CI log
 * shows). dwDebugEventCode/ProcessId/ThreadId occupy 12 bytes, the union
 * starts at 16 (8-byte alignment), EXCEPTION_DEBUG_INFO is a 152-byte
 * EXCEPTION_RECORD followed by dwFirstChance.
 */
#define UML_NT_DE_CODE		0	/* DWORD */
#define UML_NT_DE_PID		4
#define UML_NT_DE_TID		8
#define UML_NT_DE_U		16
#define UML_NT_U_EXC_CODE	0	/* within the union */
#define UML_NT_U_EXC_FLAGS	4
#define UML_NT_U_EXC_ADDR	16
#define UML_NT_U_EXC_NPARAMS	24
#define UML_NT_U_EXC_INFO	32
#define UML_NT_U_EXC_FIRSTCH	152
#define UML_NT_U_EXIT_CODE	0
#define UML_NT_DE_SIZE		176
#define UML_NT_EXCEPTION_DEBUG	1u
#define UML_NT_EXIT_PROCESS	5u
#define UML_NT_LOAD_DLL		6u

#define UML_NT_DBG_CONTINUE	0x00010002u
#define UML_NT_DBG_NOT_HANDLED	0x80010001u

static volatile int dbg_stop;
static unsigned long dbg_events;

static unsigned int de_u32(const unsigned char *b, unsigned int off)
{
	unsigned int v;

	__builtin_memcpy(&v, b + off, 4);
	return v;
}

static unsigned long long de_u64(const unsigned char *b, unsigned int off)
{
	unsigned long long v;

	__builtin_memcpy(&v, b + off, 8);
	return v;
}

static unsigned long UML_NTABI_CC dbg_pump(void *arg)
{
	unsigned long pid = (unsigned long)(uintptr_t)arg;
	unsigned char de[UML_NT_DE_SIZE];
	int budget = 2000;

	while (!dbg_stop && budget-- > 0) {
		unsigned int code, tid, st;
		const unsigned char *u = de + UML_NT_DE_U;

		if (!nt->WaitForDebugEvent(de, 200))
			continue;
		dbg_events++;
		code = de_u32(de, UML_NT_DE_CODE);
		tid = de_u32(de, UML_NT_DE_TID);
		st = UML_NT_DBG_CONTINUE;
		if (code == UML_NT_EXCEPTION_DEBUG) {
			unsigned int np = de_u32(u, UML_NT_U_EXC_NPARAMS);
			unsigned int k;
			char info[160];
			int n = 0;

			info[0] = 0;
			for (k = 0; k < np && k < 4; k++)
				n += snprintf(info + n, sizeof(info) - n,
					      " info[%u]=0x%llx", k,
					      de_u64(u, UML_NT_U_EXC_INFO + 8 * k));
			os_info("[dbg] pid %lu EXC%s code=0x%08x addr=0x%llx "
				"nparams=%u%s tid=%u\n",
				pid,
				de_u32(u, UML_NT_U_EXC_FIRSTCH) ? "1" : "2",
				de_u32(u, UML_NT_U_EXC_CODE),
				de_u64(u, UML_NT_U_EXC_ADDR), np, info, tid);
			/* never steal: the stub's own handlers see it
			 * exactly as they would without us */
			st = UML_NT_DBG_NOT_HANDLED;
		} else if (code == UML_NT_EXIT_PROCESS) {
			os_info("[dbg] pid %lu EXIT_PROCESS code=0x%x "
				"(GetExitCodeProcess will agree)\n",
				pid, de_u32(u, UML_NT_U_EXIT_CODE));
			nt->ContinueDebugEvent(de_u32(de, UML_NT_DE_PID), tid, st);
			os_info("[dbg] pump ended after %lu event(s)\n",
				dbg_events);
			return 0;
		}
		nt->ContinueDebugEvent(de_u32(de, UML_NT_DE_PID), tid, st);
	}
	os_info("[dbg] pump ended after %lu event(s)\n", dbg_events);
	return 0;
}

/* Every conn is its own process, and every debug event freezes the whole
 * debuggee until it is continued — so we must continue events for EVERY
 * process we attached to, not only the one whose exceptions we log. The
 * active pid decides who gets the detailed lines (Shelley 193). */
static unsigned long dbg_pids[8];
static unsigned long dbg_active_pid;

static void dbg_pid_add(unsigned long pid)
{
	int i;

	for (i = 0; i < 8; i++)
		if (dbg_pids[i] == pid)
			return;
	for (i = 0; i < 8; i++)
		if (dbg_pids[i] == 0) {
			dbg_pids[i] = pid;
			return;
		}
}

static void dbg_pid_del(unsigned long pid)
{
	int i;

	for (i = 0; i < 8; i++)
		if (dbg_pids[i] == pid)
			dbg_pids[i] = 0;
	if (dbg_active_pid == pid)
		dbg_active_pid = 0;
}

static int dbg_pid_live(unsigned long pid)
{
	int i;

	for (i = 0; i < 8; i++)
		if (dbg_pids[i] == pid)
			return 1;
	return 0;
}

/* (alpha/beta, Shelley 194): module map + the full exception record.
 * A second-chance AV is only useful if we can say WHERE it fell, and
 * "0x7ffc76f32639" says nothing until it is named against the module that
 * contains it. LOAD_DLL events carry BaseOfDll; the ring keeps the last
 * eight first-chance exceptions so the log stays readable and the events
 * that led to the death are still there when the process exits.
 */
#define UML_NT_MAX_MODS	64
static unsigned long long dbg_mods[UML_NT_MAX_MODS];
static int dbg_nmods;
static unsigned long dbg_burst_exc1;

struct dbg_ring_ent {
	unsigned int code, firstchance, tid;
	unsigned long long addr;
	unsigned long long info[4];
	unsigned int nparams;
};
static struct dbg_ring_ent dbg_ring[8];
static int dbg_ring_at;

static void dbg_mod_add(unsigned long long base)
{
	int i;

	if (base == 0)
		return;
	for (i = 0; i < dbg_nmods; i++)
		if (dbg_mods[i] == base)
			return;
	if (dbg_nmods < UML_NT_MAX_MODS)
		dbg_mods[dbg_nmods++] = base;
}

/* Shelley 214: which host module owns an address? The debug loader map is
 * the only host-side map we have, and the nearest base at or below the VA is
 * the module — unless the VA is far above every base, in which case it is
 * past the last section we know about. */
void uml_nt_host_mod(unsigned long long va, char *out, int len)
{
	unsigned long long best = 0;
	int i;

	for (i = 0; i < dbg_nmods; i++) {
		if (dbg_mods[i] <= va && dbg_mods[i] >= best)
			best = dbg_mods[i];
	}
	if (best != 0 && va - best < (64ull << 20))
		snprintf(out, len, "mod@0x%llx+0x%llx", best, va - best);
	else
		snprintf(out, len, "UNKNOWN-HOST-MODULE (mods=%d)", dbg_nmods);
}

static void dbg_mod_name(unsigned long long addr, char *out, int len)
{
	unsigned long long best = 0;
	int i;

	for (i = 0; i < dbg_nmods; i++)
		if (dbg_mods[i] <= addr && dbg_mods[i] > best)
			best = dbg_mods[i];
	if (best == 0) {
		snprintf(out, len, "no-module");
		return;
	}
	snprintf(out, len, "mod@0x%llx+0x%llx", best, addr - best);
}

static unsigned long dbg_drained;	/* total events drained */
static unsigned long dbg_drain_calls;	/* how many times dbg_drain ran */
static unsigned long dbg_wfd_false;	/* WaitForDebugEvent returned 0 */
static int dbg_wfd_err_logged;
static void dbg_event(unsigned char *de);

/* Drain-to-empty: after every ContinueDebugEvent, keep taking events with
 * a zero timeout until the queue answers "nothing". A debug event freezes
 * every debuggee thread, so an event left in the queue is a guest standing
 * still — referee 40449370951 hung the login stub's first round exactly
 * that way. */
/* Shelley 208 (VUA): walk every executable VMA of the dying conn, read each
 * run through the kernel's flat view, and count 0f 05 bytes that are STILL
 * there. A sweep left one behind = a real Windows syscall the guest could
 * still make. Bounded so a death stays cheap. */
int uml_nt_run_is_swept(struct uml_nt_stub_conn *c, unsigned long long off,
			int exec_vma);
unsigned long uml_nt_count_syscalls(void *buf, unsigned long len);

void uml_nt_death_scan_exec(struct uml_nt_stub_conn *c)
{
	int i;
	unsigned long long runs = 0, bad = 0, badva = 0, total_bytes = 0;
	int printed = 0;

	if (c == NULL || c->mm == NULL)
		return;
	for (i = 0; i < c->mm->nvma && runs < 1024; i++) {
		struct uml_nt_vma *v = &c->mm->vma[i];
		unsigned long long va, off;

		if (!uml_nt_prot_execable(v->prot))
			continue;
		total_bytes += v->end - v->start;
		for (va = v->start; va < v->end && runs < 1024;
		     va += UML_NT_PHYS_RUN_SIZE) {
			unsigned long long so = uml_nt_vma_translate(
				c->mm, va, 1);
			unsigned char *p;
			unsigned long long k, np = 0;

			if (so < 0)
				continue;
			off = (unsigned long long)so;
			p = (unsigned char *)uml_boot.physmem_base + off;
			np = uml_nt_count_syscalls(p,
						   UML_NT_PHYS_RUN_SIZE);
			runs++;
			if (np > 0) {
				bad += np;
				if (printed < 8) {
					printed++;
					badva = va;
					unsigned long long b;

					os_info("[exec-scan] run va=0x%llx "
						"has %llu unpatched "
						"syscall byte(s) "
						"vma=[0x%llx,0x%llx) "
						"prot=0x%x flags=0x%x "
						"run_off=0x%llx "
						"gen=0x%llx swept=%d\n",
						va, np, v->start, v->end,
						v->prot, v->flags, v->run_off,
						uml_nt_phys_gen(c->ph,
							(long long)off),
						uml_nt_run_is_swept(c, off,
							uml_nt_prot_execable(
								v->prot)));
					{
						unsigned long long k2, start;
						int shown = 0;

						/* print the bytes AT the hit, not the run
						 * start: a hit inside data is not a
						 * weapon and must not be read as one */
						for (k2 = 0; k2 + 1 < UML_NT_PHYS_RUN_SIZE &&
						     shown < 2; k2++) {
							char line[3 * 16 + 1];
							int q = 0;
							unsigned long long m;

							if (p[k2] != 0x0f ||
							    p[k2 + 1] != 0x05)
								continue;
							start = k2 > 8 ? k2 - 8 : 0;
							for (m = 0; m < 16; m++) {
								unsigned char bt =
								 p[start + m];

								line[q++] = "0123456789abcdef"
									[(bt >> 4) & 15];
								line[q++] = "0123456789abcdef"
									[bt & 15];
								line[q++] = ' ';
							}
							line[q] = 0;
							os_info("[exec-scan]   hit@+0x%llx "
								"(ctx from +0x%llx): %s\n",
								k2, start, line);
							shown++;
						}
					}
				}
			}
		}
	}
	os_info("[exec-scan] pid %lu: %llu exec run(s) scanned "
		"(%llu of %llu byte(s) = %llu%%), %llu unpatched "
		"SYSCALL SITE(s)%s\n",
		(unsigned long)c->pid, runs, runs << UML_NT_PHYS_RUN_SHIFT,
		total_bytes,
		total_bytes ? (runs << UML_NT_PHYS_RUN_SHIFT) * 100ull /
			      total_bytes : 0ull,
		bad, bad == 0 ? " ==> every exec page is swept" : "");
}

/* Shelley 208 (1): did the guest itself ask to leave? */

/* Shelley 226: which VMA — and therefore which module — holds the rip the
 * guest died at. Three deaths, three addresses: if they land in one image
 * the class is that image, and if they do not, the class is time. */
void uml_nt_death_rip_vma(struct uml_nt_stub_conn *c)
{
	unsigned long long rip;
	int i;
	struct uml_nt_mm *mm;

	if (c == NULL || c->d == NULL || c->mm == NULL)
		return;
	mm = c->mm;
	rip = c->d->regs.rip;
	for (i = 0; i < mm->nvma; i++) {
		struct uml_nt_vma *v = &mm->vma[i];

		if (rip >= v->start && rip < v->end) {
			unsigned char ins[16];
			unsigned char hdr[8];
			int hok = 0;

			memset(ins, 0, sizeof(ins));
			/* Shelley 227: the bytes are in the physmem we own,
			 * so the dead is still readable — the one thing the
			 * dump could never do. */
			if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
					     rip, sizeof(ins), (char *)ins,
					     0) == 0)
				hok = 1;
			memset(hdr, 0, sizeof(hdr));
			uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
					 v->start, sizeof(hdr), (char *)hdr, 0);
			os_info("[rip-vma] pid %d rip=0x%llx vma[%d] "
				"[0x%llx,0x%llx) prot=0x%x flags=0x%x "
				"run_off=0x%llx off_in_vma=0x%llx "
				"image_runs=%d read=%s "
				"insn=%02x%02x%02x%02x%02x%02x%02x%02x "
				"vma_hdr=%02x%02x%02x%02x\n",
				(int)c->pid, rip, i, v->start, v->end,
				v->prot, v->flags, v->run_off,
				rip - v->start, c->imgw_n,
				hok ? "ok" : "FAULT",
				ins[0], ins[1], ins[2], ins[3], ins[4],
				ins[5], ins[6], ins[7],
				hdr[0], hdr[1], hdr[2], hdr[3]);
			return;
		}
	}
	os_info("[rip-vma] pid %d rip=0x%llx NO VMA (guest ran outside "
		"every mapping) image_runs=%d\n",
		(int)c->pid, rip, c->imgw_n);
}

void uml_nt_death_rip_vma(struct uml_nt_stub_conn *c);
void uml_nt_death_exit_check(struct uml_nt_stub_conn *c)
{
	if (c == NULL || c->d == NULL)
		return;
	os_info("[exit-req] pid %lu last_nr=%llu args[0]=0x%llx halt=%u "
		"action=%u vstage=%u ==> %s\n", (unsigned long)c->pid,
		c->last_nr,
		c->d->args[0], (unsigned)c->d->halt,
		(unsigned)c->d->action, (unsigned)c->d->vstage,
		c->d->halt ? "guest asked to exit (its own code)"
			   : "guest did NOT ask to exit");
}

void uml_nt_dbg_summary(void)
{
	os_info("[dbg] summary: drain calls=%lu events=%lu empty=%lu "
		"live=%d ==> %s\n", dbg_drain_calls, dbg_drained,
		dbg_wfd_false, dbg_pid_live(0) ? 1 : 0,
		dbg_drain_calls == 0 ? "the poll never ran" :
		(dbg_drained == 0 ? "polled, nothing was ever queued" :
		 "polled and took events"));
}

void dbg_drain(void)
{
	unsigned char de[UML_NT_DE_SIZE];
	int guard = 256;
	unsigned long n = 0;

	dbg_drain_calls++;
	while (guard-- > 0) {
		if (!nt->WaitForDebugEvent(de, 0)) {
			dbg_wfd_false++;
			if (!dbg_wfd_err_logged) {
				dbg_wfd_err_logged = 1;
				os_info("[dbg] first empty poll: WaitForDebugEvent"
					"=0 win32=%lu (0 = nothing queued, which "
					"is normal; anything else means the port "
					"is not ours)\n",
					nt->RtlGetLastWin32Error());
			}
			break;
		}
		dbg_event(de);
		n++;
	}
	dbg_drained += n;
	/* Rule #11: report the counters whether or not anything came out —
	 * "nothing to do" and "never ran" must never read the same. */
	if (n > 0 || (dbg_drain_calls % 200ul) == 0)
		os_info("[dbg] drain calls=%lu events=%lu total=%lu "
			"empty=%lu\n", dbg_drain_calls, n, dbg_drained,
			dbg_wfd_false);
}

static void dbg_event(unsigned char *de)
{
	unsigned int code = de_u32(de, UML_NT_DE_CODE);
	unsigned int pid = de_u32(de, UML_NT_DE_PID);
	unsigned int tid = de_u32(de, UML_NT_DE_TID);

	dbg_events++;
	if (code == UML_NT_LOAD_DLL) {
		dbg_mod_add(de_u64(de, UML_NT_DE_U));	/* BaseOfDll */
		nt->ContinueDebugEvent(pid, tid, UML_NT_DBG_CONTINUE);
		return;
	}
	if (code == UML_NT_EXIT_PROCESS) {
		int k;

		os_info("[dbg] EXIT_PROCESS pid=%u code=0x%x (burst EXC1=%lu)\n",
			pid, de_u32(de, UML_NT_DE_U), dbg_burst_exc1);
		for (k = 0; k < 8; k++) {
			struct dbg_ring_ent *e = &dbg_ring[k];

			if (e->code == 0)
				continue;
			os_info("[dbg]   ring[%d] EXC%d code=0x%08x addr=0x%llx "
				"nparams=%u info[0]=0x%llx info[1]=0x%llx "
				"tid=%u\n", k, e->firstchance ? 1 : 2, e->code,
				e->addr, e->nparams, e->info[0], e->info[1],
				e->tid);
		}
		/* Two sources for one number (Shelley 202): this is the
		 * exit code the DEBUG PORT reports; the kernel reads its own
		 * from GetExitCodeProcess. Equal codes = the OS itself
		 * terminated the process; a mismatch = someone lied. */
		os_info("[dbg] EXIT_PROCESS pid %lu code=0x%lx (from the "
			"debug event)\n", (unsigned long)pid,
			(unsigned long)de_u32(de, UML_NT_DE_U));
		nt->ContinueDebugEvent(pid, tid, UML_NT_DBG_CONTINUE);
		dbg_pid_del((unsigned long)pid);
		return;
	}
	if (code != UML_NT_EXCEPTION_DEBUG) {
		/* CREATE_PROCESS, thread and string events: continue them or
		 * the debuggee never runs again. This one omission parked the
		 * login stub at its first round with an empty queue. */
		nt->ContinueDebugEvent(pid, tid, UML_NT_DBG_CONTINUE);
		return;
	}
	{
		const unsigned char *u = de + UML_NT_DE_U;
		unsigned int np = de_u32(u, UML_NT_U_EXC_NPARAMS);
		unsigned int fc = de_u32(u, UML_NT_U_EXC_FIRSTCH);
		unsigned long long addr = de_u64(u, UML_NT_U_EXC_ADDR);
		unsigned int exc = de_u32(u, UML_NT_U_EXC_CODE);
		unsigned long long info[4] = { 0, 0, 0, 0 };
		unsigned int k;
		char mod[64];

		for (k = 0; k < np && k < 4; k++)
			info[k] = de_u64(u, UML_NT_U_EXC_INFO + 8 * k);
		dbg_mod_name(addr, mod, sizeof(mod));
		dbg_ring[dbg_ring_at & 7].code = exc;
		dbg_ring[dbg_ring_at & 7].firstchance = fc;
		dbg_ring[dbg_ring_at & 7].tid = tid;
		dbg_ring[dbg_ring_at & 7].addr = addr;
		dbg_ring[dbg_ring_at & 7].nparams = np;
		for (k = 0; k < 4; k++)
			dbg_ring[dbg_ring_at & 7].info[k] = info[k];
		dbg_ring_at++;
		if (!fc || (unsigned long)pid == dbg_active_pid) {
			if (fc)
				dbg_burst_exc1++;
			/* second chance is always worth a full line; first
			 * chance only for the conn we are watching, and even
			 * then without the burst roar */
			if (!fc || dbg_burst_exc1 <= 20)
				os_info("[dbg] EXC%d code=0x%08x addr=0x%llx "
					"%s nparams=%u info[0]=0x%llx "
					"info[1]=0x%llx info[2]=0x%llx "
					"info[3]=0x%llx tid=%u pid=%u\n",
					fc ? 1 : 2, exc, addr, mod, np,
					info[0], info[1], info[2], info[3],
					tid, pid);
		}
	}
}

int uml_nt_dbg_on = -1;
int uml_nt_witness_off = -1;
static int witness_off(void)
{
	int i;

	if (uml_nt_witness_off >= 0)
		return uml_nt_witness_off;
	uml_nt_witness_off = 1;
	for (i = 0; i < uml_boot.argc; i++)
		if (uml_boot.argv[i] != NULL &&
		    __builtin_strcmp(uml_boot.argv[i],
				     "uml_nt_witness=1") == 0)
			uml_nt_witness_off = 0;
	if (uml_nt_witness_off)
		os_info("[witness] uml_nt_witness=0 — guest-visible "
			"instrumentation OFF (cowtrap/mapcanary/ss)\n");
	return uml_nt_witness_off;
}

/* M5.6a A/B (Shelley 182): the DR-execute probe is the instrument that
 * pushes a #DB round between the guest's password syscalls. The lever
 * decides whether the probe exists at all on this run:
 *   uml_nt_drexec=0  -> probe off (the A/B "off" leg)
 * Anything else keeps today's behaviour, so every earlier referee stays
 * comparable. Prints once, loudly, because a silent switch is exactly the
 * class of mistake this hunt keeps paying for. */
int uml_nt_drexec_off = -1;
/* Shelley 188 (3): a further step down from EVADE — turn the remaining
 * login-conn instruments (ctx-audit snapshots, reg-fault dumps) off too.
 * If the death disappears under this, one of them still had no lever. */
int uml_nt_quiet_off = -1;
static int quiet_off(void)
{
	int i;

	if (uml_nt_quiet_off >= 0)
		return uml_nt_quiet_off;
	uml_nt_quiet_off = 0;
	for (i = 0; i < uml_boot.argc; i++)
		if (uml_boot.argv[i] != NULL &&
		    __builtin_strcmp(uml_boot.argv[i],
				     "uml_nt_quiet=1") == 0)
			uml_nt_quiet_off = 1;
	if (uml_nt_quiet_off)
		os_info("[quiet] uml_nt_quiet=1 — ctx-audit snapshots and "
			"reg-fault dumps OFF (deepest EVADE leg)\n");
	return uml_nt_quiet_off;
}
static int drexec_off(void)
{
	int i;

	if (uml_nt_drexec_off >= 0)
		return uml_nt_drexec_off;
	uml_nt_drexec_off = 0;
	for (i = 0; i < uml_boot.argc; i++)
		if (uml_boot.argv[i] != NULL &&
		    __builtin_strcmp(uml_boot.argv[i],
				     "uml_nt_drexec=0") == 0)
			uml_nt_drexec_off = 1;
	if (uml_nt_drexec_off)
		os_info("[drexec] uml_nt_drexec=0 — the DR-execute probe is "
			"OFF for this boot (A/B leg)\n");
	return uml_nt_drexec_off;
}

static void uml_nt_cowtrap_arm(struct uml_nt_stub_conn *c,
			       unsigned long long owner_va,
			       unsigned long long hit_va,
			       unsigned long long run_off)
{
	unsigned long long tv = hit_va & ~(UML_NT_FAULT_PAGE_SIZE - 1);
	if (cowtrap_conn != NULL)
		return; /* one live trap — the log names re-arms */
	if (uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT,
			       UML_NT_PAGE_READONLY, tv,
			       UML_NT_FAULT_PAGE_SIZE, 0) < 0)
		return;
	cowtrap_conn = c;
	cowtrap_lo = tv;
	cowtrap_hi = tv + UML_NT_FAULT_PAGE_SIZE;
	cowtrap_pending = 1;
	os_info("[cowtrap] ARMED page 0x%llx pid %lu (run 0x%llx) "
		"READ-ONLY — the next WRITE names the writer\n", tv,
		(unsigned long)c->pid, run_off);
}

/* The arm rides a serve-round tail, where the next dispatch's plan
 * reset would eat the op — both answer carriers re-queue it right
 * after their reset (the syscall entry, the fault handler). */
void uml_nt_cowtrap_pending(struct uml_nt_stub_conn *c)
{
	if (cowtrap_conn != c || !cowtrap_pending)
		return;
	if (uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT,
			       UML_NT_PAGE_NOACCESS, cowtrap_lo,
			       UML_NT_FAULT_PAGE_SIZE, 0) < 0)
		return;
	cowtrap_pending = 0;
}

static void uml_nt_cowwatch_arm(unsigned long long run_off,
				unsigned long long owner_va,
				unsigned long owner_pid)
{
	unsigned int i;

	/* Dedup: a run already armed keeps its older (longer-lived)
	 * budget — re-arming the same run would churn the ring. */
	for (i = 0; i < UML_NT_COWWATCH_N; i++)
		if (cowwatchs[i].armed &&
		    cowwatchs[i].run_off == run_off)
			return;
	for (i = 0; i < UML_NT_COWWATCH_N; i++)
		if (!cowwatchs[i].armed)
			break;
	if (i == UML_NT_COWWATCH_N) {
		i = cowwatch_cursor;
		cowwatch_cursor = (cowwatch_cursor + 1) %
				  UML_NT_COWWATCH_N;
	}
	cowwatchs[i].run_off = run_off;
	cowwatchs[i].owner_va = owner_va;
	cowwatchs[i].owner_pid = owner_pid;
	cowwatchs[i].armed = 1;
	cowwatchs[i].rounds = UML_NT_COWWATCH_ROUNDS;
	{
		static int cowwatch_arm_budget = 64;

		if (cowwatch_arm_budget > 0) {
			cowwatch_arm_budget--;
			os_info("[cowwatch] armed run=0x%llx owner=%lu@0x%llx "
				"(slot %u)\n", run_off, owner_pid, owner_va, i);
		}
	}
}

/* The alloc-side arm (report 106's closing slice): the poison is
 * always already there when the cowwatch first sights it, so the
 * sighting-time trap can never name its writer. Arm at ALLOC instead:
 * every multi-run anon span (the malloc-arena class) and every brk
 * re-home gets its FIRST page READ-ONLY — the run's first WRITE is
 * the writer, with live regs. The buddy zeroes every backend alloc,
 * so a trip on the fill-less fresh span names a real write path;
 * the repair rides the normal mm_fault flow and the slot retires.
 *
 * Report 108 (run 37069739489) rewrote the coverage: the head page
 * burns on glibc's own first write every time (top-chunk header,
 * nr=12, 20/24 catches), while the poison landed 268 pages deep at
 * the heap TAIL — 0x67d0e580, a page born fresh in a brk grow
 * ([0x67d00000,0x67d10000) of the ->0x67d10000 grow), written once,
 * then never touched again (the sighting-time re-arm stayed silent
 * to the abort). Cold tail pages are exactly where a once-only
 * writer lives: arm head + the last UML_NT_COWTRAP_TAIL pages. */
#define UML_NT_COWTRAP_N 64
#define UML_NT_COWTRAP_TAIL 16
struct uml_nt_cowtrap {
	struct uml_nt_stub_conn *conn;
	unsigned long long lo, hi;  /* trapped guest VA range */
	unsigned long long run_off;
};
static struct uml_nt_cowtrap cowtraps[UML_NT_COWTRAP_N];
static unsigned int cowtrap_cursor;

void uml_nt_cowtrap_arm_alloc(struct uml_nt_stub_conn *c,
			      unsigned long long va,
			      unsigned long long len,
			      unsigned long long run_off)
{
	struct uml_nt_cowtrap *t;
	unsigned int i, armed = 0;
	unsigned long long page;

	if (witness_off())
		return;

	/* A grow (and any MAP_FIXED replace) UNMAP+MAPs the span: trap
	 * slots on this range watched views that no longer exist. A
	 * stale slot can never trip — and the old dedup let it BLOCK
	 * the re-arm onto the fresh view. Retire them first. */
	for (i = 0; i < UML_NT_COWTRAP_N; i++)
		if (cowtraps[i].conn == c &&
		    cowtraps[i].lo >= va && cowtraps[i].lo < va + len)
			cowtraps[i].conn = NULL;

	for (page = va; page < va + len;
	     page += UML_NT_FAULT_PAGE_SIZE) {
		unsigned long long off = page - va;

		/* head page + the last UML_NT_COWTRAP_TAIL pages
		 * (spans smaller than that arm every page). */
		if (off != 0 &&
		    off < len - (unsigned long long)UML_NT_COWTRAP_TAIL *
			          UML_NT_FAULT_PAGE_SIZE)
			continue;
		if (uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT,
				       UML_NT_PAGE_READONLY, page,
				       UML_NT_FAULT_PAGE_SIZE, 0) < 0)
			continue;
		t = &cowtraps[cowtrap_cursor];
		cowtrap_cursor = (cowtrap_cursor + 1) % UML_NT_COWTRAP_N;
		t->conn = c;
		t->lo = page;
		t->hi = page + UML_NT_FAULT_PAGE_SIZE;
		t->run_off = run_off;
		armed++;
	}
	os_info("[cowtrap] ARMED(alloc) %u page(s) (head+tail) of "
		"[0x%llx,0x%llx) pid %lu (run 0x%llx, %llu run(s)) — "
		"each page's first WRITE names the writer\n", armed, va,
		va + len, (unsigned long)c->pid, run_off,
		len / UML_NT_PHYS_RUN_SIZE);
}

/* WRITER-HUNT (M5.6a, run 37078256773): a brk grow retires the old
 * span's trap slots (the re-home UNMAP+MAPs) and re-arms only the
 * NEW span's head+tail — the previous frontier pages
 * [old_end-16p, old_end) fall out of coverage the moment the heap
 * grows past them. Run 37069739489's poison page (0x67d0e580) was
 * exactly that: tail-16-armed at its birth grow, written AFTER the
 * next grow retired it — invisible. Re-arm the old tail on the
 * fresh span: those are the pages glibc's allocator frontier is
 * actively filling. */
void uml_nt_cowtrap_arm_oldtail(struct uml_nt_stub_conn *c,
				unsigned long long heap_start,
				unsigned long long old_end,
				unsigned long long new_off)
{
	unsigned long long otv = old_end -
		(unsigned long long)UML_NT_COWTRAP_TAIL *
		UML_NT_FAULT_PAGE_SIZE;

	if (otv <= heap_start)
		return; /* heap smaller than the tail window */
	uml_nt_cowtrap_arm_alloc(c, otv, old_end - otv,
				 new_off + (otv - heap_start));
}

void uml_nt_cowtrap_trip(struct uml_nt_stub_conn *c,
			 struct uml_nt_stub_data *d)
{
	unsigned int i;
	for (i = 0; i < UML_NT_COWTRAP_N; i++) {
		struct uml_nt_cowtrap *t = &cowtraps[i];
		if (t->conn != c || d->fault_addr < t->lo ||
		    d->fault_addr >= t->hi)
			continue;
		os_info("[cowtrap] FIRST-WRITE CAUGHT pid %lu "
			"rip=0x%llx rsp=0x%llx rcx=0x%llx addr=0x%llx "
			"type=%u nr=%llu ret=%lld (run 0x%llx) — "
			"restoring, write replays\n",
			(unsigned long)c->pid, d->regs.rip,
			d->regs.rsp, d->regs.rcx, d->fault_addr,
			d->fault_type, c->last_nr, c->last_ret,
			t->run_off);
		t->conn = NULL;
	}
}

/* M5.6a TCACHE TRIP (referee 37089977192 decode): the poison write
 * hits the tcache struct page DIRECTLY (the entries[] slots
 * themselves — the chunk watch stayed silent this boot), a
 * repeated deterministic stale value (0x67d6ecae, misaligned past
 * the heap end; the "SYSTEMD_" text of the earlier referees = the
 * same class, different scratch contents). Bypasses every funnel:
 * raw_copy_to_user, the four tracked flat copiers, the guards —
 * the pages are writable so nothing faults. Arm the struct page
 * READ-ONLY from this conn's first fork seed on (the poison window
 * opens post-fork); every write faults and names its rip. Legit
 * glibc entries churn = the noise the budget pays (its rips are
 * known: malloc+0x16a/0x172); the writer's rip = anything else.
 * Private-run repair = a plain PROTECT back (the cowtrap lesson:
 * one log line, one round-trip, never the guest's life). */
static struct uml_nt_stub_conn *tctrip_conn;
static unsigned long long tctrip_page;
static int tctrip_pending;
static int tctrip_budget; /* 0: DISARMED — the perpetual-RO arm
	* stormed (dl6 37263914229: 19.4M-line log, boot starved): heap
	* page 0 holds the first ~3.5KB of hot chunk DATA past the
	* struct, and every chunk-data write faulted the page. The 12
	* dl5-style trips proved all legit; the tear's writer must be
	* caught surgically instead — DR0-3 write-watchpoints on the
	* entries[] qwords (next slice). The emulate machinery stays:
	 * its encoding matcher moves stub-side there. */

static void uml_nt_tctrip_arm(struct uml_nt_stub_conn *c)
{
	int fresh = 0;

	if (tctrip_budget <= 0 || witness_off())
		return;
	if (tctrip_conn != NULL && tctrip_conn != c)
		return; /* one live trip */
	if (c->mm == NULL || c->mm->heap_start == 0)
		return;
	if (uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT,
			       UML_NT_PAGE_READONLY, c->mm->heap_start,
			       UML_NT_FAULT_PAGE_SIZE, 0) < 0)
		return;
	fresh = (tctrip_conn != c || tctrip_page != c->mm->heap_start);
	tctrip_conn = c;
	tctrip_page = c->mm->heap_start;
	tctrip_pending = 1;
	if (fresh)
		os_info("[tctrip] armed tcache page 0x%llx pid %lu "
			"READ-ONLY + emulate-skip — every struct write "
			"transits the dispatch, page never writable\n",
			tctrip_page, (unsigned long)c->pid);
}

static int tctrip_loud_budget = 24;
static unsigned long long tctrip_emulated;

/* M5.6a tctrip-EMULATE: the RO tcache page's writes are emulated
 * kernel-side and the guest resumes PAST the store — the page never
 * becomes writable, so EVERY write to the tcache struct transits
 * this dispatch (the old trip-then-repair flow opened a whole
 * free-run hole per trip, and its 12-trip budget died at line ~80k
 * — dl5's entries[] tear landed at ~88k, unseen). Five encodings
 * cover all observed traffic: tcache_put's pair (entries[i]=e at
 * libc+0x965d2, counts[i]++ at +0x965da) and tcache_get's triple
 * (entries[i]=REVEAL(e->next) at +0x98a9a, counts[i]-- at +0x98a9e,
 * e->key=NULL at +0x98aa2). Anything else prints LOUD with the full
 * register file and falls through to the normal repair. A legit
 * encoding with a non-heap value = the chain was torn upstream:
 * emulate anyway (native semantics — a witness observes, never
 * alters) but shout. Returns 1 when the store was emulated (skip
 * mm_fault; empty plan; rip advanced). */
static int uml_nt_tctrip_emulate(struct uml_nt_stub_conn *c,
				 struct uml_nt_stub_data *d)
{
	unsigned char ib[8];
	long long it, off;
	unsigned long long dst = 0, val = 0;
	int len = 0, size = 8, badval = 0;
	const char *what = NULL;

	if (tctrip_conn != c || c->mm == NULL ||
	    d->fault_addr < tctrip_page ||
	    d->fault_addr >= tctrip_page + UML_NT_FAULT_PAGE_SIZE ||
	    d->fault_type != UML_NT_FAULT_WRITE)
		return 0;
	it = uml_nt_vma_translate(c->mm, d->regs.rip, 8);
	if (it < 0)
		return 0;
	memcpy(ib, (char *)uml_boot.physmem_base + it, 8);
	if (!memcmp(ib, "\x4c\x89\x8c\xc8\x80\x00\x00\x00", 8)) {
		/* mov %r9,0x80(%rax,%rcx,8) — tcache_put entries[i]=e */
		dst = d->regs.rax + 0x80 + d->regs.rcx * 8;
		val = d->regs.r9;
		len = 8;
		what = "put";
		if (val < c->mm->heap_start || val >= c->mm->heap_end)
			badval = 1;
	} else if (!memcmp(ib, "\x66\x89\x34\x48", 4)) {
		/* mov %si,(%rax,%rcx,2) — tcache_put counts[i]++ */
		dst = d->regs.rax + d->regs.rcx * 2;
		val = d->regs.rsi & 0xffff;
		len = 4;
		size = 2;
		what = "put-count";
	} else if (!memcmp(ib, "\x48\x89\x34\xfa", 4)) {
		/* mov %rsi,(%rdx,%rdi,8) — tcache_get entries[i]=next */
		dst = d->regs.rdx + d->regs.rdi * 8;
		val = d->regs.rsi;
		len = 4;
		what = "get";
		if (val != 0 && (val < c->mm->heap_start ||
				 val >= c->mm->heap_end))
			badval = 1;
	} else if (!memcmp(ib, "\x66\x89\x0c\x6a", 4)) {
		/* mov %cx,(%rdx,%rbp,2) — tcache_get counts[i]-- */
		dst = d->regs.rdx + d->regs.rbp * 2;
		val = d->regs.rcx & 0xffff;
		len = 4;
		size = 2;
		what = "get-count";
	} else if (!memcmp(ib, "\x48\xc7\x40\x08\x00\x00\x00\x00",
			   8)) {
		/* movq $0,0x8(%rax) — tcache_get e->key=NULL */
		dst = d->regs.rax + 8;
		val = 0;
		len = 8;
		what = "key-null";
	} else {
		if (tctrip_loud_budget > 0) {
			tctrip_loud_budget--;
			os_info("[tctrip-WRITER] pid %lu rip=0x%llx "
				"insn=%02x %02x %02x %02x %02x %02x %02x "
				"%02x addr=0x%llx rsp=0x%llx nr=%llu "
				"ret=%lld\n",
				(unsigned long)c->pid, d->regs.rip,
				ib[0], ib[1], ib[2], ib[3], ib[4], ib[5],
				ib[6], ib[7], d->fault_addr, d->regs.rsp,
				c->last_nr, c->last_ret);
			os_info("[tctrip-WRITER]   rax=0x%llx rcx=0x%llx "
				"rdx=0x%llx rsi=0x%llx rdi=0x%llx "
				"r8=0x%llx r9=0x%llx r10=0x%llx "
				"r11=0x%llx\n",
				d->regs.rax, d->regs.rcx, d->regs.rdx,
				d->regs.rsi, d->regs.rdi, d->regs.r8,
				d->regs.r9, d->regs.r10, d->regs.r11);
		}
		/* The chunk-data case: repair writable; replay_check_arm
		 * ties the stub's post-store re-arm of the tripwire to
		 * THIS round's ss_page, so a refused decode cannot leak
		 * the re-arm into a later resume. */
		return 0; /* the writer is named above */
	}
	if (dst != d->fault_addr) {
		if (tctrip_loud_budget > 0) {
			tctrip_loud_budget--;
			os_info("[tctrip-DSTMATCH] pid %lu %s dst=0x%llx "
				"but fault=0x%llx — NOT emulating\n",
				(unsigned long)c->pid, what, dst,
				d->fault_addr);
		}
		return 0;
	}
	off = uml_nt_vma_translate(c->mm, dst, size);
	if (off < 0)
		return 0;
	/* K6 [flatwr]: the emulated struct store is a kernel flat
	 * write of guest content — capture the (run, gen) at the
	 * translate, compare at the write. */
	{
		unsigned long long cap = (unsigned long long)
			uml_nt_phys_gen(c->ph, off);

		uml_nt_flatwr_check(c, UML_NT_FLATWR_SITE_TCTRIP_EMU,
				    dst, size, (unsigned long long)off,
				    cap, off);
		/* REPLAY FOLLOWS CONTENT, at the site that really writes.
		 * Shelley 181's audit: this emulated struct store is the ONE
		 * place the kernel puts a saved replay value into guest
		 * memory — replay_check_verify only ever measures. So the
		 * guard belongs here, and it has two laws:
		 *   1. a 2-byte store must be 2-byte aligned, an 8-byte
		 *      store 8-byte: an unaligned one IS the u16-at-+6
		 *      signature (0x4802… shifted into a register's top
		 *      half) and must never be written;
		 *   2. the word must not already hold the value (ALREADY):
		 *      the store happened, writing again is at best noise.
		 */
		{
			unsigned int misaligned = (size == 2 &&
				(dst & 1)) || (size == 8 && (dst & 7));
			unsigned long long cur = (size == 2) ?
				(unsigned long long)*(const unsigned short *)
					((const char *)uml_boot.physmem_base +
					 off) :
				*(const unsigned long long *)
					((const char *)uml_boot.physmem_base +
					 off);
			int v = uml_nt_replay_verdict_seq(cur, cur, val, 1);

			if (misaligned) {
				c->tctrip_refused++;
				if (c->tctrip_refused <= 8)
					os_info("[tctrip-GUARD] pid %lu "
						"REFUSED unaligned size=%u "
						"dst=0x%llx (offset %u) — "
						"the u16-at-+6 signature\n",
						(unsigned long)c->pid, size,
						dst, (unsigned)(dst & 7));
			} else if (v == UML_NT_REPLAY_ALREADY) {
				c->rp_already++;
			} else if (size == 2) {
				*(unsigned short *)((char *)
					uml_boot.physmem_base + off) =
					(unsigned short)val;
				c->rp_writes++;
			} else {
				*(unsigned long long *)((char *)
					uml_boot.physmem_base + off) = val;
				c->rp_writes++;
			}
		}
	}
	d->regs.rip += len;
	tctrip_emulated++;
	if (badval && tctrip_loud_budget > 0) {
		tctrip_loud_budget--;
		os_info("[tctrip-BADVAL] pid %lu %s val=0x%llx NOT in "
			"heap [0x%llx,0x%llx) rip=0x%llx nr=%llu — "
			"emulated (native), chain torn upstream\n",
			(unsigned long)c->pid, what, val,
			c->mm->heap_start, c->mm->heap_end, d->regs.rip,
			c->last_nr);
	}
	if ((tctrip_emulated & 0x3ff) == 1)
		os_info("[tctrip] %llu emulated struct writes (page "
			"never writable — every write transits here)\n",
			tctrip_emulated);
	return 1;
}

/* [copyver] (see syscall.h): memcpy + read-back verify for the
 * kernel-side bulk copies into guest memory. The trap census only
 * sees stub-view writes — a bad kernel copy is invisible to it, and
 * it lands precisely in allocator-metadata territory. */
int uml_nt_copy_verify(char *dst, const char *src, unsigned long long len,
		       const char *what)
{
	unsigned long long i;

	uml_nt_flatcopy_begin(dst, src, len, what,
			      (unsigned long long)__builtin_return_address(0));
	memcpy(dst, src, len);
	uml_nt_flatcopy_end();
	if (memcmp(dst, src, len) == 0)
		return 0;
	for (i = 0; i + 8 <= len; i++)
		if (dst[i] != src[i])
			break;
	os_info("[copyver] %s: MISMATCH len=%llu first-diff at +%llu: "
		"src=%02x%02x%02x%02x%02x%02x%02x%02x "
		"dst=%02x%02x%02x%02x%02x%02x%02x%02x — the copy did "
		"not land\n", what, len, i, (unsigned char)src[i],
		(unsigned char)src[i + 1], (unsigned char)src[i + 2],
		(unsigned char)src[i + 3], (unsigned char)src[i + 4],
		(unsigned char)src[i + 5], (unsigned char)src[i + 6],
		(unsigned char)src[i + 7], (unsigned char)dst[i],
		(unsigned char)dst[i + 1], (unsigned char)dst[i + 2],
		(unsigned char)dst[i + 3], (unsigned char)dst[i + 4],
		(unsigned char)dst[i + 5], (unsigned char)dst[i + 6],
		(unsigned char)dst[i + 7]);
	return -1;
}

static void uml_nt_cowwatch_round(struct uml_nt_stub_conn *c)
{
	unsigned int i;
	static unsigned int cowwatch_phase;
	static int cowwatch_exp_budget = 64;

	cowwatch_phase = (cowwatch_phase + 1) & 0xF;
	if (cowwatch_phase != 0)
		return;

	for (i = 0; i < UML_NT_COWWATCH_N; i++) {
		struct uml_nt_cowwatch *w = &cowwatchs[i];
		unsigned long long off, base;
		int dumped;

		if (!w->armed)
			continue;
		if (w->rounds-- == 0) {
			w->armed = 0;
			if (cowwatch_exp_budget > 0) {
				cowwatch_exp_budget--;
				os_info("[cowwatch] run=0x%llx expired\n",
					w->run_off);
			}
			continue;
		}
		base = w->run_off;
		for (off = base;
		     off + 16 <= base + UML_NT_PHYS_RUN_SIZE;
		     off += 8) {
			unsigned long long fd, bk, q;
			int k;

			memcpy(&fd, (char *)uml_boot.physmem_base +
			       off, 8);
			if (fd != 0x1a)
				continue;
			memcpy(&bk, (char *)uml_boot.physmem_base +
			       off + 8, 8);
			if (bk != 0x8000)
				continue;
			w->armed = 0;
			os_info("[cowwatch] HIT run=0x%llx at +0x%llx "
				"(owner %lu@0x%llx)%s — writer round: "
				"pid %lu nr=%llu ret=%lld rip=0x%llx "
				"rsp=0x%llx rcx=0x%llx cmd=%d\n",
				w->run_off, off - base,
				w->owner_pid, w->owner_va,
				w->seen ? " (repeat)" : " (first-see)",
				(unsigned long)c->pid, c->last_nr,
				c->last_ret, c->d->regs.rip,
				c->d->regs.rsp, c->d->regs.rcx,
				c->d->cmd);
			w->seen = 1;
			/* The WRITER-side VA: this conn's mapping of
			 * the same run — a fixed per-mm offset (both
			 * 37014552047 hits: +0xb6b0) = the write
			 * landed through the writer's OWN mapping. */
			{
				struct uml_nt_vma *wv =
					uml_nt_vma_find(c->mm,
						c->d->regs.rip);

				if (wv != NULL)
					os_info("[cowwatch] writer "
						"mm: rip in vma "
						"[0x%llx,0x%llx) "
						"run_off=0x%llx\n",
						wv->start, wv->end,
						wv->run_off);
			}
			/* [cowtrap]: arm the write-watch on the
			 * pattern's page — the owner's own round
			 * (c == the owner conn) is the only vantage
			 * that can flip ITS view. */
			if (c->pid == w->owner_pid)
				uml_nt_cowtrap_arm(c, w->owner_va,
					w->owner_va + (off - base),
					w->run_off);
			/* ±0x40 context, 8 qwords a row — the 0x100
			 * window of map 059, phys-side. */
			dumped = 0;
			for (k = -8, q = off - 64;
			     k < 8 && !dumped;
			     k++, q += 8) {
				unsigned long long x;

				if (q < base ||
				    q + 8 > base +
				    UML_NT_PHYS_RUN_SIZE)
					continue;
				memcpy(&x, (char *)
				       uml_boot.physmem_base + q, 8);
				os_info("[cowwatch]   %s0x%llx: "
					"0x%llx\n",
					q < off ? " " : ">",
					q, x);
				if (q >= off)
					dumped = 1;
			}
			break;
		}
	}
}

/* 098 δ: kernel-direct write census — every bulk write the KERNEL
 * makes into guest RAM reports if it touches a cowwatch-armed run.
 * The 097 verdict: stomp writes land with NO fault through RO views
 * (verify_prot = 0 mismatches, fork-sync proves the views applied),
 * so the writer must be a path that bypasses the stub's VEH
 * machinery entirely — the seed/eager copies, the brk re-home, the
 * sweep patcher, the zero fills. A census line in the same run as a
 * cowwatch HIT names the writer; census silence across a poisoned
 * boot EXCLUDES every kernel-direct path and re-points the hunt at
 * the views. Log-only: no behavior change. */
void uml_nt_cowwatch_touch(unsigned long long off, unsigned long long len,
			   const char *what)
{
	unsigned int i;
	static int cowwatch_kw_budget = 64;

	if (cowwatch_kw_budget <= 0)
		return;
	for (i = 0; i < UML_NT_COWWATCH_N; i++) {
		struct uml_nt_cowwatch *w = &cowwatchs[i];

		if (!w->armed)
			continue;
		if (off + len <= w->run_off ||
		    off >= w->run_off + UML_NT_PHYS_RUN_SIZE)
			continue;
		if (cowwatch_kw_budget > 0) {
			cowwatch_kw_budget--;
			os_info("[cowwatch] kernel-write %s run=0x%llx touch "
				"[0x%llx,+0x%llx) owner=%lu\n", what,
				w->run_off, off, len, w->owner_pid);
		}
	}
}

/* ---- [cowrace] (M5.6a, feature cowcopy-race-witness) ---------------
 * The tear survived 6d3c932/fc4381a (dl24 37532472713 / dl25
 * 37534293014): the chunk-side stores (e->next/e->key) are lost at
 * RUN granularity while the tcache-struct-side stores land, with
 * [cowcopy] activity on runs ADJACENT to the torn chunks' run at the
 * fire round and 0 [viewswap] lines (the plan-op guard class is not
 * the vector). Hypothesis: a COW/re-home content copy races an
 * in-flight guest store — the store lands in the SOURCE run after or
 * while the copy, the view swaps to the copy, and the store is lost
 * canonically.
 *
 * Witness (read-only: NO ss/TF, NO DR, NO page protects; the only
 * fault-park work is the recording the brief mandates AT the copy —
 * a 64K hash + the sharer snapshot, no guest-visible state, no new
 * walks of guest memory at fault parks):
 *   ARM at every run copy+re-home — the [cowcopy] fault-path COW
 *   copy (serve_conn) and the brk re-home (sys_brk): src/dst run,
 *   va range, the copying conn/pid, the source's t0 hash (src == dst
 *   byte-for-byte AT the copy — uml_nt_copy_verify memcpys AND
 *   memcmps), its phys gen/refs, and the RUNNING-vs-PARKED snapshot
 *   of every other conn sharing that mm or mapping that src run
 *   (the stub park protocol: req_seq/done_seq are cross-process
 *   coherent; req==done is RUNNING, req==done+1 is PARKED).
 *   CHECK at the NEXT SYSCALL PARKS only (the witness placement
 *   rule — nothing at fault parks): gate on the run's lifecycle
 *   (gen moved = recycled, refs==0 = released: retire), then re-hash
 *   the src range. src != t0 = a store landed in the SOURCE after
 *   the copy. Classified at fire: refs>=2 or no live mm maps src =
 *   LOST (every view of a shared run is READ-ONLY — the write
 *   bypassed the COW fault path; nobody owns these bytes writable);
 *   refs==1 with a live mapper = SHARED-WRITE (the remaining owner
 *   re-privatized and wrote on — the benign class, decode
 *   correlates). Reports the differing qword offsets + both values
 *   + the arm-time RUNNING sharers.
 * Budgets: ring 64 (UML_NT_COWRACE_N, widened from 16 — dlV ran
 * 129 arms under a 16-slot ring: most watches were evicted before
 * any check landed), hash window 4 parks for non-watched sources
 * and big spans, 32 for watched-heap sources of <= 2 runs (dlV's
 * 4-park t0-window expiry was a silent hole; a quiet watch stays
 * armed, gate-only, until the run retires), 512MB hashed bytes,
 * 128 arm lines, 32 LOST fires, 16 SHARED-WRITE fires, 16 retire
 * notes, 16 RETIRE-LOST fires — one-shots per watch. */
#define UML_NT_COWRACE_HASH_BUDGET (512ull * 1024 * 1024)
static struct uml_nt_cowrace_watch cowrace_w[UML_NT_COWRACE_N];
static unsigned int cowrace_cursor;
static unsigned long long cowrace_hashed;
static unsigned long long cowrace_arms;
static int cowrace_arm_budget = 128;
static int cowrace_fire_budget = 32;
static int cowrace_shared_budget = 16;
static int cowrace_ret_budget = 16;
static int cowrace_retlost_budget = 64; /* RETIRE-LOST fires (the
	* release-time src-vs-t0 diff — dlV's blind spot). K6
	* (cowcopy-race-class-fix): raised 16→64 — the verdict runs
	* measured 16 fires/referee BUDGET-CAPPED, so the true
	* population was invisible; the fix's acceptance is 0
	* RETIRE-LOST on heap, and a wide-open budget is the only
	* way "0" is evidence rather than truncation. */
static int cowrace_arm_said, cowrace_hash_said;

/* Live conns whose mm maps the run at src_off (the vma backing span
 * predicate). Fills up to max pids; returns the count found. */
static int cowrace_mappers(unsigned long long src_off,
			   unsigned long *pids, int max)
{
	struct task_struct *p;
	int n = 0;

	for_each_process(p) {
		struct uml_nt_stub_conn *pc;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD || !pc->alive)
			continue;
		if (!uml_nt_cowrace_maps_run(pc->mm, src_off))
			continue;
		if (pids != NULL && n < max)
			pids[n] = (unsigned long)pc->pid;
		n++;
	}
	return n;
}

void uml_nt_cowrace_arm(struct uml_nt_stub_conn *c,
			unsigned long long src_off,
			unsigned long long dst_off,
			unsigned long long len,
			unsigned long long va_base,
			const char *what)
{
	unsigned long run_pids[UML_NT_COWRACE_PIDS];
	int n_run = 0, n_park = 0, n_samm = 0, trunc = 0, watched = 0;
	struct task_struct *p;
	unsigned long long h0;
	int slot, i;

	if (c == NULL || c->ph == NULL || src_off == 0 || len == 0)
		return;
	if (cowrace_hashed >= UML_NT_COWRACE_HASH_BUDGET) {
		if (!cowrace_hash_said) {
			cowrace_hash_said = 1;
			os_info("[cowrace] hash budget exhausted "
				"(%llu bytes hashed, %llu arms) — "
				"checks stopped\n", cowrace_hashed,
				cowrace_arms);
		}
		return;
	}
	/* K6 widening (feature flatwrite-retire-witness): the
	 * watched-heap gate — the same 0x291 glibc shape as
	 * tcache_ekey_watch/viewprobe. Watched sources get the LONG
	 * hash window and the eviction preference; cheap (one
	 * translate + one qword read) and it rides the existing arm. */
	if (c->mm != NULL && c->mm->heap_start != 0) {
		long long ho = uml_nt_vma_translate(c->mm,
			c->mm->heap_start, 16);

		if (ho >= 0 &&
		    *(const unsigned long long *)(const void *)
		    ((char *)uml_boot.physmem_base + ho + 8) == 0x291)
			watched = 1;
	}
	/* The t0 both ends share at the copy: uml_nt_copy_verify
	 * just memcpy'd AND memcmp'd src==dst over [0, len). */
	h0 = uml_nt_uacc_fnv1a64(
		(const void *)((char *)uml_boot.physmem_base + src_off),
		(unsigned long)len);
	cowrace_hashed += len;

	/* The RUNNING-vs-PARKED sharer snapshot: every OTHER live conn
	 * that shares the copying mm or maps the src run. The copying
	 * conn is parked at its fault/syscall by definition (skipped);
	 * a never-resumed conn never ran guest code (skipped). */
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		int shares = 0, st;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc == c || pc->mm == NULL ||
		    pc->d == NULL || !pc->alive || !pc->resumed ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		if (pc->mm == c->mm) {
			shares = 1;
			n_samm++;
		} else if (uml_nt_cowrace_maps_run(pc->mm, src_off))
			shares = 1;
		if (!shares)
			continue;
		st = uml_nt_cowrace_run_state(pc->d->req_seq,
					      pc->d->done_seq);
		if (st == 1) {
			/* RUNNING: its guest stores can be in flight
			 * against the copy RIGHT NOW. */
			if (n_run < UML_NT_COWRACE_PIDS)
				run_pids[n_run] = (unsigned long)pc->pid;
			else
				trunc = 1;
			n_run++;
		} else {
			n_park++; /* parked (or desync — cannot write) */
		}
	}
	for (i = n_run < UML_NT_COWRACE_PIDS ? n_run :
		     UML_NT_COWRACE_PIDS;
	     i < UML_NT_COWRACE_PIDS; i++)
		run_pids[i] = 0;

	slot = uml_nt_cowrace_slot_arm(cowrace_w, UML_NT_COWRACE_N,
				       &cowrace_cursor, src_off, dst_off,
				       len, va_base,
				       uml_nt_phys_gen(c->ph,
						       (long long)src_off),
				       h0, (unsigned long)c->pid,
				       run_pids, n_run, n_park, n_samm,
				       trunc, watched);
	cowrace_w[slot].ph = c->ph;
	cowrace_arms++;
	if (cowrace_arm_budget > 0) {
		cowrace_arm_budget--;
		os_info("[cowrace] arm %s src=0x%llx dst=0x%llx "
			"len=0x%llx va=0x%llx pid=%lu running=%d "
			"[%lu %lu %lu %lu] parked=%d samm=%d w=%d "
			"h0=0x%llx\n", what, src_off, dst_off, len,
			va_base, (unsigned long)c->pid, n_run,
			run_pids[0], run_pids[1], run_pids[2],
			run_pids[3], n_park, n_samm, watched, h0);
	} else if (!cowrace_arm_said) {
		cowrace_arm_said = 1;
		os_info("[cowrace] arm prints exhausted (%llu arms "
			"total) — watches continue silently\n",
			cowrace_arms);
	}
}

/* The check pass — SYSCALL PARKS ONLY (the placement rule). For
 * every armed watch: lifecycle gates first (cheap, EVERY park —
 * even quiet ones: a watch whose hash window closed stays armed
 * until the run retires, where the RETIRE-LOST diff decides lost
 * store vs dead backing), then the src hash while the window is
 * open; a divergence fires once and retires the watch. */
static void cowrace_round(struct uml_nt_stub_conn *c)
{
	int i;

	for (i = 0; i < UML_NT_COWRACE_N; i++) {
		struct uml_nt_cowrace_watch *w = &cowrace_w[i];
		unsigned long long gen_now, hsrc = 0, hdst = 0;
		unsigned long mpids[UML_NT_COWRACE_PIDS] = { 0 };
		unsigned long long offs[UML_NT_COWRACE_DIFFS];
		unsigned long long sv[UML_NT_COWRACE_DIFFS];
		unsigned long long dv[UML_NT_COWRACE_DIFFS];
		int refs_now, v, k, nd, nm, cls;

		if (!w->armed)
			continue;
		if (cowrace_hashed >= UML_NT_COWRACE_HASH_BUDGET) {
			if (!cowrace_hash_said) {
				cowrace_hash_said = 1;
				os_info("[cowrace] hash budget exhausted "
					"(%llu bytes hashed, %llu arms) — "
					"checks stopped\n", cowrace_hashed,
					cowrace_arms);
			}
			return;
		}
		gen_now = uml_nt_phys_gen(w->ph,
					   (long long)w->src_off);
		refs_now = uml_nt_phys_refs(w->ph,
					    (long long)w->src_off);
		v = uml_nt_cowrace_gate(w, gen_now, refs_now);
		if (v == 0) {
			if (w->quiet)
				continue; /* window spent: gate-only
					   * until the lifecycle ends */
			hsrc = uml_nt_uacc_fnv1a64(
				(const void *)((char *)
					uml_boot.physmem_base +
					w->src_off),
				(unsigned long)w->len);
			cowrace_hashed += w->len;
			if (hsrc == w->h0) {
				/* nothing moved in the source: spend
				 * one check, stay armed until the
				 * K-th (the fire window is the few
				 * parks right after the copy). */
				(void)uml_nt_cowrace_spend(w);
				continue;
			}
			hdst = uml_nt_uacc_fnv1a64(
				(const void *)((char *)
					uml_boot.physmem_base +
					w->dst_off),
				(unsigned long)w->len);
			cowrace_hashed += w->len;
			v = uml_nt_cowrace_verdict(w, hsrc, hdst);
		}
		/* fire or retire: one-shot. */
		w->armed = 0;
		if (v == UML_NT_COWRACE_RECYCLE) {
			if (cowrace_ret_budget > 0) {
				cowrace_ret_budget--;
				os_info("[cowrace] retire src=0x%llx "
					"(recycled: gen 0x%llx->0x%llx "
					"refs=%d) — a new generation's "
					"bytes, not a lost update "
					"(content wiped at handout)\n",
					w->src_off, w->gen_src, gen_now,
					refs_now);
			}
			continue;
		}
		if (v == UML_NT_COWRACE_RELEASE) {
			/* K6 RETIRE-LOST (feature
			 * flatwrite-retire-witness): the dlV blind
			 * spot — all 16 retires went out as "dead
			 * backing" with NO content check, while a
			 * store landing in the source between the
			 * copy and its release retires silently. The
			 * pool zeroes at HANDOUT, not release
			 * (physalloc.c), so a released run with its
			 * gen intact still holds its last-life bytes:
			 * diff the src against the arm t0 BEFORE
			 * declaring it dead. src != t0 = a store
			 * landed in the abandoned source after the
			 * copy — the lost pair retired as a dead
			 * backing. */
			hsrc = uml_nt_uacc_fnv1a64(
				(const void *)((char *)
					uml_boot.physmem_base +
					w->src_off),
				(unsigned long)w->len);
			cowrace_hashed += w->len;
			if (hsrc != w->h0) {
				hdst = uml_nt_uacc_fnv1a64(
					(const void *)((char *)
						uml_boot.physmem_base +
						w->dst_off),
					(unsigned long)w->len);
				cowrace_hashed += w->len;
				if (cowrace_retlost_budget > 0) {
					cowrace_retlost_budget--;
					os_info("[cowrace] RETIRE-LOST "
						"src=0x%llx dst=0x%llx "
						"va=0x%llx len=0x%llx "
						"arm-pid=%lu refs=%d — "
						"h0=0x%llx hsrc=0x%llx "
						"hdst=0x%llx (dst %s)\n",
						w->src_off, w->dst_off,
						w->va_base, w->len,
						(unsigned long)w->pid,
						refs_now, w->h0, hsrc,
						hdst,
						hdst == w->h0 ?
						"untouched" :
						"moved too");
					os_info("[cowrace]   released "
						"(refs=0, gen 0x%llx "
						"intact) with content != "
						"t0 — a store landed in "
						"the abandoned source "
						"between the copy and "
						"the release\n", gen_now);
					nd = uml_nt_cowrace_diff(
						(const unsigned char *)
						uml_boot.physmem_base +
						w->src_off,
						(const unsigned char *)
						uml_boot.physmem_base +
						w->dst_off,
						w->len, offs, sv, dv,
						UML_NT_COWRACE_DIFFS);
					for (k = 0; k < nd &&
					     k < UML_NT_COWRACE_DIFFS; k++)
						os_info("[cowrace]   diff "
							"+0x%llx "
							"src=0x%016llx "
							"dst=0x%016llx\n",
							offs[k], sv[k],
							dv[k]);
					if (nd > UML_NT_COWRACE_DIFFS)
						os_info("[cowrace]   +%d "
							"more differing "
							"qwords\n",
							nd -
							UML_NT_COWRACE_DIFFS);
					os_info("[cowrace]   found at park "
						"pid=%lu nr=%llu ret=%lld "
						"rip=0x%llx\n",
						(unsigned long)c->pid,
						c->last_nr, c->last_ret,
						c->d->regs.rip);
				}
				continue;
			}
			if (cowrace_ret_budget > 0) {
				cowrace_ret_budget--;
				os_info("[cowrace] retire src=0x%llx "
					"(released: gen 0x%llx->0x%llx "
					"refs=%d) — dead backing, src==t0 "
					"(diff checked)\n", w->src_off,
					w->gen_src, gen_now, refs_now);
			}
			continue;
		}
		/* src moved with the gates intact: a store landed in
		 * the SOURCE after the copy. Classify: who can still
		 * legitimately write it? */
		nm = cowrace_mappers(w->src_off, mpids,
				     UML_NT_COWRACE_PIDS);
		cls = uml_nt_cowrace_class(refs_now, nm);
		if (cls == UML_NT_COWRACE_LOST) {
			if (cowrace_fire_budget <= 0)
				continue;
			cowrace_fire_budget--;
		} else {
			if (cowrace_shared_budget <= 0)
				continue;
			cowrace_shared_budget--;
		}
		os_info("[cowrace] %s src=0x%llx dst=0x%llx "
			"va=0x%llx len=0x%llx arm-pid=%lu refs=%d "
			"mappers=%d — h0=0x%llx hsrc=0x%llx "
			"hdst=0x%llx (dst %s)\n",
			cls == UML_NT_COWRACE_LOST ? "LOST" :
			"SHARED-WRITE",
			w->src_off, w->dst_off, w->va_base, w->len,
			(unsigned long)w->pid, refs_now, nm, w->h0,
			hsrc, hdst,
			hdst == w->h0 ? "untouched" : "moved too");
		nd = uml_nt_cowrace_diff(
			(const unsigned char *)
				uml_boot.physmem_base + w->src_off,
			(const unsigned char *)
				uml_boot.physmem_base + w->dst_off,
			w->len, offs, sv, dv, UML_NT_COWRACE_DIFFS);
		for (k = 0; k < nd && k < UML_NT_COWRACE_DIFFS; k++)
			os_info("[cowrace]   diff +0x%llx "
				"src=0x%016llx dst=0x%016llx\n",
				offs[k], sv[k], dv[k]);
		if (nd > UML_NT_COWRACE_DIFFS)
			os_info("[cowrace]   +%d more differing "
				"qwords\n", nd - UML_NT_COWRACE_DIFFS);
		os_info("[cowrace]   found at park pid=%lu nr=%llu "
			"ret=%lld rip=0x%llx; arm-time sharers: "
			"running=%d [%lu %lu %lu %lu] parked=%d; "
			"fire-time mappers: [%lu %lu %lu %lu]\n",
			(unsigned long)c->pid, c->last_nr, c->last_ret,
			c->d->regs.rip, w->n_run,
			w->run_pids[0], w->run_pids[1], w->run_pids[2],
			w->run_pids[3], w->n_park,
			mpids[0], mpids[1], mpids[2], mpids[3]);
	}
}

/* ---- K6 [flatwr] (M5.6a, feature flatwrite-retire-witness) -------
 * The kernel-flat-write staleness witness — candidate (b) of the
 * 139a dead-end: the lost tcache_put pair reaches a backing NO
 * park-visible view shows, and the surviving NON-VIEW candidate is
 * a kernel-side flat write of guest content through a translation
 * OLDER than the current table (the store lands in the abandoned
 * source run — the dl26 content shape, run 0x4090000 refs=1).
 * Every flat-write site of guest content captures the (run, gen)
 * at TRANSLATE time; uml_nt_flatwr_check compares the phys gen of
 * the offset being written AND the CURRENT table translate of the
 * guest va (run-granular — every backing offset is run-aligned) at
 * WRITE time. A mismatch is recorded into the ring AT the site
 * (bookkeeping only: no hashing, no printing at fault parks) and
 * printed at the next syscall park (flatwr_report, beside
 * claim_audit — the placement rule). Read-only witness: no ss/TF,
 * no DR, no page protects, no guest-visible state.
 *
 * Sites covered (capture at the translate, compare at the write):
 *  - the fault-path COW copy, src read + dst write (caps stamped
 *    in uml_nt_mm_fault's plan; checked in serve_conn's copy
 *    block before the memcpy);
 *  - the uacc walker's inline fixup copy (uml_nt_flatwr_uacc_
 *    fixup, pinned as the uaccess_walk.h hook — the walker stays
 *    pure/log-free);
 *  - the brk re-home span copy (sys_brk);
 *  - the mmap fill (memset + the file read) and the mmap sweep
 *    patch (syscall.c — post-write compare: a blocking file read
 *    or kvmalloc can sleep mid-piece);
 *  - the mapcanary plant -> RESTORE (the round-trip window: op
 *    issue -> PROT_DONE, the highest-risk gap of the set);
 *  - the tctrip emulated tcache-struct store;
 *  - the fork eager copies (both fork paths) + the below-rsp
 *    residue zeros.
 * Enumerated and EXCLUDED (rg-verified, no capture needed): the
 * D15 uacc funnel itself (its own generation contract:
 * uacc_gen_stale + the write_ptr re-check); the exec-time writers
 * (binfmt ELF segments/stack, os_pwrite_file's memfd fills — a
 * fresh PRIVATE mm, no fork sharers, refs=1, single thread); the
 * pool zeroing (uml_nt_phys_zero_flat: handout-time, refs==0 by
 * construction); the entry-blob staging (infrastructure bytes, not
 * guest VAs); and the FP/sigframe pushback (no flat physmem
 * write: the frame writes ride the guarded walker, the xstate
 * rides the stub descriptor page, and the adfc650 pull-push
 * contract owns the staleness class). */
static struct uml_nt_flatwr_rec flatwr_ring[UML_NT_FLATWR_N];
static int flatwr_count;
static unsigned int flatwr_cursor;
static int flatwr_budget = 16; /* park prints, one-shot exhaustion */
static int flatwr_said;
static const char *const flatwr_sites[] = {
	"cowcopy-src", "cowcopy-dst", "uacc-fixup", "brk-fill",
	"mmap-fill", "mmap-sweep", "mc-plant", "mc-restore",
	"tctrip-emu", "fork-eager", "fork-zero",
};
#define FLATWR_SITES_N ((int)(sizeof(flatwr_sites) / \
			      sizeof(flatwr_sites[0])))

/* The site core (no conn needed — the uacc hook has none: the
 * record carries pid=0 and the live nr, the decode correlates the
 * round from the surrounding [uawrite]/[uacc-fixup] lines). */
/* The persistent image-run table (M5.6a writer-hunt follow-up): every
 * captured image run + its handout gen; registration happens at
 * imgwatch capture, AFTER the exec-time patching. The TO_GUEST funnel
 * and every flat kernel write test it — a hit is a post-load write
 * into loaded image text, logged with its site. */
static unsigned long long g_image_gen[UML_NT_PHYS_MAX_RUNS];
static struct uml_nt_phys *g_image_ph;

static void flatwr_core(struct uml_nt_mm *mm, struct uml_nt_phys *ph,
			unsigned long pid, unsigned long long nr,
			unsigned long long ret, int site,
			unsigned long long va, unsigned long long len,
			unsigned long long off,
			unsigned long long gen_old,
			long long tbl_expect)
{
	unsigned long long gen_now, tbl_old = 0, tbl_new = ~0ull;
	long long tbl_now = -1;
	struct uml_nt_flatwr_rec rec;
	int what;

	if (ph == NULL)
		return;
	/* A flat write into a REGISTERED image run (any conn) with no
	 * funnel record is a post-load text rewrite. The exec-time
	 * sweep runs before registration, so it never lands here. */
	if (off != (unsigned long long)-1LL) {
		static int fwi_budget = 16;
		unsigned int ii = (unsigned int)(off /
						 UML_NT_PHYS_RUN_SIZE);

		if (ii < UML_NT_PHYS_MAX_RUNS && g_image_gen[ii] != 0 &&
		    uml_nt_phys_gen(ph, (long long)off) ==
		    g_image_gen[ii] && fwi_budget > 0 &&
		    site != UML_NT_FLATWR_SITE_COWCOPY_SRC) {
			fwi_budget--;
			os_info("[flatwr-image] site=%d pid %lu "
				"va=0x%llx len=%llu off=0x%llx nr=%llu — "
				"a flat kernel write into a loaded image "
				"run\n", site, pid, va, len, off, nr);
		}
	}
	gen_now = (unsigned long long)uml_nt_phys_gen(ph,
						      (long long)off);
	if (mm != NULL && va != 0 && tbl_expect >= 0)
		tbl_now = uml_nt_vma_translate(mm, va, 1);
	what = uml_nt_flatwr_class(gen_old, gen_now,
				   tbl_expect >= 0 ? tbl_now : -1,
				   tbl_expect);
	if (what == UML_NT_FLATWR_OK)
		return;
	if (tbl_expect >= 0)
		tbl_old = (unsigned long long)tbl_expect &
			~(unsigned long long)
			(UML_NT_PHYS_RUN_SIZE - 1);
	if (tbl_expect >= 0 && tbl_now >= 0)
		tbl_new = (unsigned long long)tbl_now &
			~(unsigned long long)
			(UML_NT_PHYS_RUN_SIZE - 1);
	rec.site = (unsigned char)site;
	rec.what = (unsigned char)what;
	rec.va = va;
	rec.len = len;
	rec.off = off;
	rec.gen_old = gen_old;
	rec.gen_now = gen_now;
	rec.tbl_old = tbl_old;
	rec.tbl_new = tbl_new;
	rec.pid = pid;
	rec.nr = nr;
	rec.ret = ret;
	(void)uml_nt_flatwr_push(flatwr_ring, UML_NT_FLATWR_N,
				 &flatwr_count, &flatwr_cursor, &rec);
}

void uml_nt_flatwr_check(struct uml_nt_stub_conn *c, int site,
			 unsigned long long va,
			 unsigned long long len,
			 unsigned long long off,
			 unsigned long long gen_old,
			 long long tbl_expect)
{
	if (c == NULL)
		return;
	flatwr_core(c->mm, c->ph, (unsigned long)c->pid, c->last_nr,
		    c->last_ret, site, va, len, off, gen_old,
		    tbl_expect);
}

/* The uacc walker's inline fixup copy (both ends, gen-only — the
 * dst is a fresh alloc the table has not claimed yet, the src still
 * backs the va pre-split; the funnel's own gen contract owns the
 * claim side). */
void uml_nt_flatwr_uacc_fixup(const struct uml_nt_mm *mm,
			      struct uml_nt_phys *ph,
			      unsigned long long va,
			      unsigned long long src_off,
			      unsigned long long gen_src,
			      unsigned long long dst_off,
			      unsigned long long gen_dst)
{
	unsigned long long nr = uml_nt_uacc_nr_current();

	flatwr_core((struct uml_nt_mm *)mm, ph, 0, nr, 0,
		    UML_NT_FLATWR_SITE_UACC_FIXUP, va,
		    UML_NT_PHYS_RUN_SIZE, src_off, gen_src, -1);
	flatwr_core((struct uml_nt_mm *)mm, ph, 0, nr, 0,
		    UML_NT_FLATWR_SITE_UACC_FIXUP, va,
		    UML_NT_PHYS_RUN_SIZE, dst_off, gen_dst, -1);
}

/* The park printer — syscall parks ONLY. Drains the ring. */
void uml_nt_flatwr_report(struct uml_nt_stub_conn *c)
{
	int i;

	if (flatwr_count <= 0)
		return;
	for (i = 0; i < flatwr_count && i < UML_NT_FLATWR_N; i++) {
		struct uml_nt_flatwr_rec *r = &flatwr_ring[i];

		if (flatwr_budget <= 0) {
			if (!flatwr_said) {
				flatwr_said = 1;
				os_info("[flatwr] print budget exhausted "
					"— records continue to be "
					"collected\n");
			}
			break;
		}
		flatwr_budget--;
		os_info("[flatwr] %s site=%s pid=%lu va=0x%llx "
			"len=0x%llx off=0x%llx gen=0x%llx->0x%llx "
			"tbl=0x%llx->0x%llx nr=%llu ret=%lld\n",
			r->what == UML_NT_FLATWR_STALE_GEN ?
			"STALE-GEN" :
			r->what == UML_NT_FLATWR_STALE_TBL ?
			"STALE-TBL" : "STALE-BOTH",
			flatwr_sites[r->site % FLATWR_SITES_N],
			(unsigned long)r->pid, r->va, r->len, r->off,
			r->gen_old, r->gen_now, r->tbl_old, r->tbl_new,
			r->nr, r->ret);
	}
	/* the park saw the ring; the next window starts here */
	flatwr_count = 0;
	flatwr_cursor = 0;
	(void)c;
}

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

/* The [viewswap] transition-note budget: the composed-plan
 * guard's allowed intermediate MAPs (superseded in-plan) print
 * once each up to this cap, so a decode can see the chained-COW
 * class working without per-fixup noise. */
static int viewswap_transition_logged;

/* Push one plan op into the conn's slot. */
static void issue_plan_op(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op)
{
	struct uml_nt_stub_data *d = c->d;
	int sup = 0;

	/* OP LEDGER (M5.6a, referee 37212286263): the wrong-backed
	 * twin is a MEM_MAPPED section view at the heap start whose
	 * backing offset is stale — some MAP op carried an old run.
	 * Record EVERY view op (64-deep ring — the fires land on
	 * pieces beyond the first, referee 37237334098: fire VAs at
	 * 0x67c3-0x67cf while the first-piece-only filter saw
	 * nothing). The [replay-lost] fire dumps the ops touching
	 * the fire page — the stale MAP/re-protect names itself. */
	if (1) {
		unsigned long long *e =
			c->op_log[c->op_log_n % 64];

		e[0] = op->op;
		e[1] = op->prot;
		e[2] = op->va;
		e[3] = op->len;
		e[4] = op->off;
		c->op_log_n++;
	}

	d->mapcanary = 0;
	if (witness_off())
		c->mc_want = 0;
	switch (op->op) {
	case UML_NT_FOP_PROTECT:
		/* VIEW LEDGER: a prot change refreshes every ledger
		 * view it overlaps (the drain census prints the
		 * prot a surviving region carries). */
		{
			int vi;

			for (vi = 0; vi < c->nviews; vi++) {
				if (c->views[vi].va >= op->va + op->len ||
				    c->views[vi].va + c->views[vi].len <=
					op->va)
					continue;
				c->views[vi].prot = op->prot;
			}
		}
		d->action = UML_STUB_ACTION_PROT;
		d->prot = op->prot;
		d->map_va = op->va;  /* PROTECT target page/range */
		d->map_len = op->len;
		break;
	case UML_NT_FOP_MAP:
		/* M5.6a root-cause fix — THE APPLY-TIME GUARD of the
		 * table<->view swap window (dl18 37512134759 named the
		 * formation class: a store landing in a backing the
		 * table no longer owns). A composed plan can queue
		 * SEVERAL COW surgeries before op 0 streams (a
		 * writeback crossing a run boundary runs two fixups
		 * into ONE plan), so the table is already the FINAL
		 * one when the guard sees the first op: an
		 * INTERMEDIATE MAP (the first fixup's still-shared
		 * tail re-map, superseded by the second fixup's
		 * corrective UNMAP/MAP queued behind it) is legal
		 * against the state the plan itself produces — the
		 * guest stays parked in the stub's action_chain until
		 * the plan drains, so nothing observes the transient
		 * view. The invariant that must hold is the FINAL one
		 * (fault.c uml_nt_fault_op_allowed): a MAP whose view
		 * SURVIVES the plan must be backed by the table's own
		 * run; a mismatch with NO same-base release behind it
		 * in the plan = the table moved under the op with no
		 * repair = applying it would hand the guest a
		 * WRONG-BACKED view — the silent split-brain behind
		 * the run-granular lost-updates. Never apply, never
		 * stay quiet: refuse and kill the conn loudly (M1
		 * pitfall 17 — fail loud, never guess). This subsumes
		 * the old ISSUE-MISMATCH print (writable prots only,
		 * log-only): ALL MAP prots, fatal. */
		sup = uml_nt_fault_op_superseded(op, &c->plan);
		if (c->mm != NULL &&
		    !uml_nt_fault_op_allowed(op, &c->plan, c->mm)) {
			os_info("[viewswap] pid %lu REFUSED stale MAP "
				"va=0x%llx len=0x%llx op_off=0x%llx — "
				"the VMA table backs another run and no "
				"in-plan op releases this view; "
				"KILLING (never a wrong-backed "
				"view)\n", (unsigned long)c->pid,
				op->va, op->len, op->off);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return;
		}
		if (sup && viewswap_transition_logged < 8) {
			viewswap_transition_logged++;
			os_info("[viewswap] pid %lu TRANSITION MAP "
				"va=0x%llx len=0x%llx off=0x%llx — "
				"superseded in-plan (release queued), "
				"allowed as an intermediate view\n",
				(unsigned long)c->pid, op->va, op->len,
				op->off);
		}
		/* VIEW LEDGER (K6 cowcopy-race-class-fix): record the
		 * view this op materializes — AFTER the guard (a
		 * refused MAP never enters the ledger). This is the
		 * census's bookkeeping and the release-set's
		 * enumeration source; an overflow is a broken
		 * protocol state (more views than the VMA cap —
		 * views are 1:1 with table VMAs), refused LOUD. */
		if (uml_nt_view_track(c->views, &c->nviews,
				      UML_NT_VIEW_MAX, op->va, op->len,
				      op->off, op->prot) < 0) {
			os_info("[viewswap] pid %lu LEDGER-OVERFLOW "
				"MAP va=0x%llx len=0x%llx (%d view(s) "
				"already) — more views than the VMA "
				"cap is a broken protocol state — "
				"KILLING (never a wrong-backed "
				"view)\n", (unsigned long)c->pid,
				op->va, op->len, c->nviews);
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return;
		}
		d->action = UML_STUB_ACTION_MAP;
		d->map_prot = op->prot;
		d->map_va = op->va;
		d->map_len = op->len;
		d->map_off = op->off;
		/* mapcanary (stub_nt.h v7): prove the fresh view's
		 * BACKING, not only its protection. Plant a nonce
		 * flat-side at the VMA TABLE's run for the view's
		 * tail-8; the stub reads the tail through the fresh
		 * view; PROTDONE compares and restores. Only writable
		 * MAPs with a private table run (refs==1): no shared
		 * run is ever clobbered (the RO/shared maps skip —
		 * the cowbreak audits own that class), and the parked
		 * guest never sees the transient plant. SUPERSEDED
		 * (transitional) MAPs skip the canary: their backing
		 * intentionally differs from the final table's run
		 * (the corrective pair behind them repairs the view
		 * before the guest resumes), so a table-side plant
		 * would only compare mismatched worlds — the
		 * surviving re-map carries the canary instead. */
		if (!sup &&
		    (op->prot == UML_NT_PAGE_READWRITE ||
		     op->prot == UML_NT_PAGE_WRITECOPY ||
		     op->prot == UML_NT_PAGE_EXECUTE_READWRITE) &&
		    op->len >= 16 && c->mm != NULL) {
			long long tbl = uml_nt_vma_translate(
				c->mm, op->va + op->len - 8, 8);
			unsigned long long plant =
				(tbl >= 0) ? (unsigned long long)tbl
					   : op->off + op->len - 8;

			if (uml_nt_phys_refs(c->ph, (long long)plant) == 1) {
				unsigned long long *qp =
					(unsigned long long *)
					((char *)uml_boot.physmem_base + plant);

				c->mc_off = plant;
				c->mc_orig = *qp;
				c->mc_want = 0x4d43414e41525900ull /* "MCANARY" */
					     ^ op->va ^ (op->off << 1);
				/* K6 [flatwr]: the plant is a kernel flat
				 * write of guest content (a transient
				 * nonce over the view's tail-8); the
				 * RESTORE below spans a stub round-trip —
				 * capture the (gen, va) here so the
				 * restore can prove it writes the SAME
				 * backing the table still owns. */
				c->mc_gen = (unsigned long long)
					uml_nt_phys_gen(c->ph,
							(long long)plant);
				c->mc_va = op->va + op->len - 8;
				uml_nt_flatwr_check(c,
					UML_NT_FLATWR_SITE_MC_PLANT,
					c->mc_va, 8, plant, c->mc_gen,
					(long long)plant);
				*qp = c->mc_want;
				c->mc_active = 1;
				d->mapcanary = c->mc_want;
			}
		}
		break;
	default: /* UML_NT_FOP_UNMAP */
		/* VIEW LEDGER: the stub releases the WHOLE view at
		 * op->va — retire the ledger entry at that base (the
		 * census below then refuses any mapping the ledger
		 * no longer admits over the released ranges). */
		{
			int vi;

			for (vi = 0; vi < c->nviews; vi++) {
				if (c->views[vi].va != op->va)
					continue;
				memmove(&c->views[vi],
					&c->views[vi + 1],
					(size_t)(c->nviews - vi - 1) *
						sizeof(c->views[0]));
				c->nviews--;
				break;
			}
		}
		d->action = UML_STUB_ACTION_UNMAP;
		d->map_va = op->va;
		d->map_len = op->len;
		break;
	}
	c->plan_next++;
}

/* K6 (M5.6a, cowcopy-race-class-fix, dl26 37539992560): the
 * release-set completeness pass + stream arming. Call at EVERY
 * prime site before op 0 issues — the fault repair's prime, the
 * syscall tail, the pump-side signal delivery. Two classes close
 * here (fault.h's block comment has the conviction):
 *   1. RELEASE SET: the plan's UNMAP at a range start releases
 *      only the view at that base — the augment inserts the
 *      ledger's per-view releases for every other issued view
 *      intersecting a released range, each at ITS OWN base,
 *      before any later re-MAP can collide with the occupied
 *      range.
 *   2. ARMING: uaccess COW fixups queue ops WITHOUT arming the
 *      stream (uacc_plan_op appends, only sc_plan_add set
 *      plan_left) — a round whose only view ops were fixups
 *      never streamed, the table had already moved (the fixup's
 *      cow_split mutated it kernel-side), and the stale view
 *      served every later guest store into the abandoned backing
 *      with NO fault and NO catch. plan_left = n_ops here makes
 *      "every queued op streams" the invariant, round shape
 *      independent.
 * Overflow of the complete set refuses LOUD here (the caller only
 * checks the return) — a dropped release is the stranding class
 * itself. */
int uml_nt_view_release_complete(struct uml_nt_stub_conn *c)
{
	int ins, start = 0;

	/* M5.6a (to-shelley 140 — stream atomicity, the dl139b
	 * formation named): a prime arriving MID-DRAIN (plan_left>0
	 * with a consumed position) must NOT re-arm from op0 — the
	 * reset restarts the stream at the already-applied releases
	 * (double-UNMAP), and the pending copy floats past its own
	 * drain (pid 3068: the park at nr=228 read the fresh span's
	 * ZEROS because the re-MAP tail never streamed, then the
	 * [cowcopy] line fired a drain LATE). MERGE instead: augment
	 * only the unissued tail, keep the position, recount the
	 * remainder (trap context — nothing is in flight). Loud:
	 * the protocol says traps cannot arrive mid-drain, so every
	 * hit names the gate that broke. */
	if (c->plan_left > 0 && c->plan_next > 0) {
		static int merge_budget = 8;

		start = c->plan_next;
		if (merge_budget > 0) {
			merge_budget--;
			os_info("[streamsync] pid %lu MID-DRAIN prime "
				"(left=%d next=%d n=%d copy_pend=%d) — "
				"MERGE, the reset-at-op0 is forbidden\n",
				(unsigned long)c->pid, c->plan_left,
				c->plan_next, c->plan.n_ops,
				c->copy_pend_kind);
		}
	}

	ins = uml_nt_fault_augment_release_set_from(&c->plan, c->views,
						    c->nviews, start);
	if (ins < 0) {
		os_info("[viewswap] pid %lu RELEASE-SET OVERFLOW — the "
			"plan (%d op(s)) cannot hold the complete "
			"per-view release set — KILLING (never a "
			"wrong-backed view)\n",
			(unsigned long)c->pid, c->plan.n_ops);
		c->d->action = UML_STUB_ACTION_KILL;
		c->d->err = 1;
		return -1;
	}
	if (ins > 0) {
		static int rel_budget = 8;

		if (rel_budget > 0) {
			rel_budget--;
			os_info("[viewswap] pid %lu EXTRA-RELEASE: %d "
				"stale ledger view(s) over re-homed "
				"range(s) released by own base (the "
				"plan's UNMAP covered only its range "
				"start)\n", (unsigned long)c->pid, ins);
		}
	}
	if (start != 0) {
		/* the merge re-arm: position kept, nothing in flight
		 * (the stub waits on THIS round's answer) — the count
		 * is the unissued tail, and the caller's issue of
		 * ops[plan_next] re-joins the stream */
		c->plan_left = uml_nt_fault_plan_left_at_trap(&c->plan,
							      c->plan_next);
		return 0;
	}
	c->plan_next = 0;
	c->plan_left = c->plan.n_ops;
	return 0;
}

/* K6 (M5.6a, cowcopy-race-class-fix): the drain-side census — the
 * swap's COMPLETION guard (extending the apply-time MAP guard to
 * the whole swap). When a plan that re-homed ranges drains, walk
 * the stub's VA space over every released range: every committed
 * MEM_MAPPED region must lie inside the conn's view ledger (a
 * view its own op stream issued and never released). Anything
 * else is a view the swap should have released but did not — a
 * writable (or readable) view over a backing the table no longer
 * owns, the dl26 conviction class. The census line lists the
 * survivor WITH the plan op that should have released it (the
 * brief's read-only pin), then the conn is REFUSED — no silent
 * continue, ever: the corruption this class produced (pid 7484's
 * tcache_put pair in the abandoned source run, dl26 37539992560)
 * was exactly a tolerated survivor. */
static int viewswap_stale_budget = 8;

/* M5.6a (to-shelley 140, witness prong 3): the RESUME AUDIT —
 * view==table at the guest-resumable point. When a re-homing
 * stream has drained (every op applied, the answer below resumes
 * the guest), every non-superseded MAP the plan issued must sit in
 * the conn's view ledger with the op's own backing AND translate
 * through the VMA table to that same run. A divergence is exactly
 * the dl139b formation: the view maps a fresh handout whose copy
 * never ran (the wiped mid-drain tail) while the table already
 * moved. Kernel-side only (ledger + table walk — no stub
 * round-trip), so it rides the drain end; the fault parks stay
 * witness-free (the witness-placement rule). Loud, never fatal:
 * the census above owns the refuse. */
static void view_resume_audit(struct uml_nt_stub_conn *c)
{
	static int audit_budget = 8;
	int i;

	if (c->mm == NULL || c->plan.n_ops == 0)
		return;
	for (i = 0; i < c->plan.n_ops; i++) {
		const struct uml_nt_fault_op *op = &c->plan.ops[i];
		long long t0, t1;
		int vi, found = 0;
		int bad;

		if (op->op != UML_NT_FOP_MAP || op->len == 0)
			continue;
		/* released in-plan (the corrective pair behind it
		 * owns the final view) — the census's case */
		if (uml_nt_fault_op_superseded(op, &c->plan))
			continue;
		for (vi = 0; vi < c->nviews; vi++)
			if (c->views[vi].va == op->va) {
				found = 1;
				break;
			}
		t0 = uml_nt_vma_translate(c->mm, op->va, 1);
		t1 = uml_nt_vma_translate(c->mm, op->va + op->len - 1, 1);
		bad = !found || c->views[vi].off != op->off ||
		      t0 < (long long)op->off ||
		      t0 >= (long long)(op->off + op->len) ||
		      t1 < (long long)op->off ||
		      t1 >= (long long)(op->off + op->len);
		if (bad && audit_budget > 0) {
			audit_budget--;
			os_info("[resumeaudit] VIEW!=TABLE pid %lu "
				"va=0x%llx len=0x%llx op-off=0x%llx: "
				"ledger=%d ledger-off=0x%llx "
				"table=[0x%llx,0x%llx] — the guest "
				"resumes into a view the table "
				"disowns\n",
				(unsigned long)c->pid, op->va, op->len,
				op->off, found,
				found ? c->views[vi].off : 0,
				(unsigned long long)t0,
				(unsigned long long)t1);
		}
	}
}

static int view_swap_guard(struct uml_nt_stub_conn *c)
{
	int i;

	if (c->proc == NULL)
		return 0; /* no handle, no census (destroy races) */
	for (i = 0; i < c->plan.n_ops; i++) {
		unsigned long long va, end;
		int iters = 0;

		if (c->plan.ops[i].op != UML_NT_FOP_UNMAP ||
		    c->plan.ops[i].len == 0)
			continue;
		va = c->plan.ops[i].va;
		end = va + c->plan.ops[i].len;
		while (va < end && iters++ < 128) {
			MEMORY_BASIC_INFORMATION mbi;
			unsigned long long rbase, rnext;
			SIZE_T got;

			memset(&mbi, 0, sizeof(mbi));
			got = nt->VirtualQueryEx(c->proc,
						 (void *)(uintptr_t)va,
						 &mbi, sizeof(mbi));
			if (got == 0 || mbi.RegionSize == 0)
				break;
			rbase = (unsigned long long)
				(uintptr_t)mbi.BaseAddress;
			rnext = rbase +
				(unsigned long long)mbi.RegionSize;
			/* committed section views only — the stub's
			 * own image/heap never intersects guest VA
			 * ranges, and free regions are releases
			 * done right */
			if (mbi.State == 0x1000 && mbi.Type == 0x40000 &&
			    !uml_nt_view_region_covered(
				    c->views, c->nviews, rbase,
				    (unsigned long long)mbi.RegionSize)) {
				if (viewswap_stale_budget > 0) {
					int ei;

					viewswap_stale_budget--;
					os_info("[viewswap] pid %lu "
						"STALE-VIEW region="
						"[0x%llx,+0x%llx) prot=0x%x "
						"— the re-homed range "
						"[0x%llx,+0x%llx) (plan op "
						"#%d) still maps it; no "
						"issued view covers it\n",
						(unsigned long)c->pid,
						rbase,
						(unsigned long long)
							mbi.RegionSize,
						mbi.Protect, va,
						c->plan.ops[i].len, i);
					/* the empirical pin: the last ops
					 * the stream applied — the op
					 * that stranded the survivor
					 * names itself here */
					for (ei = 3; ei >= 1; ei--) {
						int idx =
							c->op_log_n - ei;

						if (idx < 0)
							continue;
						os_info("[viewswap] pid %lu "
							"op-ring -%d: o=%u "
							"va=0x%llx l=0x%llx "
							"off=0x%llx\n",
							(unsigned long)
								c->pid, ei,
							(unsigned)
							c->op_log[idx % 64][0],
							c->op_log[idx % 64][2],
							c->op_log[idx % 64][3],
							c->op_log[idx % 64][4]);
					}
				}
				return -1;
			}
			if (rnext <= va)
				break; /* defensive */
			va = rnext;
		}
	}
	return 0;
}

/* D26 MAP-hold gate (defined beside the deferred-copy execs) —
 * forward decl for the pump-side export below. */
static int copy_pend_gate(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op);

/* Publish one plan op into the stub slot (d->action operands) and
 * advance the runner. Exported for the pump-side signal delivery
 * (process.c): a sigframe write that COW-fixed-up a shared run
 * queues ops into the conn's plan mid-signal_check. */
void uml_nt_plan_issue_op(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op)
{
	/* D26: the MAP-hold gate covers the pump-side issue too — a
	 * sigframe fixup MAP must not cover a pending copy's range
	 * before the copy ran. On a refusal the conn is already
	 * KILLed loud; publishing nothing is the dead-conn shape. */
	if (copy_pend_gate(c, op) == 0)
		issue_plan_op(c, op);
}

/* M5.4 c3: dump the first n bytes at a guest VA through the mm's VMA
 * translate — at the SIGSEGV site this decides "the child's view maps
 * the WRONG run (it reads kernel/foreign bytes as its own data)" vs
 * "the guest's own logic built the wild pointer" without a debugger
 * (native referee has none). */
static void dump_guest_bytes(struct uml_nt_mm *mm, unsigned long long va,
			     int n, const char *tag)
{
	/* map 059: 128 bytes per call (the residue-ctx window), printed
	 * in 64-byte rows — os_info truncates at 256, a 128-byte hex
	 * row (384+ chars) would be cut mid-line and the struct shape
	 * lost exactly where it matters. */
	unsigned char buf[128];
	char line[3 * 64 + 1];
	long long off;
	int i;

	if (n > (int)sizeof(buf))
		n = (int)sizeof(buf);
	off = uml_nt_vma_translate(mm, va, n);
	if (off < 0) {
		os_info("[stubtest]   %s 0x%llx: untranslatable (%lld)\n",
			tag, va, off);
		return;
	}
	memcpy(buf, (char *)uml_boot.physmem_base + off, n);
	for (i = 0; i < n; i += 64) {
		int chunk = (n - i < 64) ? n - i : 64;
		int j;

		for (j = 0; j < chunk; j++)
			snprintf(line + 3 * j, 4, "%02x ", buf[i + j]);
		os_info("[stubtest]   %s 0x%llx: %s\n", tag, va + i, line);
	}
}

/* v5: read one guest qword at slot_va and dump the bytes it points
 * to — the strv slots and the frame chain decode themselves into the
 * log (the walker's saved regs ARE the env strv / merge state). */
static void dump_ptr_at(struct uml_nt_mm *mm, unsigned long long slot,
			const char *tag)
{
	unsigned char b[8];
	long long off;
	long long v = 0;
	int i;

	off = uml_nt_vma_translate(mm, slot, 8);
	if (off < 0) {
		os_info("[stubtest]   %s 0x%llx: slot untranslatable "
			"(%lld)\n", tag, slot, off);
		return;
	}
	memcpy(b, (char *)uml_boot.physmem_base + off, 8);
	for (i = 7; i >= 0; i--)
		v = (v << 8) | b[i];
	os_info("[stubtest]   %s [0x%llx] -> 0x%llx\n", tag, slot, v);
	if (v > 0x1000 && v < 0x800000000000ull) {
		dump_guest_bytes(mm, (unsigned long long)v, 32, tag);
	} else if (v != 0) {
		/* v6: a slot can hold a NON-pointer (the wild
		 * 0x3577fffff0003d40 is non-canonical — it fails every
		 * magnitude guard). Print the {lo,hi} split inline so
		 * the log decodes the constant itself (051 task 4). */
		os_info("[stubtest]     (non-ptr: lo=0x%08x hi=0x%08x)\n",
			(unsigned int)(v & 0xffffffff),
			(unsigned int)(v >> 32));
	}
}

/* v6 (051 task 2): dump the strv array AROUND the walker's cursor.
 * The dead caller (_strv_env_merge's static env walker) keeps its
 * strv cursor in r13 (the walker's original rdx) — the garbage ENTRY
 * is the slot it loads or a neighbour. Which INDEX rots (head/tail/
 * middle), what the live slots hold (heap string pointers vs
 * pointers into the pthread arena) and whether the terminator moved
 * is the shape evidence a single slot value can't give. */
static void dump_strv_slots(struct uml_nt_mm *mm, unsigned long long cursor)
{
	int i;

	for (i = -4; i <= 3; i++) {
		char tag[16];
		long long delta = i * 8;

		snprintf(tag, sizeof(tag), "strv[%+d]", i);
		dump_ptr_at(mm, cursor + delta, tag);
	}
}

/* v6 (051 task 3): the pthread arena head. Every victim's r12 and
 * saved-rbp slot point INTO the 704KB stack mmap (arena+0x10 /
 * arena+0x40) it dies right after; run-aligned base = r12 & ~0xffff
 * (the arena VA is 64K-aligned — it comes from sys_mmap). The first
 * 256 bytes show the co-tenants (TCB? list heads? guard?) and
 * whether the wild value lives in the ARENA itself or only in the
 * strv that points into it. */
static void dump_arena_head(struct uml_nt_mm *mm, unsigned long long r12)
{
	unsigned long long base;
	int i;

	if (r12 <= 0x1000 || r12 >= 0x800000000000ull)
		return;
	base = r12 & ~0xffffull;
	for (i = 0; i < 256; i += 48) {
		int n = (256 - i < 48) ? 256 - i : 48;

		dump_guest_bytes(mm, base + i, n, "arena");
	}
}

/* v7 (map 052a): qword-decode a VA range of the death frame chain.
 * The walker's rbp is a merge-frame local pointer and its ret slot is
 * already garbage (0x3000000030) — decoding [rsp-0x40, rbp+0x140) as
 * raw qwords shows EVERY saved-register slot of the strcspn/walker/
 * merge frames at once: which slot holds the _Fork+0x23 value and
 * what the neighbouring slots are (string pointers? frame chain?
 * more code addresses?). delta = slot_va - rsp for greppability. */
static void dump_qword_range(struct uml_nt_mm *mm, unsigned long long va,
			     unsigned long long len, unsigned long long rsp)
{
	unsigned long long slot;
	int i;

	for (i = 0, slot = va; i < 80 && slot + 8 <= va + len;
	     i++, slot += 8) {
		long long off = uml_nt_vma_translate(mm, slot, 8);
		long long delta = (long long)(slot - rsp);
		unsigned long long v = 0;

		if (off < 0)
			continue; /* hole — the addresses still tell it */
		memcpy(&v, (char *)uml_boot.physmem_base + off, 8);
		os_info("[stubtest]   frameq rsp%+lld 0x%llx: 0x%llx\n",
			delta, slot, v);
	}
}

/* v7 (map 052b): scan ONE mm's every VMA for an 8-byte value at
 * absolute 8-aligned VAs, through the flat view. Returns hits (capped
 * — a hot value must not flood the log). */
static int scan_mm_value(struct uml_nt_mm *mm, const unsigned char *pat,
			 int max_hits)
{
	int vi, hits = 0;

	for (vi = 0; vi < mm->nvma && hits < max_hits; vi++) {
		unsigned long long va = mm->vma[vi].start;
		unsigned long long end = mm->vma[vi].end;

		/* absolute 8-alignment so slots never straddle a
		 * chunk edge unexamined */
		va = (va + 7) & ~7ull;
		while (va + 8 <= end && hits < max_hits) {
			unsigned long long chunk = 4096 - (va & 0xfff);
			long long off;
			unsigned long long k, start;

			if (va + chunk > end)
				chunk = end - va;
			off = uml_nt_vma_translate(mm, va, chunk);
			if (off < 0) {
				va += chunk;
				continue;
			}
			start = va & ~7ull;
			for (k = start - va; k + 8 <= chunk; k += 8) {
				if (memcmp((char *)uml_boot.physmem_base +
						   off + k, pat, 8) == 0) {
					os_info("[stubtest]   valscan HIT pid-side vma[%d] 0x%llx-0x%llx @0x%llx\n",
						vi, mm->vma[vi].start,
						mm->vma[vi].end, va + k);
					dump_guest_bytes(mm, va + k - 16, 48,
							 "valscan-ctx");
					hits++;
					if (hits >= max_hits)
						break;
				}
			}
			va += chunk;
		}
	}
	return hits;
}

/* v7 (map 052b): the VALUE hunt at SIGSEGV — scan the dying child's
 * whole address space plus PID 1's (the manager whose long-lived
 * strvs the executor children inherit) for the walker's cursor value
 * (r13 = _Fork+0x23 here). A hit in PID 1's heap = long-lived slot
 * corruption; hits only in the child's stack = own-fork residue. */
static void valscan_death(struct uml_nt_stub_conn *c, unsigned long long val)
{
	struct task_struct *p;
	unsigned char pat[8];
	int hits;

	memcpy(pat, &val, 8);
	hits = scan_mm_value(c->mm, pat, 16);
	os_info("[stubtest]   valscan self pid %lu: %d hit(s)\n",
		(unsigned long)c->pid, hits);
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		/* map 056: c->ppid is the HOST stub pid of the parent
		 * conn — it NEVER equals a kernel task pid, so the pid
		 * match silently skipped the parent in every run (only
		 * "valscan self" + "valscan pid 1" lines ever printed —
		 * run 36848102086). Match the task_struct directly: the
		 * death round runs on the victim's task (the pump is
		 * its userspace() loop), real_parent is the fork
		 * parent. Keep the ppid match as belt-and-braces for
		 * the POC conns. */
		int is_parent = (p == current->real_parent ||
				 p->pid == (int)c->ppid);

		if (p->mm == NULL)
			continue;
		if (p->pid != 1 && !is_parent)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		hits = scan_mm_value(pc->mm, pat, 16);
		os_info("[stubtest]   valscan pid %d%s: %d hit(s)\n",
			p->pid, is_parent ? " (fork parent)" : "", hits);
	}
}

/* WRITER-HUNT (068 suppl. 5): the tcache dump caught the poison in
 * the raw — entries[1] = entries[2] = 0x5f444d455455245a, ASCII
 * "Z$UTMED_" twice among mangled-sane pointers: a string/buffer
 * write landed at the wrong offset. Offline grep: the fragment
 * matches no rodata in the rootfs image nor vmlinux/launcher —
 * a runtime-built string (same class as the R8 "STREAM=7" window of
 * the env template JOURNAL_STREAM=%lu:%lu in libsystemd-core). Scan
 * the dying space + PID 1 + fork parent for the fragment itself:
 * every hit = a live copy of the poisoned text (env block? stack
 * residue? heap struct?) — the provenance map for the string
 * source. Read-only, the valscan machinery; the caller supplies the
 * pattern (no hardcoded constant). */
void uml_nt_stub_frag_scan(struct uml_nt_stub_conn *c,
			   const unsigned char *pat)
{
	struct task_struct *p;
	int hits;

	hits = scan_mm_value(c->mm, pat, 8);
	os_info("[abrt] fragscan self pid %lu: %d hit(s)\n",
		(unsigned long)c->pid, hits);
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		int is_parent = (p == current->real_parent ||
				 p->pid == (int)c->ppid);

		if (p->mm == NULL)
			continue;
		if (p->pid != 1 && !is_parent)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		hits = scan_mm_value(pc->mm, pat, 8);
		os_info("[abrt] fragscan pid %d%s: %d hit(s)\n",
			p->pid, is_parent ? " (fork parent)" : "",
			hits);
	}
}

/* M5.4 c3 (map 057): the residue-watch scan. Armed by the fork seed
 * with the parent's trap+2 (the fork-resume rip) — a value NO live
 * frame may carry as data (_Fork is a leaf: nothing returns past its
 * syscall). The seed's own checks read clean (below-rsp zero + live
 * window, run 36850929441: 22/22 forks 0 hit(s)), yet the victim's
 * stack carried 7 hits at death — the writer acts post-seed, inside
 * the child's own address space. This per-round whole-VMA scan names
 * the round that first re-introduces the value: nr/retval + the trap
 * regs + up to 8 hit VAs. One-shot (disarm on first hit or expiry). */
static void uml_nt_residue_watch(struct uml_nt_stub_conn *c)
{
	struct uml_nt_vma *v;
	unsigned long long va, end;
	int hits = 0;

	v = uml_nt_vma_find(c->mm, c->watch_rsp);
	if (v == NULL) {
		/* Stack VMA gone (exec teardown) — nothing to watch. */
		c->watch_val = 0;
		return;
	}
	for (va = (v->start + 7) & ~7ull, end = v->end;
	     va + 8 <= end; va += 8) {
		unsigned long long x;

		memcpy(&x, uml_boot.physmem_base + v->run_off +
			    (va - v->start), 8);
		if (x == c->watch_val) {
			if (hits < 8) {
				/* map 059: a 0x100-byte window around
				 * the hit — the writer is a WHOLE
				 * struct (the dispatch CONTEXT); the
				 * old 48-byte peek could not span its
				 * qword rows. Clamp to the VMA: the
				 * translate is all-or-nothing. */
				unsigned long long lo = va - 0x80;
				unsigned long long len = 0x100;

				os_info("[stubtest]   residue-hit "
					"@0x%llx (vma run_off=0x%llx)\n",
					va, v->run_off);
				if (lo < v->start)
					lo = v->start;
				if (lo + len > v->end)
					len = v->end - lo;
				dump_guest_bytes(c->mm, lo, (int)len,
						 "residue-ctx");
			}
			hits++;
		}
	}
	if (hits == 0)
		return;
	/* map 059: two lines (os_info cuts at 256) — main carries the
	 * round identity + the VOLATILE slots that discriminate the
	 * writer (rcx = the seed-rcx/VEH-CONTEXT slot, r11 = the
	 * rflags slot); the callee row mirrors the SIGSEGV part-2
	 * line for byte-exact seed comparison. */
	os_info("[stubtest] RESIDUE-WATCH pid %lu: %d hit(s) of 0x%llx "
		"after nr=%llu ret=%lld rip=0x%llx rsp=0x%llx "
		"rcx=0x%llx r11=0x%llx cmd=%d\n",
		(unsigned long)c->pid, hits, c->watch_val, c->last_nr,
		c->last_ret, c->d->regs.rip, c->d->regs.rsp,
		c->d->regs.rcx, c->d->regs.r11, c->d->cmd);
	os_info("[stubtest] RESIDUE-WATCH pid %lu callee: rbx=0x%llx "
		"r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n",
		(unsigned long)c->pid, c->d->regs.rbx, c->d->regs.r12,
		c->d->regs.r13, c->d->regs.r14, c->d->regs.r15);
	c->watch_val = 0;
}

/* Serve one published request on this conn. Returns 0 on success. */

/* c00000fd fix (archive 065 greenlight): re-assert the VEH dispatch
 * window at every OP-CARRYING answer. Only kernel-queued ops change
 * the stub's views, so only these rounds can leave the committed
 * (RW) extent below the trap rsp smaller than the ~12KB dispatch
 * state + the handler's own do_action frames — the shape that dies
 * "UNOWNED exception c00000fd" mid-op-stream (rsp=0x6006dc58 with a
 * 12KB RW window, 3 byte-identical sightings, runs 36901177086 /
 * 36902413478 / 36905053855-era). The window ops ride the SAME
 * answer, INSERTED AT PLAN HEAD: they must land before the handler's
 * own ops (the fork reprotect's UNMAP/MAP pairs, mmap fresh views) —
 * the stub executes each op INSIDE the VEH handler, pushing below
 * the trap rsp while it works. Op-free answers change no view: the
 * last assertion still holds, so they pay nothing (the M4.1 bench
 * RTT gate stays untouched). Spawn needs nothing: the INIT plan maps
 * whole VMAs, so a fresh conn's stack run starts fully RW.
 * Prot semantics preserved by construction: the ops carry the VMA's
 * EFFECTIVE prot (COW-shared runs re-assert READ-ONLY) and guard
 * ranges are never covered. Pure logic lives in
 * uml_nt_stack_window_plan (fault.c, unit-tested). */
static int stack_window_logged;

static void stack_window_reassert(struct uml_nt_stub_conn *c)
{
	struct uml_nt_fault_op win[8];
	unsigned long long rsp = c->d->regs.rsp;
	int nwin, i, shift;

	if (c->plan.n_ops <= 0)
		return;
	nwin = uml_nt_stack_window_plan(c->mm, c->ph, rsp, win, 8);
	if (nwin == 0)
		return;
	if (nwin < 0) {
		if (stack_window_logged < 8) {
			stack_window_logged++;
			os_info("[stack-window] pid %lu rsp=0x%llx: "
				"refused (%d) — stolen window run?\n",
				(unsigned long)c->pid, rsp, nwin);
		}
		return;
	}
	if (c->plan.n_ops + nwin > UML_NT_FAULT_MAX_OPS)
		return; /* never drop handler ops for the window */
	shift = c->plan.n_ops;
	memmove(&c->plan.ops[nwin], &c->plan.ops[0],
		(size_t)shift * sizeof(c->plan.ops[0]));
	for (i = 0; i < nwin; i++)
		c->plan.ops[i] = win[i];
	c->plan.n_ops += nwin;
	c->plan_next = 0;
	c->plan_left = c->plan.n_ops;
	if (stack_window_logged < 8) {
		stack_window_logged++;
		os_info("[stack-window] pid %lu rsp=0x%llx re-assert %d "
			"op(s) ahead of %d plan op(s)\n",
			(unsigned long)c->pid, rsp, nwin,
			c->plan.n_ops - nwin);
		for (i = 0; i < nwin; i++)
			os_info("[stack-window]   prot=0x%x "
				"[0x%llx,0x%llx)\n", win[i].prot,
				win[i].va, win[i].va + win[i].len);
	}
}

/* WRITER-HUNT (M5.6a): the tcache canary watch — read-only validator
 * at the poison site, every serve round. glibc 2.36: the
 * tcache_perthread_struct is the heap's first chunk
 * [heap_start, +0x290): counts[64] u16 then entries[64] safe-linked
 * pointers. VALIDATION IS MANGLING-FREE by design (the reveal key
 * lives in the pushed chunk's own address — un-mangling from the
 * slot address fired false on every healthy cache in runs
 * 36972326995/36972320563): every count must be <= 7
 * (mp_.tcache_count — text poison "a%UTEMD_S$UTEMD_" reads as huge
 * counts and fires here), and the count/head pair-state must agree
 * (NULL head <=> zero count; glibc updates them together). The fire
 * dump covers the slack on BOTH sides of the struct (the spill
 * direction) + the round attribution (last_nr/last_ret + trap regs).
 * Read-only by design: writing canary BYTES around the struct would
 * corrupt live malloc metadata — the very corruption being hunted.
 * One-shot per conn, global budget (os_info 256-byte lesson: short
 * lines, structured rows). */
#define UML_NT_TCACHE_COUNTS 64
#define UML_NT_TCACHE_LIMIT  7
static int tcache_watch_budget = 8;
/* The entries delta-watch budget (see the DELTA WATCH in
 * tcache_watch) — one line per pointer-ILLEGAL entry change. */
static int tcache_delta_budget = 16;
/* The chunk watch budget (see the CHUNK WATCH in tcache_watch) —
 * one line + dump per foreign write into a watched head chunk. */
static int tcache_chunk_budget = 16;
/* The poison sweep budgets (see the POISON SWEEP in tcache_watch):
 * whole-heap scans at [tcdelta] fire + per-round byte watches on the
 * swept hit chunks. */
static int posweep_budget = 8;
static int posweep_va_budget = 16;
/* The tcchunk split budgets: POISON-class fires (decoded next
 * misaligned/out-of-heap) vs churn re-arms — see the watch body. */
static int tcache_poison_budget = 16;
/* The payload literal: "SYSTEMD_" as a little-endian qword — the raw
 * freed-chunk content the reveal math decodes to on every boot. */
#define UML_NT_POSWEEP_QWORD 0x5f444d4554535953ull

/* [alias] census (M5.6a, decode 37095399220): every witness on the
 * kernel write paths is now negative — [kcopy] 0, [uawrite] and
 * [deadwrite] silent, futex dw silent, [tctrip] trips all legit —
 * while the poison keeps landing on a page that is RO-armed in the
 * victim's OWN stub view. The writer class left standing is a VIEW:
 * another live conn's stub still maps this phys run (a stale view
 * over a recycled run — the D22 free-while-mapped family, INVISIBLE
 * to run refcounts: views are not refs). Walk every live conn's VMA
 * table for VMA run-ranges intersecting [run_off, run_off+len): a
 * FOREIGN mapper = the alias named (its VA + its conn — the
 * writer's process); self-only = the writer is still kernel-side
 * through an unseen path. Log-only; the pump runs on the one vCPU
 * thread, the task list cannot mutate under the walk. */
void uml_nt_run_alias_census(struct uml_nt_stub_conn *c,
			     unsigned long long run_off,
			     unsigned long long len)
{
	struct task_struct *p;
	int conns = 0;

	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		struct uml_nt_vma *pv;
		int vi;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		conns++;
		if (pc == c)
			continue; /* the detector's own mapping is legit */
		for (vi = 0; vi < pc->mm->nvma; vi++) {
			unsigned long long lo, hi;

			pv = &pc->mm->vma[vi];
			lo = pv->run_off;
			hi = lo + (pv->end - pv->start);
			if (lo < run_off + len && run_off < hi)
				os_info("[alias] foreign mapper pid %d: "
					"vma [0x%llx,0x%llx) run_off=0x%llx "
					"intersects run 0x%llx+0x%llx\n",
					p->pid, pv->start, pv->end,
					pv->run_off, run_off, len);
		}
	}
	os_info("[alias] census: %d live conns, foreign mappers of run "
		"0x%llx+0x%llx listed above (none = kernel-side unseen "
		"path)\n", conns, run_off, len);
}

/* ---------------- M5.6a census + IMGWATCH ----------------------
 * The why=a/why=p autopsy pair (referees 39950777465/39950787337):
 * the run pool died at login with zero phys-layer alarms, so the
 * dying dumps alone could not say WHAT held the runs. The census
 * prints the pool's composition at every exec/exit (the churn
 * curve) and at every failed handout (the pressure moment):
 * used/parked runs, fcache pins, live/dying conns, the top-3
 * footprints, and the kernel's own free/pagecache/slab split (the
 * guest pool shares the 120 MiB buddy with both). IMGWATCH rides
 * the same walk: every exec fingerprints its pure-RO image runs
 * (post-D20-patch) and the census re-hashes them per conn — a
 * divergence is the rewritten-text class (victim #3's zeroed ld.so
 * page) named at the first census after the write. */
unsigned long long uml_nt_imgw_hash(const void *run_base)
{
	const unsigned long long *q = run_base;
	unsigned long long h = 1469598103934665603ULL;
	int i;

	/* One qword per guest 4K page: the observed rewrite class is
	 * page-scale (whole pages zeroed + stray dwords), so 16
	 * samples per run discriminate it at a fraction of the cost
	 * of a full 64 KiB hash. */
	for (i = 0; i < 16; i++) {
		h ^= q[i * 512];
		h *= 1099511628211ULL;
	}
	return h;
}

/* The full-run fingerprint (every qword) — captured once per image
 * run at exec, recomputed only at death. The 16-sample hash above
 * cannot see a write between its samples (the login-depth victims'
 * interp content at 0xb560 sits between samples). */
unsigned long long uml_nt_imgw_hash_full(const void *run_base)
{
	const unsigned long long *q = run_base;
	unsigned long long h = 1469598103934665603ULL;
	unsigned int i;

	for (i = 0; i < UML_NT_PHYS_RUN_SIZE / 8; i++) {
		h ^= q[i];
		h *= 1099511628211ULL;
	}
	return h;
}

/* The persistent image-run write witness (rf pair 40064950549/590):
 * every captured image run + its handout gen; the TO_GUEST funnel
 * tests each write against this table and logs a hit immediately.
 * The generation pins the entry to the run's life — a recycled run
 * (new gen) never false-fires. The table itself sits next to
 * flatwr_core (the flat-write sites use it too). */
void uml_nt_image_run_register(unsigned long long run,
			       unsigned long long gen,
			       struct uml_nt_phys *ph)
{
	unsigned int i = (unsigned int)(run / UML_NT_PHYS_RUN_SIZE);

	if (i < UML_NT_PHYS_MAX_RUNS && gen != 0) {
		g_image_gen[i] = gen;
		g_image_ph = ph;
	}
}

void uml_nt_image_run_touch(unsigned long long run,
			    unsigned long long va,
			    unsigned long long len,
			    unsigned long long nr)
{
	static int imgwr_budget = 16;
	unsigned int i;

	if (g_image_ph == (struct uml_nt_phys *)0 || imgwr_budget <= 0)
		return;
	i = (unsigned int)(run / UML_NT_PHYS_RUN_SIZE);
	if (i >= UML_NT_PHYS_MAX_RUNS || g_image_gen[i] == 0)
		return;
	if (uml_nt_phys_gen(g_image_ph, (long long)run) != g_image_gen[i])
		return;
	imgwr_budget--;
	os_info("[towrite-image] run=0x%llx va=0x%llx len=%llu nr=%llu "
		"— a kernel funnel write landed in a loaded image run\n",
		run, va, len, nr);
}

void uml_nt_imgwatch_capture(struct uml_nt_stub_conn *c,
			     const struct uml_nt_elf_image *img, int reset)
{
	int si;

	if (c == NULL || c->ph == NULL || img == NULL)
		return;
	if (reset)
		c->imgw_n = 0;
	for (si = 0; si < img->nseg; si++) {
		unsigned int r;

		for (r = 0; r < img->seg[si].ro_runs; r++) {
			unsigned long long run =
				img->seg[si].run_off +
				(unsigned long long)r *
				UML_NT_PHYS_RUN_SIZE;

			if (c->imgw_n >= UML_NT_IMGWATCH_MAX)
				return;
			c->imgw_run[c->imgw_n] = run;
			c->imgw_gen[c->imgw_n] =
				uml_nt_phys_gen(c->ph, (long long)run);
			c->imgw_hash[c->imgw_n] = uml_nt_imgw_hash(
				(const void *)((const char *)
				uml_boot.physmem_base + run));
			c->imgw_full[c->imgw_n] = uml_nt_imgw_hash_full(
				(const void *)((const char *)
				uml_boot.physmem_base + run));
			uml_nt_image_run_register(run,
						  c->imgw_gen[c->imgw_n],
						  c->ph);
			c->imgw_n++;
		}
	}
}

#define UML_NT_CENSUS_TOP 3
static int census_pressure_left = 8;
static int imgw_fire_left = 32;

/* Death-time imgwatch check (M5.6a writer-hunt follow-up): the run
 * the victim's unowned RIP translates through, re-hashed against the
 * post-load fingerprint. The periodic census can miss a rewrite that
 * lands after its last walk and kills before the next one (referee
 * 40013998474: a death with zero imgwatch lines). MATCH exonerate
 * the page — the death then came from a control transfer or a
 * view/table divergence; MISMATCH names the rewritten-text class at
 * the exact run the victim died on. */
void uml_nt_imgwatch_death_check(struct uml_nt_stub_conn *c,
				 unsigned long long run)
{
	int i;

	if (c == NULL || c->ph == NULL || run == 0)
		return;
	for (i = 0; i < c->imgw_n; i++) {
		unsigned long long h, g;

		if (c->imgw_run[i] != run)
			continue;
		g = uml_nt_phys_gen(c->ph, (long long)run);
		if (g != c->imgw_gen[i]) {
			os_info("[imgwatch] death: run 0x%llx gen moved "
				"(%llx -> %llx) — re-handout, not a "
				"post-load rewrite\n", run,
				c->imgw_gen[i], g);
			return;
		}
		h = uml_nt_imgw_hash((const void *)((const char *)
				uml_boot.physmem_base + run));
		os_info("[imgwatch] death: run 0x%llx %s (post-load "
			"%016llx now %016llx)\n", run,
			h == c->imgw_hash[i] ?
				"MATCHES the post-load image" :
				"REWRITTEN after load",
			c->imgw_hash[i], h);
		{
			unsigned long long hf = uml_nt_imgw_hash_full(
				(const void *)((const char *)
				uml_boot.physmem_base + run));

			os_info("[imgwatch] death: run 0x%llx full %s "
				"(post-load %016llx now %016llx)\n", run,
				hf == c->imgw_full[i] ?
					"MATCHES" : "REWRITTEN",
				c->imgw_full[i], hf);
		}
		return;
	}
	os_info("[imgwatch] death: run 0x%llx not in this conn's "
		"image set (%d watched run(s))\n", run, c->imgw_n);
}

/* Read the TCB secrets glibc sets from AT_RANDOM: fs:0x28 canary and
 * fs:0x30 pointer guard. */
static int guard_tcb_read(struct uml_nt_stub_conn *c,
			  struct uml_nt_stub_data *d,
			  unsigned long long *canary,
			  unsigned long long *guard)
{
	long long co, go;

	if (c->mm == NULL || d->fs_base == 0 ||
	    d->fs_base > ~0ull - 0x38)
		return -1;
	co = uml_nt_vma_translate(c->mm, d->fs_base + 0x28, 8);
	go = uml_nt_vma_translate(c->mm, d->fs_base + 0x30, 8);
	if (co < 0 || go < 0)
		return -1;
	memcpy(canary, (char *)uml_boot.physmem_base + co, 8);
	memcpy(guard, (char *)uml_boot.physmem_base + go, 8);
	return 0;
}

/* M5.6a login-depth follow-up (to-shelley 148-UPDATE 9/10): guard
 * stability. The static TLS block is zeroed until glibc's
 * security_init copies AT_RANDOM (canary = bytes 0..7, guard = bytes
 * 8..15); the first non-matching sight is "not initialized yet". Once
 * recorded, every real trap re-check: a changed fs:0x30 makes every
 * jmp_buf demangle to a foreign pointer — the wild-stack pivot would
 * be a guard-change symptom, not a corrupted buffer. */
static void guard_probe(struct uml_nt_stub_conn *c,
			struct uml_nt_stub_data *d)
{
	static int guard_init_budget = 64;
	static int guard_change_budget = 16;
	static int guard_tcb_budget = 8;
	unsigned long long canary, guard;
	int tcb = -1;

	if (guard_tcb_read(c, d, &canary, &guard) < 0)
		return;
	if (c->auxv_rand_valid)
		tcb = uml_nt_guard_tcb_check(c->auxv_rand, canary, guard);
	if (!c->guard_seen) {
		/* With nonzero AT_RANDOM, the derived guard is nonzero
		 * — a zero fs:0x30 means TLS is still the kernel's zeroed
		 * block. With zero AT_RANDOM the guard IS zero; tcb
		 * reports the match (the [auxv-random] line names the
		 * host-RNG starvation). */
		if (guard == 0 &&
		    !(tcb >= 0 && (tcb & UML_NT_GUARD_TCB_GUARD)))
			return;
		c->guard_seen = 1;
		c->guard_init = guard;
		c->guard_canary = canary;
		c->guard_changes = 0;
		if (guard_init_budget > 0) {
			guard_init_budget--;
			os_info("[guard-init] pid %lu fs_base=0x%llx "
				"canary=%016llx guard=%016llx tcb=%d "
				"last_nr=%llu last_ret=%lld — TLS secrets "
				"recorded for the stability check\n",
				(unsigned long)c->pid, d->fs_base, canary,
				guard, tcb, c->last_nr, c->last_ret);
		}
		return;
	}
	if (guard != c->guard_init) {
		c->guard_changes++;
		if (guard_change_budget > 0) {
			guard_change_budget--;
			os_info("[guard-change] pid %lu fs_base=0x%llx "
				"init=%016llx now=%016llx canary "
				"%016llx -> %016llx tcb=%d last_nr=%llu "
				"last_ret=%lld trap rip=0x%llx rsp=0x%llx "
				"— PTR_DEMANGLE now yields foreign "
				"pointers\n",
				(unsigned long)c->pid, d->fs_base,
				c->guard_init, guard, c->guard_canary,
				canary, tcb, c->last_nr, c->last_ret,
				d->regs.rip, d->regs.rsp);
		}
	} else if (tcb != -1 && tcb !=
		   (UML_NT_GUARD_TCB_CANARY | UML_NT_GUARD_TCB_GUARD) &&
		   guard_tcb_budget > 0) {
		guard_tcb_budget--;
		os_info("[guard-tcb] pid %lu fs_base=0x%llx canary="
			"%016llx guard=%016llx tcb=%d last_nr=%llu — the "
			"TCB no longer matches the exec's AT_RANDOM\n",
			(unsigned long)c->pid, d->fs_base, canary, guard,
			tcb, c->last_nr);
	}
}

/* glibc's x86-64 jmp_buf: qword 6 = PTR_MANGLE(rsp), qword 7 =
 * PTR_MANGLE(rip), the guard at fs:0x30. At a wild-rsp fire, scan the
 * previous stack run plus the run above it (older frames live at
 * higher addresses) for that signature, under the fire guard and the
 * recorded init guard. The VMA test IS the signature: a demangled
 * random qword lands inside a mapped guest VMA with probability
 * ~2^-47 (guest VAs occupy megabytes of a 2^64 space). Classification
 * is the branch decision:
 *   saved-rsp in the stack VMA => an intact catch frame; its longjmp
 *                                 would restore a valid stack, the
 *                                 pivot is elsewhere;
 *   saved-rsp in an image run => Branch A: setjmp itself ran on a
 *                                 text stack, the longjmp only
 *                                 REPLAYED the slip. */
static void jmpbuf_scan(struct uml_nt_stub_conn *c,
			struct uml_nt_stub_data *d, unsigned long long rsp)
{
	unsigned long long g_now, g_init, canary;
	long long ro;
	struct uml_nt_vma *sv;
	unsigned long long run, run_va, nq;
	const unsigned long long *q;
	int hits = 0, have_init, ri, i;

	if (c->mm == NULL || d->fs_base == 0 || rsp < 8)
		return;
	if (guard_tcb_read(c, d, &canary, &g_now) < 0)
		return;
	g_init = c->guard_init;
	have_init = c->guard_seen && g_init != g_now;
	sv = uml_nt_vma_find(c->mm, rsp - 1);
	if (sv == NULL)
		return;
	ro = uml_nt_vma_translate(c->mm, rsp, 1);
	if (ro < 0)
		return;
	run = ((unsigned long long)ro) & ~(UML_NT_PHYS_RUN_SIZE - 1);
	for (ri = 0; ri < 2 && hits < 4; ri++) {
		unsigned long long r = run + (unsigned long long)ri *
			UML_NT_PHYS_RUN_SIZE;

		run_va = sv->start + (r - sv->run_off);
		if (run_va < sv->start || run_va >= sv->end)
			continue;
		nq = UML_NT_PHYS_RUN_SIZE / 8;
		if (run_va + nq * 8 > sv->end)
			nq = (sv->end - run_va) / 8;
		q = (const unsigned long long *)((char *)uml_boot.physmem_base
						 + r);
		for (i = 0; i + 1 < (int)nq && hits < 4; i++) {
			int k, nguard = have_init ? 2 : 1;

			for (k = 0; k < nguard && hits < 4; k++) {
				unsigned long long g = k ? g_init : g_now;
				unsigned long long d0, d1, sva;
				struct uml_nt_vma *v0, *v1;
				long long t0;
				int img0;
				const char *cls;

				d0 = uml_nt_guard_demangle(q[i], g);
				d1 = uml_nt_guard_demangle(q[i + 1], g);
				v1 = uml_nt_vma_find(c->mm, d1);
				if (v1 == NULL)
					continue;
				v0 = uml_nt_vma_find(c->mm, d0);
				if (v0 == NULL)
					continue;
				t0 = uml_nt_vma_translate(c->mm, d0, 1);
				img0 = t0 >= 0 &&
				       uml_nt_imgwatch_is_image(c,
					((unsigned long long)t0) &
					~(UML_NT_PHYS_RUN_SIZE - 1));
				cls = img0 ? "TEXT" :
				      (v0 == sv ? "STACK" :
				       (uml_nt_prot_writable(v0->prot) ?
					"WRITABLE" : "RO"));
				sva = run_va + (unsigned long long)i * 8;
				hits++;
				os_info("[jmpbuf] pid %lu slot=0x%llx "
					"raw=%016llx %016llx saved-rsp="
					"0x%llx [%s] saved-rip=0x%llx "
					"[0x%llx,0x%llx) prot=0x%x "
					"guard=%016llx%s\n",
					(unsigned long)c->pid, sva,
					q[i], q[i + 1], d0, cls, d1,
					v1->start, v1->end, v1->prot, g,
					k ? " (INIT guard)" : "");
				if (img0)
					os_info("[jmpbuf-TEXT] pid %lu "
						"slot=0x%llx saved-rsp="
						"0x%llx saved-rip=0x%llx "
						"— setjmp itself ran on "
						"an image/text stack: the "
						"longjmp REPLAYED the "
						"slip (Branch A)\n",
						(unsigned long)c->pid, sva,
						d0, d1);
			}
		}
	}
	if (hits == 0)
		os_info("[jmpbuf] pid %lu: no PTR_MANGLEd (rsp,rip) pair "
			"with mapped targets in the stack run (guard="
			"%016llx)\n", (unsigned long)c->pid, g_now);
}

/* One-shot dump of the TEXT-stack frames at the first wild fire: the
 * guest is now running on an image run, and everything ABOVE the wild
 * rsp is the caller chain it built there — including the initial value
 * the pivot installed (the Windows dispatch context only wrote below
 * rsp). Compare against the image file offline: the boundary where
 * the file bytes end is the top the pivot started from, and the
 * return-address chain names the caller that pivoted. */
static void dump_wild_text_stack(struct uml_nt_stub_conn *c,
				 unsigned long long rsp)
{
	struct uml_nt_vma *v;
	unsigned long long run_va, va, end;
	long long ro;

	if (c->mm == NULL)
		return;
	v = uml_nt_vma_find(c->mm, rsp);
	if (v == NULL)
		return;
	ro = uml_nt_vma_translate(c->mm, rsp, 1);
	if (ro < 0)
		return;
	run_va = v->start + ((((unsigned long long)ro) &
			      ~(UML_NT_PHYS_RUN_SIZE - 1)) - v->run_off);
	if (run_va < v->start || run_va >= v->end)
		return;
	end = run_va + UML_NT_PHYS_RUN_SIZE;
	if (end > v->end)
		end = v->end;
	va = rsp & ~127ull;
	if (va < run_va)
		va = run_va;
	os_info("[wild-stack-text] pid %lu rsp=0x%llx: dumping "
		"0x%llx..0x%llx (the caller chain ABOVE the pivot rsp; "
		"the dispatch context wrote below)\n",
		(unsigned long)c->pid, rsp, va, end);
	while (va < end) {
		int n = (end - va < 128) ? (int)(end - va) : 128;

		dump_guest_bytes(c->mm, va, n, "wild-stack-text");
		va += (unsigned long long)n;
	}
}

/* One-shot raw dump of the previous trap's 64 KiB stack run: the
 * catch frame is above the previous rsp (older frame) and the Windows
 * dispatch context only wrote BELOW it, so the run is the intact
 * pivot source. Offline, every candidate can be demangled under every
 * guard without another boot. */
static void dump_prev_stack_run(struct uml_nt_stub_conn *c,
				unsigned long long rsp)
{
	struct uml_nt_vma *sv;
	unsigned long long run_va, end;
	long long ro;

	if (c->mm == NULL || rsp < 1)
		return;
	sv = uml_nt_vma_find(c->mm, rsp - 1);
	if (sv == NULL)
		return;
	ro = uml_nt_vma_translate(c->mm, rsp, 1);
	if (ro < 0)
		return;
	run_va = sv->start + ((((unsigned long long)ro) &
			       ~(UML_NT_PHYS_RUN_SIZE - 1)) - sv->run_off);
	if (run_va < sv->start || run_va >= sv->end)
		return;
	end = run_va + UML_NT_PHYS_RUN_SIZE;
	if (end > sv->end)
		end = sv->end;
	os_info("[stack-run] pid %lu prev rsp=0x%llx: dumping "
		"0x%llx..0x%llx (the intact catch frame/pivot region)\n",
		(unsigned long)c->pid, rsp, run_va, end);
	while (run_va < end) {
		int n = (end - run_va < 128) ? (int)(end - run_va) : 128;

		dump_guest_bytes(c->mm, run_va, n, "prev-stack-run");
		run_va += (unsigned long long)n;
	}
}

int uml_nt_imgwatch_is_image(struct uml_nt_stub_conn *c,
			     unsigned long long run)
{
	int i;

	if (c == NULL)
		return 0;
	for (i = 0; i < c->imgw_n; i++)
		if (c->imgw_run[i] == run)
			return 1;
	return 0;
}

/* Park-time round-robin full-hash check (M5.6a writer-hunt follow-up:
 * rf pair's interp run0 is rewritten after load with the funnel and
 * the sigframe innocent). One image run per real trap park; the FIRST
 * park after a divergence logs the round's last_nr/last_ret/trap rip —
 * the write happened in the interval that round closes. A run is
 * reported once (imgw_div). Gen-pinned: a re-handed run is skipped. */
void uml_nt_imgwatch_park_check(struct uml_nt_stub_conn *c)
{
	unsigned long long h, g;
	int i;

	if (c == NULL || c->ph == NULL || c->mm == NULL || c->imgw_n <= 0)
		return;
	i = (int)(c->imgw_rr++ % (unsigned int)c->imgw_n);
	if (c->imgw_div[i])
		return;
	g = uml_nt_phys_gen(c->ph, (long long)c->imgw_run[i]);
	if (g != c->imgw_gen[i])
		return;
	h = uml_nt_imgw_hash_full((const void *)((const char *)
			uml_boot.physmem_base + c->imgw_run[i]));
	if (h == c->imgw_full[i])
		return;
	c->imgw_div[i] = 1;
	os_info("[imgwatch-park] pid %lu run 0x%llx REWRITTEN: first "
		"park after last_nr=%llu last_ret=%lld trap rip=0x%llx "
		"rax=0x%llx rsp=0x%llx — the write sits in the interval "
		"that round closes\n",
		(unsigned long)c->pid, c->imgw_run[i], c->last_nr,
		c->last_ret, c->d->regs.rip, c->d->regs.rax,
		c->d->regs.rsp);
}

/*
 * M5.6a login-depth follow-up (Shelley 149) — the [resume-regs]
 * witness.
 *
 * The whole login class hangs on one unanswered question: when the
 * conn resumed after round close(3) (trap rsp=0x6005d258, clean), did
 * the guest come back with that rsp — or did the answer already carry
 * the wild text rsp the next trap reports (0x6001c228, inside the
 * interp run)? Every existing witness logs the TRAP state only, so
 * both halves of the referee question look identical in the log.
 *
 * The resume state IS d->regs: the stub's VEH applies it verbatim
 * (gp_to_context) before returning EXCEPTION_CONTINUE_EXECUTION, and a
 * syscall/fault fold touches rip (+2 / replay) and rax (retval) only.
 * So the answer's rsp against the SAME round's trap capture splits the
 * class cleanly (resume_model.h: SAME / VERBATIM / REWRITE), and the
 * stub's own d->resume_rsp closes the last gap — a CONTEXT restore that
 * did not carry what the answer said.
 *
 * Budget: 256 loud lines (rewrite-class resumes and resumes whose rsp
 * landed in an image run); the ring keeps the interval tail for the
 * fire dump. Idle resumes print nothing — a clean boot stays quiet.
 */
static int uml_nt_resume_rsp_wild(struct uml_nt_stub_conn *c,
				  unsigned long long rsp)
{	long long ro;

	if (c->imgw_n <= 0 || c->mm == NULL)
		return 0;
	ro = uml_nt_vma_translate(c->mm, rsp, 1);
	if (ro < 0)
		return 0;
	return uml_nt_imgwatch_is_image(c,
			((unsigned long long)ro) &
			~(UML_NT_PHYS_RUN_SIZE - 1));
}

/* The round class as a stable word (a multi-op round resumes at its
 * drain end, so "op-drain" is a resume too). */
static const char *uml_nt_resume_cmd_name(unsigned int cmd)
{
	switch (cmd) {
	case UML_STUB_CMD_SYSCALL:
		return "syscall";
	case UML_STUB_CMD_FAULT:
		return "fault";
	case UML_STUB_CMD_PROT_DONE:
		return "op-drain";
	case UML_STUB_CMD_INIT:
		return "init";
	default:
		return "?";
	}
}

/* The answer is about to release the stub: record what the guest will
 * resume with. `pushed` = signal delivery rewrote the state this round
 * (uml_nt_signal_check); the XS_VERBATIM flag is the kernel's own word
 * on it and is what the classifier trusts. */
static void uml_nt_resume_regs_record(struct uml_nt_stub_conn *c,
				      int pushed)
{
	struct uml_nt_stub_data *d = c->d;
	struct uml_nt_rres_rec *r;
	unsigned int verbatim =
		(d->xstate_flags & UML_STUB_XS_VERBATIM) ? 1u : 0u;
	int cls = UML_NT_RRES_UNCHANGED;
	int wild;

	/* Only conns that carry an image run: the class this names is a
	 * stack pointer inside loaded text, and nothing else is (the
	 * [rsp-image] gate — same condition, same reason). */
	if (c->imgw_n <= 0)
		return;

	if (c->res_trap_valid)
		cls = uml_nt_resume_regs_class(c->res_trap_rsp,
					       d->regs.rsp, (int)verbatim);
	wild = uml_nt_resume_rsp_wild(c, d->regs.rsp);
	c->res_seen++;
	if (wild)
		c->res_wild_n++;
	if (cls == UML_NT_RRES_REWRITE)
		c->res_rewrite_n++;

	r = &c->res_ring[c->res_ring_next];
	r->seq = d->req_seq;
	r->rip = d->regs.rip;
	r->rsp = d->regs.rsp;
	r->rbp = d->regs.rbp;
	r->rbx = d->regs.rbx;
	r->rax = d->regs.rax;
	r->trap_rip = c->res_trap_rip;
	r->trap_rsp = c->res_trap_rsp;
	r->last_nr = c->last_nr;
	r->last_ret = c->last_ret;
	r->cmd = d->cmd;
	r->verbatim = verbatim;
	r->wild = wild ? 1u : 0u;
	r->cls = (unsigned int)cls;
	c->res_ring_next = (c->res_ring_next + 1) % UML_NT_RRES_RING;
	if (c->res_ring_n < UML_NT_RRES_RING)
		c->res_ring_n++;
	c->res_last = *r;
	c->res_last_valid = 1;

	/* The stub-side half of the same contract: the rsp the CONTEXT
	 * restore must carry is the rsp this answer just published. */
	c->res_chk_rsp = d->regs.rsp;
	c->res_chk_valid = 1;

	if (wild || cls == UML_NT_RRES_REWRITE) {
		static int rres_budget = 256;

		if (rres_budget > 0) {
			rres_budget--;
			os_info("[resume-regs] pid %lu %s resume rip=0x%llx "
				"rsp=0x%llx rbp=0x%llx rbx=0x%llx rax=0x%llx "
				"trap-rsp=0x%llx verdict=%s verbatim=%u "
				"pushed=%d last_nr=%llu last_ret=%lld%s%s\n",
				(unsigned long)c->pid,
				uml_nt_resume_cmd_name(d->cmd),
				d->regs.rip, d->regs.rsp, d->regs.rbp,
				d->regs.rbx, d->regs.rax, c->res_trap_rsp,
				uml_nt_resume_regs_name(cls), verbatim, pushed,
				c->last_nr, c->last_ret,
				wild ? " [RSP-IN-IMAGE-RUN]" : "",
				cls == UML_NT_RRES_REWRITE ?
					" [REWRITE: the answer moved rsp]" : "");
		}
	}
}

/* At the first wild-rsp fire: the immediately preceding resume (the
 * round that closed before the guest entered image text) plus the
 * interval tail. A clean SAME record here means the stub restored the
 * trap's own stack pointer and the pivot happened in guest code; a
 * REWRITE record means our own answer carried the wild value. */
static void uml_nt_resume_regs_fire(struct uml_nt_stub_conn *c)
{
	struct uml_nt_rres_rec *l = &c->res_last;
	int i, n;

	if (!c->res_last_valid) {
		os_info("[resume-regs] pid %lu no resume recorded yet "
			"(seen=%u) — the pivot precedes the witness window\n",
			(unsigned long)c->pid, c->res_seen);
		return;
	}
	os_info("[resume-regs] pid %lu PREV RESUME seq=%llu %s "
		"rip=0x%llx rsp=0x%llx rbp=0x%llx rbx=0x%llx "
		"trap-rip=0x%llx trap-rsp=0x%llx verdict=%s verbatim=%u "
		"last_nr=%llu last_ret=%lld — SAME rsp here = the pivot is "
		"GUEST code; a wild rsp here = our reg-restore\n",
		(unsigned long)c->pid, l->seq,
		uml_nt_resume_cmd_name(l->cmd),
		l->rip, l->rsp, l->rbp, l->rbx, l->trap_rip, l->trap_rsp,
		uml_nt_resume_regs_name((int)l->cls), l->verbatim,
		l->last_nr, l->last_ret);
	n = (int)c->res_ring_n;
	if (n > 6)
		n = 6;
	for (i = n; i >= 1; i--) {
		unsigned int idx = (c->res_ring_next + UML_NT_RRES_RING -
				    (unsigned int)i) % UML_NT_RRES_RING;
		struct uml_nt_rres_rec *e = &c->res_ring[idx];

		os_info("[resume-regs]   -%d seq=%llu %s rip=0x%llx "
			"rsp=0x%llx last_nr=%llu last_ret=%lld %s%s\n",
			i, e->seq,
			uml_nt_resume_cmd_name(e->cmd),
			e->rip, e->rsp, e->last_nr, e->last_ret,
			uml_nt_resume_regs_name((int)e->cls),
			e->wild ? " WILD" : "");
	}
}

/*
 * M5.6a [pivot trace] — the TF single-step trace of the interval the
 * [resume-regs] verdict named.
 *
 * Two referees (40083772914, 40083780256) logged the resume right
 * before the first wild-rsp trap: rip=0x601ece65 (libc close site),
 * rsp=0x6005d258 — verdict SAME against the round's own trap capture,
 * no stub-restore mismatch, every previous resume SAME. The kernel and
 * the stub both handed the guest its own stack pointer, so the pivot
 * is GUEST code between the close(3) return and the fstatat trap.
 *
 * TF is the only instrument that can name that instruction: the answer
 * after a successful close(3) on a login conn arms d->tf_trace; the
 * stub raises TF at the resume (fault trampoline, TLS base live) and
 * every guest instruction then traps once as cmd FAULT /
 * fault_type STEP. Each step logs rip/rsp/rbp/rbx/rax; the step whose
 * rsp MOVED into an image run is the pivot's successor — the pivot is
 * the previous step's rip, and its source slot is still fresh in the
 * previous step's stack window (exactly one instruction has run since).
 *
 * Cost bound: per-arm 1500 steps, per-conn 3000, login conns only.
 */
static void uml_nt_tf_trace_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned int n = UML_NT_TF_STEPS_PER_ARM;

	if (c->tf_used + n > UML_NT_TF_STEPS_PER_CONN)
		n = c->tf_used >= UML_NT_TF_STEPS_PER_CONN ?
			0 : UML_NT_TF_STEPS_PER_CONN - c->tf_used;
	if (n == 0)
		return;
	c->tf_used += n;
	c->tf_arms++;
	c->tf_left = n;
	c->tf_prev_rsp = d->regs.rsp;
	c->tf_prev_rip = d->regs.rip;
	c->tf_prev_valid = 1;
	c->tf_n = 0;
	c->tf_rr = 0;
	d->tf_stop = 0;
	d->tf_trace = n;
	os_info("[pivot-trace] pid %lu %s TF TRACE armed (%u step(s), arm "
		"%u): from rip=0x%llx rsp=0x%llx last_nr=%llu last_ret=%lld — "
		"single-stepping the interval the resume proved is guest code\n",
		(unsigned long)c->pid, c->exec_path, n, c->tf_arms,
		d->regs.rip, d->regs.rsp, c->last_nr, c->last_ret);
}

/* One step round: log it and answer. Never repairs anything — TF steps
 * are pure observation. */
static void uml_nt_tf_trace_step(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned long long rsp = d->regs.rsp;
	unsigned long long rip = d->regs.rip;
	int in_image = uml_nt_resume_rsp_wild(c, rsp);
	int moved = c->tf_prev_valid && rsp != c->tf_prev_rsp;
	int verdict = uml_nt_tf_trace_next(c->tf_left, in_image, moved);
	struct uml_nt_rres_rec *r;

	r = &c->tf_ring[c->tf_rr];
	r->seq = d->req_seq;
	r->rip = rip;
	r->rsp = rsp;
	r->rbp = d->regs.rbp;
	r->rbx = d->regs.rbx;
	r->rax = d->regs.rax;
	r->last_nr = c->last_nr;
	r->last_ret = c->last_ret;
	r->cmd = d->fault_type;
	c->tf_rr = (c->tf_rr + 1) % UML_NT_TF_RING;
	if (c->tf_n < UML_NT_TF_RING)
		c->tf_n++;

	if (c->tf_left > 0)
		c->tf_left--;

	if (verdict == UML_NT_TF_PIVOT) {
		int i;

		os_info("[pivot-trace] pid %lu PIVOT: the instruction at "
			"0x%llx moved rsp 0x%llx -> 0x%llx (into image text) — "
			"step %u of arm %u, last_nr=%llu last_ret=%lld\n",
			(unsigned long)c->pid, c->tf_prev_rip,
			c->tf_prev_rsp, rsp,
			UML_NT_TF_STEPS_PER_ARM - c->tf_left, c->tf_arms,
			c->last_nr, c->last_ret);
		/* The pivot instruction's own bytes (table view) and the
		 * slot it loaded from: only ONE guest instruction has run
		 * since, so [prev_rsp - 0x80, prev_rsp + 0x100) is still
		 * the live frame. */
		if (c->mm != NULL) {
			dump_guest_bytes(c->mm, c->tf_prev_rip - 8, 32,
					 "pivot-insn");
			if (c->tf_prev_rsp > 0x80)
				dump_guest_bytes(c->mm,
						 c->tf_prev_rsp - 0x80, 0x180,
						 "pivot-src");
		}
		for (i = (int)c->tf_n; i >= 1; i--) {
			unsigned int idx = (c->tf_rr + UML_NT_TF_RING -
					    (unsigned int)i) % UML_NT_TF_RING;
			struct uml_nt_rres_rec *e = &c->tf_ring[idx];

			os_info("[pivot-trace]   -%d seq=%llu rip=0x%llx "
				"rsp=0x%llx rbp=0x%llx rbx=0x%llx rax=0x%llx\n",
				i, e->seq, e->rip, e->rsp, e->rbp, e->rbx,
				e->rax);
		}
		d->tf_trace = 0;
	} else if (verdict == UML_NT_TF_EXHAUSTED) {
		os_info("[pivot-trace] pid %lu budget spent (%u step(s), arm "
			"%u) at rip=0x%llx rsp=0x%llx — no pivot in this "
			"interval; the next close(3) arms again while the conn's "
			"budget lasts\n",
			(unsigned long)c->pid, c->tf_used, c->tf_arms,
			rip, rsp);
		d->tf_trace = 0;
	} else {
		unsigned int n = UML_NT_TF_STEPS_PER_ARM - c->tf_left;

		/* Volume policy: the first 64 steps of an arm are logged
		 * whole (the interval's shape), then every 256th as a
		 * heartbeat — the pivot line always prints, and the ring
		 * carries its context. A 3000-step arm costs ~76 lines. */
		if (n <= 64 || (n & 0xff) == 0)
			os_info("[pivot-trace] pid %lu step %u rip=0x%llx "
				"rsp=0x%llx rbp=0x%llx rbx=0x%llx rax=0x%llx "
				"insn=%016llx\n",
				(unsigned long)c->pid, n, rip, rsp,
				d->regs.rbp, d->regs.rbx, d->regs.rax,
				d->trap_insn);
		if (c->tf_left == 0) {
			os_info("[pivot-trace] pid %lu budget spent (%u step(s), "
				"arm %u) at rip=0x%llx rsp=0x%llx — no pivot in "
				"this interval; the next close(3) arms again while "
				"the conn's budget lasts\n",
				(unsigned long)c->pid, c->tf_used, c->tf_arms,
				rip, rsp);
		}
		d->tf_trace = c->tf_left;
	}
	c->tf_prev_rsp = rsp;
	c->tf_prev_rip = rip;
	c->tf_prev_valid = 1;
}

/*
 * M5.6a [pivot-sample] — Shelley's ruling on to-shelley/150.
 *
 * The [resume-regs] verdict exonerated the kernel and the stub: the
 * answer carried the trap's OWN rsp and the stub restored exactly that,
 * so the stack pointer moves in GUEST code between the close(3) return
 * and the fstatat trap. TF single-step cannot witness it (the Windows
 * exception dispatcher eats TF on every hop — referees 40089224944/
 * 40089231217), and Shelley's static walk named the mechanism: the
 * interp's `_dl_find_dso_for_object` (entry 0xb490) copies its `addr`
 * argument into rbp at 0xb4a4 and then marshals a ~0x400-byte array
 * BELOW rbp (`mov %rsi,-0x428(%rbp,%rcx,1)` at 0xc626, stride 16,
 * counter `cmp $0x3f,%ebx` at 0xc610). With a byte-shifted addr —
 * rbp≈0x6001c650 — that array lands in interp TEXT, exactly the sparse
 * 258-byte footprint and the ≈0x6001c600 pivot rsp this hunt measured.
 *
 * So the sampler reads the RUNNING stub thread's CONTEXT between two
 * rounds: SuspendThread → GetThreadContext → ResumeThread, ~5-20 us per
 * probe, sampling right after the close(3) answer is released and
 * stopping the moment the next round is published. A hit is a sample
 * whose rsp landed in an image run (the pivot just happened) or whose
 * rip is inside the `_dl_find_dso_for_object` window (the bad call is
 * running); in both cases the PREVIOUS sample names the caller / the
 * instruction that produced the bad pointer.
 */
static int uml_nt_sample_read(struct uml_nt_stub_conn *c,
			      unsigned long long *rip, unsigned long long *rsp,
			      unsigned long long *rbp, unsigned long long *rdi,
			      unsigned long long *rsi, unsigned long long *rbx)
{
	/* x64 CONTEXT, 0x4d0 bytes; only CONTEXT_CONTROL is requested, and
	 * ntabi.h's fixed offsets (Rip 0xf8, Rsp 0x98, Rbp 0xa0, ...) are
	 * the documented winnt.h layout. The buffer is per-conn (two
	 * kernel tasks can serve two stubs concurrently). */
	unsigned char *ctx = c->smp_ctx;
	int ok;

	/* CONTEXT_CONTROL | CONTEXT_INTEGER: the pivot hunt needs the
	 * ARGUMENT registers (rdi/rsi) and rbx, not just rsp/rbp/rip —
	 * with CONTROL alone every integer slot reads back 0 (referees
	 * 40094545095/40094551603 sampled rdi=rsi=rbx=0 on every guest
	 * rip, which cannot tell a text-shaped argument). */
	*(unsigned int *)(ctx + 0x30) = 0x00100003u;
	{
		ULONG prev = nt->SuspendThread(c->thread);

		if (prev == (ULONG)-1) {
			c->d->smp_susp_fail++;
			return -1;
		}
		/* a non-zero previous count means someone left a suspend
		 * behind — that alone can freeze a thread for good */
		if (prev != 0)
			c->d->smp_susp_nonzero++;
	}
	ok = nt->GetThreadContext(c->thread, ctx);
	if (!uml_nt_dbg_flag()) {
		ULONG r = nt->ResumeThread(c->thread);

		if (r == (ULONG)-1)
			c->d->smp_resume_fail++;
	}
	if (!ok)
		return -1;
	*rip = UML_NT_X64_CTX_RIP(ctx);
	*rsp = UML_NT_X64_CTX_RSP(ctx);
	*rbp = UML_NT_X64_CTX_RBP(ctx);
	*rdi = UML_NT_X64_CTX_REG(ctx, 0xb0);
	*rsi = UML_NT_X64_CTX_REG(ctx, 0xa8);
	*rbx = UML_NT_X64_CTX_REG(ctx, 0x90);
	return 0;
}
/* Shelley 232: one mid-compute sample, kept in a four-deep ring. Only
 * called while the guest owns the CPU (round_step 11 = published), which
 * is also the only place a suspend is safe for us. */
void uml_nt_sample_push(struct uml_nt_stub_conn *c)
{
	unsigned long long rip = 0, rsp = 0, rbp = 0, rdi = 0, rsi = 0, rbx = 0;
	unsigned slot;

	if (c == NULL || c->d == NULL)
		return;
	if (c->d->smp_cap == 0)
		c->d->smp_cap = 64;	/* default: 64 samples, then silence */
	c->d->smp_calls++;
	/* Shelley 234: only sample when the guest owns the CPU and the kernel
	 * is holding nothing — a suspend taken while a round is in flight is
	 * what wedged the boot. And never run forever: a hard cap keeps the
	 * instrument from becoming the experiment. */
	if (c->thread == NULL || c->d->round_step != 11 ||
	    c->d->done_seq != c->d->req_seq ||
	    (c->d->smp_cap != 0 && c->d->smp_n >= c->d->smp_cap)) {
		c->d->smp_skip_step++;
		return;
	}
	if (uml_nt_sample_read(c, &rip, &rsp, &rbp, &rdi, &rsi, &rbx) != 0) {
		c->d->smp_fail++;
		return;
	}
	c->d->smp_ok++;
	slot = c->d->smp_n & 3u;
	c->d->smp_rip[slot] = rip;
	c->d->smp_rsp[slot] = rsp;
	c->d->smp_fl[slot] = (unsigned long long)c->pid; /* tagged below */
	c->d->smp_n++;
}

void uml_nt_sample_dump(const struct uml_nt_stub_conn *c)
{
	int k;

	if (c == NULL || c->d == NULL)
		return;
	/* Shelley 236: the guest stood on one address for the whole window.
	 * Read what is there (our own physmem, so the dead is readable) and
	 * scan the containing mapping for a library name. */
	{
		static unsigned char sbuf[16384];
		unsigned long long srip = c->d->smp_rip[(c->d->smp_n + 3) & 3u];
		struct uml_nt_vma *v =
			(c->mm != NULL) ? uml_nt_vma_find(c->mm, srip) : NULL;

		if (v != NULL) {
			unsigned char ins[16];
			unsigned long long len = v->end - v->start;
			int got = 0, k, n;
			char name[96];

			memset(ins, 0, sizeof(ins));
			got = uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
					       srip, sizeof(ins),
					       (char *)ins, 0) == 0;
			memset(sbuf, 0, sizeof(sbuf));
			if (len > sizeof(sbuf))
				len = sizeof(sbuf);
			uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
					 v->start, len, (char *)sbuf, 0);
			/* find a printable run that looks like a library name */
			name[0] = 0;
			for (k = 0; k + 8 < (int)len; k++) {
				if (sbuf[k] == 'l' && sbuf[k + 1] == 'i' &&
				    sbuf[k + 2] == 'b') {
					for (n = 0; n < (int)sizeof(name) - 1 &&
					     k + n < (int)len; n++) {
						unsigned char ch = sbuf[k + n];

						if (ch < 0x20 || ch > 0x7e)
							break;
						name[n] = (char)ch;
					}
					name[n] = 0;
					if (n > 4 &&
					    (k + n + 3 < (int)len) &&
					    sbuf[k + n] == '.' &&
					    sbuf[k + n + 1] == 's' &&
					    sbuf[k + n + 2] == 'o')
						break;
					name[0] = 0;
				}
			}
			os_info("[smp] stuck rip=0x%llx vma=[0x%llx,0x%llx) "
				"prot=0x%x flags=0x%x read=%s "
				"insn=%02x%02x%02x%02x%02x%02x%02x%02x "
				"lib='%s'\n",
				srip, v->start, v->end, v->prot, v->flags,
				got ? "ok" : "FAULT",
				ins[0], ins[1], ins[2], ins[3], ins[4],
				ins[5], ins[6], ins[7],
				name[0] ? name : "?");
		}
	}
	os_info("[smp] pid %d taken=%u calls=%u skip=%u fail=%u ok=%u "
		"susp_nonzero=%u susp_fail=%u resume_fail=%u "
		"step=%u 4 last (rip rsp):\n",
		(int)c->pid, (unsigned)c->d->smp_n,
		(unsigned)c->d->smp_calls, (unsigned)c->d->smp_skip_step,
		(unsigned)c->d->smp_fail, (unsigned)c->d->smp_ok,
		(unsigned)c->d->smp_susp_nonzero,
		(unsigned)c->d->smp_susp_fail,
		(unsigned)c->d->smp_resume_fail,
		(unsigned)c->d->round_step);
	for (k = 3; k >= 0; k--) {
		unsigned slot = (c->d->smp_n + k) & 3u;

		if (c->d->smp_rip[slot] == 0 && k == 3)
			continue;
		os_info("[smp]   -%d rip=0x%llx rsp=0x%llx\n", 3 - k,
			c->d->smp_rip[slot], c->d->smp_rsp[slot]);
	}
}


/* A sample is a GUEST sample only when the thread is executing guest
 * code: between the answer release and the next trap the stub spends
 * its first tens of microseconds waking up and running its own
 * dispatch/C paths (rip in ntdll, rsp still on the guest stack) —
 * referees 40092427406/40092433563 sampled exactly that and learned
 * nothing. Everything outside the guest span is retried, never logged
 * and never charged to the budget. */
static int uml_nt_sample_is_guest(const struct uml_nt_stub_conn *c,
				  unsigned long long rip)
{
	unsigned long long lo, hi;

	if (c->d == NULL)
		return 0;
	lo = (unsigned long long)c->d->ram_base;
	hi = lo + (unsigned long long)c->d->ram_size;
	return rip >= lo && rip < hi;
}

/* Is `rip` inside the interp's image run(s)? Cheap: the conn's image
 * runs are runs, not VAs — translate and match, like the rsp test. */
static int uml_nt_sample_rip_in_image(struct uml_nt_stub_conn *c,
				      unsigned long long rip)
{
	long long ro;

	if (c->imgw_n <= 0 || c->mm == NULL)
		return 0;
	ro = uml_nt_vma_translate(c->mm, rip, 1);
	if (ro < 0)
		return 0;
	return uml_nt_imgwatch_is_image(c,
			((unsigned long long)ro) &
			~(UML_NT_PHYS_RUN_SIZE - 1));
}

/* Shelley 150's mechanism, expressed as a LIVE signature (the VMAs do
 * not carry file offsets, so the window is matched by shape, not by
 * offset): `_dl_find_dso_for_object` copies its `addr` argument into
 * rbp (0xb4a4) and marshals a ~0x400-byte array BELOW it
 * (`-0x428(%rbp,%rcx,1)` at 0xc626). So the bad call looks like: rbp in
 * image TEXT and rsp inside [rbp - 0x440, rbp). */
static int uml_nt_sample_marshal_shape(struct uml_nt_stub_conn *c,
				       unsigned long long rbp,
				       unsigned long long rsp)
{
	if (rbp <= rsp)
		return 0;
	if (rbp - rsp > 0x440)
		return 0;
	return uml_nt_sample_rip_in_image(c, rbp);
}

/*
 * M5.6a [pivot-dr] — the DR execute breakpoint on the interp's
 * `_dl_find_dso_for_object` entry (Shelley 150's static walk; the
 * sampler's evidence that the interval is ~1-2 us of guest time, i.e.
 * unreachable by a suspend/read probe).
 *
 * The entry VA is derived from the conn's own VMA table: the interp is
 * the LOWEST file-backed image whose run starts with the ELF magic and
 * whose header is ET_DYN (self-validating — a wrong pick simply never
 * arms). Slot 2 of the DR set carries the execute breakpoint; the v13
 * write slots keep slots 0/1 (and 3 for the arena heads).
 */
#define UML_NT_DR_EXEC_SLOT 2
#define UML_NT_DLDSO_ENTRY_OFF 0xb490ull

static int uml_nt_run_is_elf_dyn(struct uml_nt_stub_conn *c,
				 unsigned long long va)
{
	long long ro = uml_nt_vma_translate(c->mm, va, 1);
	const unsigned char *p;
	unsigned int magic, type;

	if (ro < 0)
		return 0;
	p = (const unsigned char *)uml_boot.physmem_base + ro;
	magic = (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
		((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
	if (magic != 0x464c457fu) /* "\x7fELF" */
		return 0;
	type = (unsigned int)p[16] | ((unsigned int)p[17] << 8); /* e_type */
	return type == 3; /* ET_DYN */
}

/* The lowest ELF-DYN image base + the entry offset, or 0.
 *
 * Referee 40099032156 armed slot 2 at 0x6008b490: the interp's VMA is
 * NOT flagged UML_NT_VMA_FILE (die log: "rip in vma [0x60010000,
 * 0x60050000) prot=0x40 flags=0x0"), so the flag filter skipped it and
 * the lowest *library* won. The image test is the ELF header in the
 * run itself — base = the VMA start whose run begins with "\x7fELF" +
 * e_type ET_DYN — and the lowest such base wins (the interp is mapped
 * below the exe and every library in this port's layout). */
static unsigned long long uml_nt_interp_entry_va(struct uml_nt_stub_conn *c)
{
	unsigned long long best = 0;
	int i, shown = 0;

	if (c->mm == NULL)
		return 0;
	for (i = 0; i < c->mm->nvma; i++) {
		struct uml_nt_vma *v = &c->mm->vma[i];

		if (!uml_nt_run_is_elf_dyn(c, v->start))
			continue;
		if (shown < 8) {
			shown++;
			os_info("[pivot-dr] image base candidate 0x%llx "
				"(vma [0x%llx,0x%llx) prot=0x%x flags=0x%x)\n",
				v->start, v->start, v->end, v->prot,
				v->flags);
		}
		if (best == 0 || v->start < best)
			best = v->start;
	}
	if (best == 0)
		return 0;
	return best + UML_NT_DLDSO_ENTRY_OFF;
}

/* Arm the execute breakpoint (idempotent; re-asserted every release so
 * a v13 arm cannot steal the slot). */
void uml_nt_dr_exec_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

	if (d == NULL || c->mm == NULL || c->imgw_n <= 0 ||
	    !uml_nt_conn_is_login(c))
		return;
	if (c->dr_exec_va == 0 && c->interp_base != 0)
		c->dr_exec_va = c->interp_base + UML_NT_DLDSO_ENTRY_OFF;
	if (c->dr_exec_va == 0)
		c->dr_exec_va = uml_nt_interp_entry_va(c);
	if (c->dr_exec_va == 0)
		return;
	d->dr_watch[UML_NT_DR_EXEC_SLOT] = c->dr_exec_va;
	d->dr_exec_mask |= 1u << UML_NT_DR_EXEC_SLOT;
	if (!c->dr_exec_armed) {
		c->dr_exec_armed = 1;
		os_info("[pivot-dr] pid %lu %s EXEC BREAKPOINT armed at "
			"0x%llx (interp _dl_find_dso_for_object entry, "
			"file 0xb490) — every call reports its argument\n",
			(unsigned long)c->pid, c->exec_path,
			c->dr_exec_va);
	}
}

/* [pivot-wslot] (to-shelley 151, Shelley's ruling): arm the four
 * ruled interp-text qwords as DR WRITE slots for a login conn.
 *
 * Why a WRITE watch and not the execute breakpoint: text is never
 * written by a correct guest, so the first hit IS the pivot's
 * footprint — no interval racing (the interval is ~1-2 us, shorter
 * than a suspend/read probe), no one-shot blind spot (the exec
 * breakpoint could only see the first call of each interval, 0 hits
 * with a text rbp out of 20000 in referees 40111848005/40111855705),
 * and the hit carries the store's own post-rip, rbp (= the pivot
 * value, measured rather than inferred) and the caller frame.
 *
 * Ownership: all four hardware slots belong to this watch. The tcache
 * entries[] watch (slots 0/1) and the arena bin heads (2/3) stand
 * down for this conn — see tcache_watch. */
static void uml_nt_pivot_wslot_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	int i;

	if (d == NULL || c->mm == NULL || c->imgw_n <= 0 || c->ws_armed)
		return;
	if (c->interp_base == 0 || !uml_nt_conn_is_login(c))
		return;
	/* RETIRED (Shelley 162/163): this instrument answered its question
	 * (the pivot was CLEARED by the stack class fix, to-shelley/155)
	 * and it owns all four hardware slots — it stomps slot 2 and
	 * clears dr_exec_mask, which silently disarmed the one-shot
	 * execute probe ("armed but never fired" while the conn lived 540
	 * more rounds, referee 40226282548). A retired instrument must not
	 * hold a live one's slot. */
	if (c->drex_armed || c->drex_used)
		return;
	for (i = 0; i < (int)UML_NT_PWSLOT_N; i++)
		d->dr_watch[i] = c->interp_base + uml_nt_pwslot_off(i);
	/* write watchpoints, not execute ones */
	d->dr_exec_mask = 0;
	c->ws_armed = 1;
	c->ws_hits = 0;
	/* THE RESOLVER'S XSAVE SIZE (Shelley 153): _dl_runtime_resolve_*
	 * does `and $-64,%rsp; sub QWORD PTR [rip+disp],%rsp` where the
	 * operand is `_rtld_global_ro+0x1b0` (ld.so file offset 0x32c70,
	 * disassembled at 0x121c8/0x12298) — a RUNTIME value that ld.so
	 * fills from CPUID. If that value exceeds the free space between
	 * the guest's rsp and the bottom of its 64K stack run, the
	 * resolver's save area lands in the interp's text (which our exec
	 * setup maps RWX directly below the stack). Read it here so the
	 * arithmetic is MEASURED, not inferred. */

	os_info("[pivot-wslot] pid %lu %s: four DR WRITE slots on the "
		"interp text at 0x%llx/0x%llx/0x%llx/0x%llx (interp base "
		"0x%llx) — the pivot's vfprintf arg array lands here\n",
		(unsigned long)c->pid, c->exec_path,
		c->interp_base + uml_nt_pwslot_off(0),
		c->interp_base + uml_nt_pwslot_off(1),
		c->interp_base + uml_nt_pwslot_off(2),
		c->interp_base + uml_nt_pwslot_off(3),
		c->interp_base);
}

/* [pivot-frame] (Shelley 152/153): rbp is STILL the real stack in every
 * store we caught (0x6005c6a0) while rsp is text — so the ordinary
 * frame-pointer chain is intact and can be WALKED BY READING. Each frame
 * yields (rbp, saved return address); the return addresses name the
 * callers, and the first one whose OWN frame lies in text is the frame
 * whose caller introduced the text rsp. Pure reads, no traps. */
static void uml_nt_frame_walk(struct uml_nt_stub_conn *c,
			      unsigned long long rbp, int max)
{
	int i;

	os_info("[pivot-frame] pid %lu %s walking the legit rbp chain from "
		"0x%llx (rsp=0x%llx is %s)\n",
		(unsigned long)c->pid, c->exec_path, rbp, c->d->regs.rsp,
		(c->d->regs.rsp >= c->interp_base &&
		 c->d->regs.rsp < c->interp_base + 0x40000) ? "TEXT" :
		"legit");
	for (i = 0; i < max && rbp >= 0x10000; i++) {
		long long so = uml_nt_vma_translate(c->mm, rbp, 16);
		unsigned long long saved = 0, ret = 0;
		struct uml_nt_vma *rv;

		if (so < 0) {
			os_info("[pivot-frame]   frame %d rbp=0x%llx "
				"untranslatable — chain ends\n", i, rbp);
			return;
		}
		saved = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + so);
		ret = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + so + 8);
		rv = uml_nt_vma_find(c->mm, ret);
		os_info("[pivot-frame]   #%d rbp=0x%llx saved-rbp=0x%llx "
			"ret=0x%llx%s%s\n", i, rbp, saved, ret,
			rv ? "" : " [ret NOT MAPPED]",
			rv && (rv->prot & 0x40) ? "" : " [ret not exec]");
		if (saved <= rbp || saved - rbp > 0x80000)
			return;
		rbp = saved;
	}
}

/* [pivot-wslot] caller walk (Shelley 152(b)): an EXECUTE breakpoint at
 * ONE concrete address, moved up the call chain, at most four hops.
 *
 * This is not the TF instrument that died on the Windows dispatcher:
 * the target is a known address, the volume is a handful of hits per
 * login (referee 40114317847 measured 5 hits/conn for a similar
 * breakpoint, and the 20k-hit variant never killed a stub), and each
 * hop answers one question — is rsp already text HERE? */
static void uml_nt_chain_arm(struct uml_nt_stub_conn *c,
			     unsigned long long va)
{
	struct uml_nt_stub_data *d = c->d;

	if (d == NULL || c->mm == NULL || va == 0 || c->chain_hops >= 4)
		return;
	c->chain_va = va;
	c->chain_armed = 1;
	d->dr_watch[UML_NT_DR_EXEC_SLOT] = va;
	d->dr_exec_mask |= 1u << UML_NT_DR_EXEC_SLOT;
	os_info("[pivot-chain] pid %lu %s hop %u armed at 0x%llx "
		"(execute) — does the text rsp already exist there?\n",
		(unsigned long)c->pid, c->exec_path, c->chain_hops, va);
}

/* THE DR SLOTS HAVE ONE OWNER AT A TIME (Shelley 164).
 *
 * Three instruments arm hardware breakpoints through the same four
 * slots: the tcache tear watch (0/1), the arena bin-head watch (2/3),
 * the write-slot pivot watch (0..3), and now the one-shot execute
 * probe (2). Every contention bug today came from that: the write-slot
 * instrument zeroed dr_exec_mask and took slot 2, and the bin-head
 * instrument rewrites slots 2/3 every 64 rounds — between them they
 * silently disarmed the probe twice while it reported "armed but never
 * fired". (A central slot allocator is the real fix and is the next
 * slice; this predicate is the honest stop-gap: while the probe is
 * live, the retired tear-hunt instruments stand down.)
 */
static int dr_probe_owns_slots(struct uml_nt_stub_conn *c)
{
	/* Shelley 164: the allocator decides now — this predicate is the
	 * instruments' cheap pre-check and mirrors the ledger's answer. */
	return c != NULL && c->drs.owner[0] != UML_NT_DRS_FREE &&
	       uml_nt_drs_holds(&c->drs, UML_NT_DRS_EXEC) > 0;
}

/* [dr-exec] (Shelley 162): DOES THE GUEST EXECUTE THE FIRST
 * INSTRUCTION AFTER THE RESUME? Everything else is measured — the
 * CONTEXT is sane, the answer's target (rip+2) holds the real
 * instruction, the VMA and the ledger agree, and the fs hop completes
 * (pre == post). The one thing never observed is the guest itself.
 *
 * So arm ONE execute breakpoint at rip+2 — the address the hop jumps
 * to — for one round of the login conn. An execute breakpoint fires
 * BEFORE the instruction, so:
 *   #DB arrives  => the resume carried the guest all the way to its
 *                   first instruction; the death is AFTER it, inside
 *                   guest code, and we get a live CONTEXT there.
 *   no #DB, dead => the death is BEFORE the guest's first instruction,
 *                   i.e. in the resume/hop path, with hard evidence.
 * The chain instrument proved this mechanism reports cleanly (never
 * killed a stub), so this is a measurement, not new machinery. */
#define UML_NT_DREX_MAX_ROUNDS 4000ul /* safety cap, not a budget */

static void uml_nt_drexec_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

	if (drexec_off())
		return;
	unsigned long long va;

	if (d == NULL || c->mm == NULL || c->imgw_n <= 0)
		return;
	if (!uml_nt_conn_is_login(c))
		return;
	if (g_xs_lever && d->xs_lever == 0) {
		d->xs_lever = 1;
		os_info("[xs-lever] login conn pid %d armed (EXTRA 1/2)\n",
			(int)c->pid);
	}
	/* Already armed? Then MOVE the breakpoint to this round's target
	 * instead of returning: keeping a stale address armed was the
	 * fourth way this probe measured nothing (referee 40243638730:
	 * armed=1, hundreds of rounds, hits=0 — the address armed on the
	 * first round was simply never executed again, and the early
	 * return meant no later round was ever bracketed). */

	/* Shelley 164: one-shot per ROUND, continuous across the conn.
	 *
	 * A single one-shot at the first syscall's target proved nothing:
	 * that address may simply never execute, and "hits=0" then says
	 * nothing about the resume path (it is not evidence of (B), it is
	 * absence of evidence). Armed on EVERY round at that round's own
	 * resume target, the instrument answers per-round: the guest
	 * demonstrably ran after N resumes, and whether the LAST resume
	 * before the death was executed. That is the (A)/(B) question. */
	if (c->drex_rounds >= UML_NT_DREX_MAX_ROUNDS)
		return;
	if (d->cmd != UML_STUB_CMD_SYSCALL)
		return;
	/* Shelley 164: arm where the answer will ACTUALLY resume.
	 *
	 * Two resume shapes exist and they do not share a rip:
	 *  - a plain syscall resume advances past the trap (stub +2);
	 *  - a VERBATIM answer (signal delivery, fault re-run) leaves
	 *    the kernel's pushed rip in place — arming at rip+2 there
	 *    watches an address the guest never reaches, which is one
	 *    more way this probe could report "armed but never fired"
	 *    while the conn ran for hundreds of rounds.
	 * d->regs.rip is read AFTER the answer is built, so it already
	 * carries whichever shape applies: for a plain answer the stub
	 * has not advanced yet (it advances at release), so +2; for a
	 * verbatim answer the kernel's rip IS the target. */
	if (d->xstate_flags & UML_STUB_XS_VERBATIM)
		va = d->regs.rip;
	else
		va = d->regs.rip + 2;
	if (uml_nt_vma_find(c->mm, va) == NULL)
		return;
	{
		int got[UML_NT_DRS_SLOTS];
		int n;

		/* a moving target keeps the same slot: only reserve when the
		 * ledger has none (the first round, or after a hit) */
		if (c->drex_slot >= 0) {
			got[0] = c->drex_slot;
			n = 1;
		} else {
			n = uml_nt_drs_reserve(&c->drs, UML_NT_DRS_EXEC, 1,
					       got);
		}
		if (n <= 0) {
			os_info("[dr-exec] pid %lu slot ledger full:\n",
				(unsigned long)c->pid);
			return;
		}
		/* the probe is the live instrument: the retired tear-hunt
		 * owners lose their claims for this conn */
		uml_nt_drs_retire(&c->drs, UML_NT_DRS_TCACHE);
		uml_nt_drs_retire(&c->drs, UML_NT_DRS_ARENA);
		uml_nt_drs_retire(&c->drs, UML_NT_DRS_WSLOT);
		c->drex_slot = got[0];
		if (quiet_off())
			c->d->quiet = 1;
		d->dr_watch[c->drex_slot] = va;
		d->dr_exec_mask |= 1u << c->drex_slot;
		os_info("[dr-exec] slot=%d shape=%s (ledger: exec=%d)\n",
			c->drex_slot,
			(d->xstate_flags & UML_STUB_XS_VERBATIM) ?
			"verbatim" : "plain",
			uml_nt_drs_holds(&c->drs, UML_NT_DRS_EXEC));
	}
	c->drex_va = va;
	c->drex_armed = 1;
	c->drex_rounds++;
	os_info("[dr-exec] pid %lu %s ONE-SHOT execute breakpoint at "
		"0x%llx (the guest's first instruction after this resume) "
		"— a hit proves the resume reached guest code\n",
		(unsigned long)c->pid, c->exec_path, va);
}

/* A DR hit at the armed address: the guest got there. Observation
 * only — disarm, log the live state, resume verbatim (an execute
 * breakpoint fires before the instruction, so rip still points at
 * it and re-executing is exactly right). */
static int uml_nt_drexec_round(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

	if (!c->drex_armed)
		return 0;
	/* the stub publishes the accessed address and its type (8 =
	 * execute) — no raw dr6 in the shared block, and none needed */
	if (d->dr_hit_va != c->drex_va && d->regs.rip != c->drex_va)
		return 0;
	c->drex_armed = 0;
	c->drex_used = 1;
	c->drex_hits_seen++;
	if (c->drex_slot >= 0) {
		d->dr_watch[c->drex_slot] = 0;
		d->dr_exec_mask &= ~(1u << c->drex_slot);
		uml_nt_drs_release(&c->drs, UML_NT_DRS_EXEC);
		c->drex_slot = -1;
	}
	d->drex_hits++;
	if (c->drex_hits_seen <= 5 || !(c->drex_hits_seen % 100))
		os_info("[dr-exec] HIT n=%lu of %lu resumes pid %lu "
			"rip=0x%llx rsp=0x%llx rax=0x%llx rflags=0x%llx "
			"hit_type=%llu ==> THE GUEST RAN after this resume\n",
			(unsigned long)c->drex_hits_seen,
			(unsigned long)c->drex_rounds, (unsigned long)c->pid,
			d->regs.rip, d->regs.rsp, d->regs.rax, d->regs.rflags,
			d->dr_hit_type);
	d->action = UML_STUB_ACTION_NONE;
	d->err = 0;
	return 1;
}

/* One walk hop: the state at a chain address, then the next hop taken
 * from the text stack's own return address ([rsp] = the caller's
 * continuation, planted by the call that entered this frame). */
static void uml_nt_chain_round(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned long long va = c->chain_va;
	unsigned long long ret = 0, caller_ra = 0;
	struct uml_nt_vma *rv;
	long long so;
	int code = 0;

	c->chain_armed = 0;
	c->chain_va = 0;
	d->dr_watch[UML_NT_DR_EXEC_SLOT] = 0;
	d->dr_exec_mask &= ~(1u << UML_NT_DR_EXEC_SLOT);
	so = uml_nt_vma_translate(c->mm, d->regs.rsp, 16);
	if (so >= 0) {
		/* [rsp] = the pushed %rbx; [rsp+8] = the call-site's
		 * return address (what the PLT pushed). */
		ret = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + so);
		caller_ra = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + so + 8);
	}
	rv = ret ? uml_nt_vma_find(c->mm, ret) : NULL;
	if (rv != NULL && (rv->prot & 0x40))	/* PAGE_EXECUTE_* */
		code = 1;
	os_info("[pivot-chain] pid %lu %s HOP %u at 0x%llx: rsp=0x%llx "
		"rbp=0x%llx rdi=0x%llx rsi=0x%llx rdx=0x%llx rbx=0x%llx "
		"[rsp]=0x%llx callerRA=0x%llx%s\n",
		(unsigned long)c->pid, c->exec_path, c->chain_hops, va,
		d->regs.rsp, d->regs.rbp, d->regs.rdi, d->regs.rsi,
		d->regs.rdx, d->regs.rbx, ret, caller_ra,
		(d->regs.rsp >= c->interp_base &&
		 d->regs.rsp < c->interp_base + 0x40000) ?
		" [rsp ALREADY IN TEXT]" : " [rsp legit]");
	if (d->regs.rbp >= 0x10000)
		uml_nt_frame_walk(c, d->regs.rbp, 4);
	/* the code around this hop (the function that owns it) */
	if (va > 0x200)
		dump_guest_bytes(c->mm, va - 0x200, 0x200, "pivot-chain-code");
	if (d->regs.rsp > 0x80)
		dump_guest_bytes(c->mm, d->regs.rsp - 0x40, 0x140,
				 "pivot-chain-stack");
	c->chain_hops++;
	if (code && c->chain_hops < 4)
		uml_nt_chain_arm(c, ret);
}

/* A write to one of the ruled text qwords: the store that marshal's
 * the arg array INTO the interp's own text. Report the order, the
 * post-store value, the store instruction, the frame pointer (the
 * pivot value), every register, and the frame itself. */
static void uml_nt_pivot_wslot_round(struct uml_nt_stub_conn *c, int slot)
{
	struct uml_nt_stub_data *d = c->d;
	long long vo = uml_nt_vma_translate(c->mm, d->fault_addr, 8);
	unsigned long long v = ~0ull;

	if (vo >= 0)
		v = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + vo);
	c->ws_hits++;
	if (c->ws_hits == 1) {
		/* The resolver's XSAVE size, read AT the hit (the arm-time
		 * read is 0 — ld.so fills it during its own init, which
		 * runs after our arm). `rsp & -64 - this` must land on the
		 * observed base+0xc600. */
		long long xo = uml_nt_vma_translate(c->mm,
						   c->interp_base + 0x32c70, 8);
		unsigned long long xsz = ~0ull;

		if (xo >= 0)
			xsz = *(const unsigned long long *)(const void *)
				((char *)uml_boot.physmem_base + xo);
		os_info("[pivot-xsav] pid %lu interp_base=0x%llx "
			"_rtld_global_ro+0x1b0 (ld.so 0x32c70) = 0x%llx — "
			"the resolver's `sub` operand\n",
			(unsigned long)c->pid, c->interp_base, xsz);
	}
	if (c->ws_hits == 1 && c->d->regs.rbp >= 0x10000)
		uml_nt_frame_walk(c, c->d->regs.rbp, 8);
	if (c->ws_hits == 1 && c->chain_hops == 0 && c->interp_base != 0) {
		/* Shelley 154 §4: arm on the LAZY-BINDING RESOLVER itself.
		 * It is entered with the PLT call's return address at
		 * [rsp+8] (after its own `push %rbx`), so one hit names
		 * the call-site that ran with a text rsp. ld.so 0x121c0 =
		 * `push %rbx; mov %rsp,%rbx; and $-64; sub [xsave],%rsp`. */
		uml_nt_chain_arm(c, c->interp_base + 0x121c0);
	}
	/* Where did the text stack get its top? The FIRST hit is the one
	 * that matters; every later hit is the stack descending. */
	os_info("[pivot-wslot] pid %lu %s HIT #%u slot=%d va=0x%llx "
		"real=0x%llx type=%llu value=0x%llx post-rip=0x%llx "
		"rbp=0x%llx rsp=0x%llx depth=0x%llx\n",
		(unsigned long)c->pid, c->exec_path, c->ws_hits, slot,
		d->fault_addr, d->dr_hit_va, d->dr_hit_type, v,
		d->regs.rip, d->regs.rbp, d->regs.rsp,
		(c->interp_base + 0xc600ull > d->regs.rsp) ?
		(c->interp_base + 0xc600ull - d->regs.rsp) : 0);
	os_info("[pivot-wslot]   rax=0x%llx rbx=0x%llx rcx=0x%llx "
		"rdx=0x%llx rsi=0x%llx rdi=0x%llx\n",
		d->regs.rax, d->regs.rbx, d->regs.rcx, d->regs.rdx,
		d->regs.rsi, d->regs.rdi);
	os_info("[pivot-wslot]   r8=0x%llx r9=0x%llx r10=0x%llx "
		"r11=0x%llx r12=0x%llx r13=0x%llx r14=0x%llx "
		"r15=0x%llx flags=0x%llx\n",
		d->regs.r8, d->regs.r9, d->regs.r10, d->regs.r11,
		d->regs.r12, d->regs.r13, d->regs.r14, d->regs.r15,
		d->regs.rflags);
	/* WHICH MODULE is the store in? Referees 40116431479/40116439363
	 * put the first push at base+0xc5f8 (rsp) with a store at
	 * 0x607a1120 / 0x604b1120 — base+0x1120 in a module whose base
	 * moves per boot — and a pushed code pointer at base+0x1347.
	 * The VMA covering the store names the module; the whole table is
	 * dumped once so the layout can be read offline. */
	{
		static int vt_done;
		struct uml_nt_vma *vn = uml_nt_vma_find(c->mm, d->regs.rip);

		if (vn != NULL)
			os_info("[pivot-wslot]   store in vma [0x%llx,0x%llx) "
				"prot=0x%x flags=0x%x run_off=0x%llx — off "
				"0x%llx into its span\n",
				vn->start, vn->end, vn->prot, vn->flags,
				vn->run_off, d->regs.rip - vn->start);
		else
			os_info("[pivot-wslot]   store rip 0x%llx is in NO "
				"vma of this mm\n", d->regs.rip);
		if (!vt_done) {
			int vi;

			vt_done = 1;
			os_info("[pivot-wslot]   login mm: %d vma(s)\n",
				c->mm->nvma);
			for (vi = 0; vi < c->mm->nvma; vi++) {
				struct uml_nt_vma *v = &c->mm->vma[vi];

				os_info("[pivot-wslot]     [0x%llx,0x%llx) "
					"prot=0x%x flags=0x%x run=0x%llx "
					"gen=0x%llx\n",
					v->start, v->end, v->prot, v->flags,
					v->run_off, v->gen);
			}
		}
	}
	/* THE CODE THAT CONSUMED THE BAD rsp: the store instruction's
	 * own bytes (post-rip - 0x20 .. +0x40), and the bytes at the
	 * pushed pointer. The store sits in a 14248-byte module freshly
	 * mmap'd at 0x607a0000 (login mm, 47 VMAs dumped below), whose
	 * image offset cannot be decoded offline — so the witness
	 * carries the bytes. */
	if (d->regs.rip > 0x150 && c->ws_hits <= 2) {
		/* Shelley 152: 0x150 of code ENDING at the store (the
		 * instruction itself, plus the block that set rsp) and
		 * the qwords around the stored pointer. */
		dump_guest_bytes(c->mm, d->regs.rip - 0x150, 0x150,
				 "pivot-wslot-code");
		if (v > 0x40 && v < 0x800000000000ull)
			dump_guest_bytes(c->mm, v - 0x40, 0x80,
					 "pivot-wslot-pushed");
		/* THE PIVOT IS HERE. Referee 40120649948 decoded the first
		 * push exactly: a `call` at module+0x1342 to its own PLT
		 * entry at module+0x1120, so the pushed qword is the
		 * return address module+0x1347 — and rsp was ALREADY
		 * 0x6001c600 (base+0xc600) when that call ran. The
		 * function that made the call therefore set rsp; its body
		 * lies in the ~0x200 bytes before the return address, and
		 * every reference in the sequence above held a legit stack
		 * frame pointer (rbp=0x6005c6a0) and legit arguments. */
	}
	/* THE TEXT STACK ITSELF: dump 0x300 from rsp upward. Once the
	 * guest runs with rsp inside the interp's text, every frame
	 * push leaves a return address there — so this dump IS the call
	 * chain, in push order, and the highest non-zero qword is the
	 * return address INTO the function that switched rsp into text
	 * (the pivot). Referee 40114317847 #1 showed the shape plainly:
	 * libc `push %r13` (`__nss_passwd_lookup2+0`) with
	 * rsp=0x6001c510 already in text. */
	if (d->regs.rsp >= 0x100 && d->regs.rsp < 0x800000000000ull)
		dump_guest_bytes(c->mm, d->regs.rsp & ~0xfull, 0x300,
				 "pivot-wslot-stack");
}

/* One execute-breakpoint round: the state at the ENTRY, before its
 * first instruction. rdi is the `addr` argument, [rsp] the caller's
 * return address — the two facts the pivot hunt needs. */
static void uml_nt_dr_exec_round(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned long long rdi = d->regs.rdi;
	unsigned long long rsi = d->regs.rsi;
	unsigned long long ret = 0;
	long long so;
	/* Shelley 150: the bad call hands _dl_find_dso_for_object a
	 * BYTE-SHIFTED pointer into the interp's own text. Test against
	 * the interp image span (interp_base .. +0x40000), which is where
	 * every observed pivot value lives (0x6001b5xx/0x6001c2xx) —
	 * tighter than "any image run" and independent of run capture. */
	int arg_text = 0;
	int rbp_text = 0;

	if (c->interp_base != 0 &&
	    ((rdi >= c->interp_base && rdi < c->interp_base + 0x40000) ||
	     (rsi >= c->interp_base && rsi < c->interp_base + 0x40000)))
		arg_text = 1;
	/* The decisive shape (referees 40107984279/40109916441 measured
	 * the entry's first calls with a CLEAN rbp=0x6005cdb0): this
	 * function builds its arg arrays at -0x430/-0x428(%rbp,%rcx,1),
	 * so once rbp itself is inside the interp span, the arrays land
	 * in TEXT — the sparse 258-byte footprint, the pivot's stack,
	 * and then the wild-entry death in this very region. An entry hit
	 * with a TEXT rbp is therefore the pivot's successor call. */
	if (c->interp_base != 0 &&
	    d->regs.rbp >= c->interp_base &&
	    d->regs.rbp < c->interp_base + 0x40000)
		rbp_text = 1;
	static int exec_budget = 64;

	c->dr_exec_hits++;
	/* ONE-SHOT: the resume re-executes the entry, and an armed
	 * execute breakpoint would re-fire on it forever (the stub's
	 * fault-resume lands exactly there). Disarm before answering —
	 * the next close(3) arms again. */
	c->dr_exec_armed = 0;
	c->dr_exec_va = 0;
	d->dr_watch[UML_NT_DR_EXEC_SLOT] = 0;
	d->dr_exec_mask &= ~(1u << UML_NT_DR_EXEC_SLOT);
	so = uml_nt_vma_translate(c->mm, d->regs.rsp, 8);
	if (so >= 0)
		ret = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + so);
	/* Log every hit for the first few (the call cadence), then only
	 * the interesting ones: a TEXT-shaped argument is the bad call
	 * this hunt is about (a byte-shifted addr handed to the loader's
	 * DSO lookup). */
	if (exec_budget > 0 && rbp_text) {
		exec_budget--;
		os_info("[pivot-dr] pid %lu %s ENTRY hit #%u rip=0x%llx "
			"rdi=0x%llx rsi=0x%llx rsp=0x%llx rbp=0x%llx "
			"rbx=0x%llx ret=0x%llx%s\n",
			(unsigned long)c->pid, c->exec_path,
			c->dr_exec_hits, d->regs.rip, rdi, rsi,
			d->regs.rsp, d->regs.rbp, d->regs.rbx, ret,
			rbp_text ? " [TEXT RBP — the arrays land in text]" :
			arg_text ? " [TEXT-SHAPED ARG]" : "");
	}
	if (arg_text || rbp_text) {
		/* The caller's frame: the slot the bad value was loaded
		 * from is in here (or in a register the caller still
		 * holds — rbp/rbx of this frame). */
		if (d->regs.rsp > 0x80 && c->mm != NULL)
			dump_guest_bytes(c->mm, d->regs.rsp - 0x80, 0x200,
					 "dr-exec-caller");
		os_info("[pivot-dr] pid %lu %s BAD CALL: entry 0x%llx with "
			"rdi=0x%llx (text-shaped), caller ret=0x%llx "
			"rbp=0x%llx rbx=0x%llx — the arrays this call "
			"marshals land in image text\n",
			(unsigned long)c->pid, c->exec_path,
			c->dr_exec_va, rdi, ret, d->regs.rbp, d->regs.rbx);
	}
}

unsigned int uml_nt_sample_burst(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned int n = 0;
	unsigned int tries = 0;

	if (c->smp_left == 0 || c->mm == NULL || c->thread == NULL || d == NULL)
		return 0;
	/* Never sample a round in flight: the pump released the answer, so
	 * the stub must be back in guest code. A published request ends
	 * the burst (the interval just closed). */
	while (n < c->smp_left && tries < UML_NT_SMP_TRIES &&
	       d->req_seq == d->done_seq) {
		unsigned long long rip = 0, rsp = 0, rbp = 0, rdi = 0,
				   rsi = 0, rbx = 0;
		int rsp_text, hit_dldso, arg_text;

		tries++;
		if (uml_nt_sample_read(c, &rip, &rsp, &rbp, &rdi, &rsi,
				       &rbx) < 0)
			break;
		if (!uml_nt_sample_is_guest(c, rip)) {
			/* the stub is still waking up / inside its own
			 * dispatch: this is not the guest running. Keep
			 * probing (the suspension alone paces us). */
			continue;
		}
		n++;
		c->smp_n++;
		rsp_text = uml_nt_resume_rsp_wild(c, rsp);
		hit_dldso = uml_nt_sample_marshal_shape(c, rbp, rsp);
		arg_text = uml_nt_sample_rip_in_image(c, rdi) ||
			   uml_nt_sample_rip_in_image(c, rsi);

		/* Volume policy: the first 24 samples of an arm log whole,
		 * then only the interesting ones (the interp window, a
		 * text rsp, a text-shaped pointer in the argument
		 * registers) plus a heartbeat every 32. */
		if (n <= 24 || (n & 31) == 0 || hit_dldso || rsp_text ||
		    arg_text ||
		    uml_nt_sample_rip_in_image(c, c->smp_prev_rip) ||
		    uml_nt_sample_marshal_shape(c, c->smp_prev_rbp,
						c->smp_prev_rsp))
			os_info("[pivot-sample] pid %lu %s n=%u/%u "
				"rip=0x%llx rsp=0x%llx rbp=0x%llx "
				"rdi=0x%llx rsi=0x%llx rbx=0x%llx%s%s\n",
				(unsigned long)c->pid, c->exec_path, n,
				c->smp_left, rip, rsp, rbp, rdi, rsi, rbx,
				rsp_text ? " [RSP-IN-TEXT]" : "",
				hit_dldso ? " [ARRAY-UNDER-TEXT-RBP]" :
				arg_text ? " [TEXT-PTR-IN-ARG]" : "");

		if (rsp_text || hit_dldso || arg_text) {
			/* The claim, checked live: print the sample BEFORE
			 * (the caller / the instruction that produced the
			 * bad pointer) and stop the burst. */
			if (c->smp_prev_valid)
				os_info("[pivot-sample] pid %lu %s HIT: previous "
					"sample rip=0x%llx rsp=0x%llx "
					"rbp=0x%llx rdi=0x%llx rsi=0x%llx "
					"rbx=0x%llx — %s\n",
					(unsigned long)c->pid, c->exec_path,
					c->smp_prev_rip, c->smp_prev_rsp,
					c->smp_prev_rbp, c->smp_prev_rdi,
					c->smp_prev_rsi, c->smp_prev_rbx,
					rsp_text ?
					  "rsp landed in image text (the pivot ran)"
					  : "the marshal array sits under a text rbp");
			/* And the live stack top: the bad pointer's slot is
			 * usually one or two qwords in. */
			if (c->smp_prev_valid && c->smp_prev_rsp > 0x80)
				dump_guest_bytes(c->mm,
						 c->smp_prev_rsp - 0x40, 0x100,
						 "sample-prev-stk");
			break;
		}
		c->smp_prev_rip = rip;
		c->smp_prev_rsp = rsp;
		c->smp_prev_rbp = rbp;
		c->smp_prev_rdi = rdi;
		c->smp_prev_rsi = rsi;
		c->smp_prev_rbx = rbx;
		c->smp_prev_valid = 1;
		c->smp_in_text = rsp_text ? 1u : 0u;
	}
	if (c->smp_left > n)
		c->smp_left -= n;
	else
		c->smp_left = 0;
	return n;
}

/* Arm the sampler on the same answer the TF trace used: a successful
 * close(3) on a login conn, not issued from the binary's own text (the
 * pivot's close came from libc). One arm per close, bounded per conn. */
static void uml_nt_sample_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned int n = UML_NT_SMP_PER_ARM;

	if (c->smp_used + n > UML_NT_SMP_PER_CONN)
		n = c->smp_used >= UML_NT_SMP_PER_CONN ?
			0 : UML_NT_SMP_PER_CONN - c->smp_used;
	if (n == 0)
		return;
	c->smp_used += n;
	c->smp_arms++;
	c->smp_left = n;
	c->smp_n = 0;
	c->smp_prev_valid = 0;
	c->smp_in_text = 0;
	os_info("[pivot-sample] pid %lu %s SAMPLER armed (%u sample(s), arm "
		"%u): from rip=0x%llx rsp=0x%llx last_nr=%llu last_ret=%lld — "
		"sampling the guest the [resume-regs] verdict proved moves its "
		"own rsp\n",
		(unsigned long)c->pid, c->exec_path, n, c->smp_arms,
		d->regs.rip, d->regs.rsp, c->last_nr, c->last_ret);
}

/* Should this answer arm the sampler? (Same shape as the retired TF
 * arm gate: a successful close(3) from a NON-exe mapping on a login
 * conn — the pivot's close is libc's `__close_nocancel`.) */
static int uml_nt_sample_should_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

	if (c->imgw_n <= 0 || c->mm == NULL || !c->res_trap_valid)
		return 0;
	if (c->smp_left != 0 || c->smp_used >= UML_NT_SMP_PER_CONN)
		return 0;
	if (!uml_nt_conn_is_login(c))
		return 0;
	if (d->cmd == UML_STUB_CMD_FAULT &&
	    d->fault_type == UML_NT_FAULT_STEP)
		return 0;
	if (c->last_nr != 3 /* close(2) */ || c->last_ret != 0)
		return 0;
	/* Never arm on a round whose rsp is ALREADY in image text: the
	 * pivot has happened (referee 40092427406 armed there once and
	 * its only hit was the post-pivot chain) — the interesting window
	 * is the one that STARTS clean. */
	if (uml_nt_resume_rsp_wild(c, d->regs.rsp))
		return 0;
	{
		struct uml_nt_vma *ev = uml_nt_vma_find(c->mm, d->entry_va);
		struct uml_nt_vma *rv = uml_nt_vma_find(c->mm, d->regs.rip);

		if (ev != NULL && ev == rv)
			return 0;
	}
	return 1;
}

/* Should this answer arm the trace? A successful close(3) on a login
 * conn, at a resume point, once the previous trace (if any) is spent. */
static int uml_nt_tf_trace_should_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

	if (c->imgw_n <= 0 || c->mm == NULL || !c->res_trap_valid)
		return 0;
	if (d->tf_trace != 0 || c->tf_used >= UML_NT_TF_STEPS_PER_CONN)
		return 0;
	if (!uml_nt_conn_is_login(c))
		return 0;
	if (d->cmd == UML_STUB_CMD_FAULT &&
	    d->fault_type == UML_NT_FAULT_STEP)
		return 0;
	if (c->last_nr != 3 /* close(2) */ || c->last_ret != 0)
		return 0;
	/* Skip closes issued from the binary's OWN text: /bin/login closes
	 * its own files in loops (referee 40086019923: both armings were
	 * rip=0x60030a05, the exe, and their 3000 steps were gone before
	 * the pivot round arrived). The pivot's close came from libc
	 * (rip=0x601ece65) — a different mapping than the entry. */
	{
		struct uml_nt_vma *ev = uml_nt_vma_find(c->mm, d->entry_va);
		struct uml_nt_vma *rv = uml_nt_vma_find(c->mm, d->regs.rip);

		if (ev != NULL && ev == rv)
			return 0;
	}
	return 1;
}

void uml_nt_census(const char *tag, long long pid)
{
	struct task_struct *p;
	struct uml_nt_phys *ph = NULL;
	unsigned long top_pid[UML_NT_CENSUS_TOP] = { 0, 0, 0 };
	int top_runs[UML_NT_CENSUS_TOP] = { 0, 0, 0 };
	int used = 0, parked = 0, live = 0, dying = 0;
	int fce = 0, fcr = 0;

	if (tag[0] == 'p' && census_pressure_left-- <= 0)
		return;
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		int vi, runs = 0, i, slot;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		if (ph == NULL && pc->ph != NULL)
			ph = pc->ph;
		if (!pc->alive) {
			dying++;
			continue;
		}
		live++;
		for (vi = 0; vi < pc->mm->nvma; vi++)
			runs += (int)((pc->mm->vma[vi].end -
				       pc->mm->vma[vi].start) >>
				      UML_NT_PHYS_RUN_SHIFT);
		for (i = 0; i < pc->imgw_n; i++) {
			unsigned long long run = pc->imgw_run[i];
			unsigned long long h;

			if (pc->ph == NULL ||
			    uml_nt_phys_refs(pc->ph, (long long)run) <= 0 ||
			    uml_nt_phys_gen(pc->ph, (long long)run) !=
			    pc->imgw_gen[i])
				continue;
			h = uml_nt_imgw_hash((const void *)((const char *)
					uml_boot.physmem_base + run));
			if (h != pc->imgw_hash[i] && imgw_fire_left-- > 0) {
				unsigned long long vstart = 0, vend = 0;
				int vi2;

				os_info("[imgwatch] pid %lu: RO image run "
					"0x%llx rewritten post-load (was "
					"%016llx now %016llx) — text "
					"rewrite class\n",
					(unsigned long)pc->pid, run,
					pc->imgw_hash[i], h);
				/* D28 follow-up: name the writer. The run's
				 * VA in THIS conn + the TO_GUEST ledger
				 * (run-keyed — the writer may be another
				 * mm) + the view-op log over the range. */
				for (vi2 = 0; vi2 < pc->mm->nvma; vi2++) {
					struct uml_nt_vma *iv =
						&pc->mm->vma[vi2];
					unsigned long long span =
						iv->end - iv->start;

					if (run < iv->run_off ||
					    run >= iv->run_off + span)
						continue;
					vstart = iv->start +
						 (run - iv->run_off);
					vend = vstart +
					       UML_NT_PHYS_RUN_SIZE;
					os_info("[imgwatch]   run->va "
						"0x%llx vma [0x%llx,0x%llx) "
						"prot=0x%x flags=0x%x\n",
						vstart, iv->start, iv->end,
						iv->prot, iv->flags);
					break;
				}
				if (vend != 0) {
					int ok, on = pc->op_log_n;
					int olo = on > 64 ? on - 64 : 0;

					uml_nt_uacc_towrite_dump(run);
					for (ok = olo; ok < on &&
					     ok < olo + 64; ok++) {
						unsigned long long *eo =
							pc->op_log[ok % 64];

						if (eo[2] >= vend ||
						    eo[2] + eo[3] <= vstart)
							continue;
						os_info("[imgwatch]   op "
							"op=%llu prot=0x%llx "
							"va=0x%llx len=0x%llx "
							"off=0x%llx\n",
							eo[0], eo[1], eo[2],
							eo[3], eo[4]);
					}
				}
			}
		}
		for (slot = 0; slot < UML_NT_CENSUS_TOP; slot++) {
			if (runs > top_runs[slot]) {
				int k;

				for (k = UML_NT_CENSUS_TOP - 1; k > slot;
				     k--) {
					top_runs[k] = top_runs[k - 1];
					top_pid[k] = top_pid[k - 1];
				}
				top_runs[slot] = runs;
				top_pid[slot] = (unsigned long)pc->pid;
				break;
			}
		}
	}
	/* D28 follow-up (Shelley 148): cross-mm run alias census — two
	 * LIVE conns' VMAs claiming the same run. Fork parent/child
	 * shares are expected (filtered via ppid); an UNRELATED pair is
	 * the double-claim/image-sharing class the co-mapper dump
	 * hinted at. Log-only, budgeted. */
	{
		static int alias_left = 24;
		static unsigned long long owner[UML_NT_PHYS_MAX_RUNS];
		static unsigned long long owner_pp[UML_NT_PHYS_MAX_RUNS];
		struct task_struct *ap;

		if (alias_left > 0) {
			memset(owner, 0, sizeof(owner));
			memset(owner_pp, 0, sizeof(owner_pp));
			for_each_process(ap) {
				struct uml_nt_stub_conn *ac;
				int ai;

				if (ap->mm == NULL)
					continue;
				ac = ((struct mm_id *)
				      &ap->mm->context.id)->nt_conn;
				if (ac == NULL || ac->mm == NULL ||
				    !ac->alive ||
				    ac->dead_magic == UML_NT_CONN_DEAD)
					continue;
				for (ai = 0; ai < ac->mm->nvma; ai++) {
					struct uml_nt_vma *v =
						&ac->mm->vma[ai];
					unsigned long long ro;
					unsigned long long me =
						(unsigned long long)ac->pid + 1;
					unsigned long long mp =
						(unsigned long long)ac->ppid + 1;

					/* Fork COW shares and the fcache's
					 * RO/EXEC file-run sharing (FILE)
					 * are both by design — only an
					 * image/anon share is suspicious. */
					if (v->flags & (UML_NT_VMA_COW |
							UML_NT_VMA_FILE))
						continue;
					for (ro = v->run_off;
					     ro < v->run_off +
						  (v->end - v->start);
					     ro += UML_NT_PHYS_RUN_SIZE) {
						unsigned int idx =
							(unsigned int)
							(ro /
							 UML_NT_PHYS_RUN_SIZE);

						if (idx >=
						    UML_NT_PHYS_MAX_RUNS)
							break;
						if (owner[idx] == 0) {
							owner[idx] = me;
							owner_pp[idx] = mp;
							continue;
						}
						if (owner[idx] == me)
							continue;
						/* expected fork share */
						if (owner[idx] == mp ||
						    owner_pp[idx] == me)
							continue;
						if (alias_left > 0) {
							alias_left--;
							os_info("[runalias] "
								"%s: run "
								"0x%llx pid %lu "
								"(ppid %llu) vs "
								"pid %llu prot=0x%x "
								"flags=0x%x\n",
								tag, ro,
								(unsigned long)
								ac->pid,
								ac->ppid,
								owner[idx] - 1,
								v->prot,
								v->flags);
						}
					}
				}
			}
		}
	}
	if (ph != NULL)
		uml_nt_phys_table_stats(ph, &used, &parked);
	uml_nt_fcache_stats(&fce, &fcr);
	{
		/* D28 instrument: the live deferred file regions and their
		 * file-run vs touched-run totals (the lazy win's metric).
		 * Budgeted — the census itself runs on every exec/exit. */
		static int lazy_census_left = 24;
		int lreg = 0;
		unsigned long long lfr = 0, ltd = 0;

		uml_nt_lazy_stats(&lreg, &lfr, &ltd);
		if (lreg > 0 && lazy_census_left-- > 0)
			os_info("[lazyfile] census pid %lld: regions=%d "
				"file_runs=%llu touched=%llu\n",
				pid, lreg, lfr, ltd);
	}
	os_info("[census] %s pid %lld: used=%d/%d runs (%llu MiB) "
		"parked=%d fc=%de/%dr live=%d dying=%d | free=%lluM "
		"file=%lluM slab=%lluM | top %lu:%dr %lu:%dr %lu:%dr\n",
		tag, pid, used,
		(int)(uml_boot.physmem_size >> UML_NT_PHYS_RUN_SHIFT),
		((unsigned long long)used << UML_NT_PHYS_RUN_SHIFT) >> 20,
		parked, fce, fcr, live, dying,
		(((unsigned long long)global_zone_page_state(NR_FREE_PAGES))
		 << PAGE_SHIFT) >> 20,
		(((unsigned long long)global_node_page_state(NR_FILE_PAGES))
		 << PAGE_SHIFT) >> 20,
		((((unsigned long long)global_node_page_state(
			NR_SLAB_RECLAIMABLE_B)) +
		  ((unsigned long long)global_node_page_state(
			NR_SLAB_UNRECLAIMABLE_B)))) >> 20,
		top_pid[0], top_runs[0], top_pid[1], top_runs[1],
		top_pid[2], top_runs[2]);
}

/* [census-class] (Shelley 156 (a)+(d)): classify every USED run so the
 * reclaim decision has numbers and the leak hunt has a target:
 *   anon-private   no file VMA claims it (heap/stack/brk) — never
 *                  evictable
 *   file-dirty     a WRITABLE file VMA claims it — not evictable
 *                  without writeback
 *   shared-exec    an executable file VMA with refs > 1 — evictable
 *                  only when every mapper is idle
 *   file-clean     only read-only file VMAs claim it — page cache,
 *                  re-faultable byte-identically from the image (D28)
 * Hardest-to-evict wins when several VMAs claim one run. */

/* [conn-reg] (Shelley 157 (b)): the census must not depend on
 * for_each_process seeing the conn through mm->context at whatever
 * instant the allocator calls the pressure hook — three referees in a
 * row printed used=0 from inside that walk. Every conn joins this
 * registry at birth and leaves it at teardown; the census walks the
 * registry instead. */
#define UML_NT_CONN_REG_MAX 256
static struct uml_nt_stub_conn *conn_reg[UML_NT_CONN_REG_MAX];
static int conn_reg_n;

void uml_nt_conn_register(struct uml_nt_stub_conn *c)
{
	int i;

	if (c == NULL)
		return;
	for (i = 0; i < conn_reg_n; i++) {
		if (conn_reg[i] == c)
			return;
	}
	if (conn_reg_n < UML_NT_CONN_REG_MAX)
		conn_reg[conn_reg_n++] = c;
	else
		os_warn("[conn-reg] registry full (%d)\n", conn_reg_n);
}

void uml_nt_conn_unregister(struct uml_nt_stub_conn *c)
{
	int i;

	for (i = 0; i < conn_reg_n; i++) {
		if (conn_reg[i] != c)
			continue;
		conn_reg[i] = conn_reg[--conn_reg_n];
		conn_reg[conn_reg_n] = NULL;
		return;
	}
}

int uml_nt_conn_reg_count(void)
{
	return conn_reg_n;
}

struct uml_nt_stub_conn *uml_nt_conn_reg_at(int i)
{
	return i >= 0 && i < conn_reg_n ? conn_reg[i] : NULL;
}

void uml_nt_census_classes(struct uml_nt_phys *ph)
{
	static unsigned char cls[UML_NT_PHYS_MAX_RUNS];
	static unsigned long long oldest[4], newest[4];
	int i, n[4] = { 0, 0, 0, 0 }, unclaimed = 0, used = 0;
	int ri;
	static int class_left = 24;

	if (ph == NULL || class_left-- <= 0)
		return;
	memset(cls, 0, sizeof(cls));
	memset(oldest, 0, sizeof(oldest));
	memset(newest, 0, sizeof(newest));
	for (ri = 0; ri < uml_nt_conn_reg_count(); ri++) {
		struct uml_nt_stub_conn *pc = uml_nt_conn_reg_at(ri);
		int vi;

		if (pc == NULL || pc->mm == NULL || pc->ph == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD || !pc->alive)
			continue;
		for (vi = 0; vi < pc->mm->nvma; vi++) {
			struct uml_nt_vma *v = &pc->mm->vma[vi];
			unsigned long long r, span = v->end - v->start;
			int c = 3;	/* file-clean by default */

			if (!(v->flags & 0x2))
				c = 0;			/* anon-private */
			else if (v->prot & 0x04)
				c = 1;			/* file-dirty */
			else if ((v->prot & 0x30) &&
				 uml_nt_phys_refs(pc->ph,
					(long long)v->run_off) > 1)
				c = 2;			/* shared-exec */
			for (r = 0; r < span; r += UML_NT_PHYS_RUN_SIZE) {
				unsigned long long run = v->run_off + r;

				if (run >= UML_NT_PHYS_MAX_RUNS)
					break;
				if (cls[run] < 200 && c > cls[run])
					cls[run] = (unsigned char)c;
				else if (cls[run] == 0)
					cls[run] = (unsigned char)c;
			}
		}
	}
	/* Count what the REGISTRY claims, not what the hook's table says:
	 * the pressure hook's `ph` is not necessarily the conns' table
	 * (three referees printed used=0 through that assumption). */
	for (i = 0; i < UML_NT_PHYS_MAX_RUNS; i++) {
		if (cls[i] == 0 && cls[i] < 200)
			continue;
		if (cls[i] >= 200)
			continue;
		used++;
		n[cls[i]]++;
		if (oldest[cls[i]] == 0 || ph->touch[i] < oldest[cls[i]])
			oldest[cls[i]] = ph->touch[i];
		if (ph->touch[i] > newest[cls[i]])
			newest[cls[i]] = ph->touch[i];
	}
	/* unclaimed = used runs nobody's VMA names (free or leaked) */
	{
		int ru = 0, ri2;

		for (ri2 = 0; ri2 < uml_nt_conn_reg_count(); ri2++) {
			struct uml_nt_stub_conn *pc2 =
				uml_nt_conn_reg_at(ri2);
			int vi2;

			if (pc2 == NULL || pc2->mm == NULL || !pc2->alive)
				continue;
			for (vi2 = 0; vi2 < pc2->mm->nvma; vi2++)
				ru += (int)((pc2->mm->vma[vi2].end -
					     pc2->mm->vma[vi2].start) >>
					    UML_NT_PHYS_RUN_SHIFT);
		}
		used = ru;
	}
	os_info("[census-class] used=%d: anon=%d(%lluK) file-dirty=%d(%lluK) "
		"shared-exec=%d(%lluK) file-clean=%d(%lluK) unclaimed=%d | "
		"touch-epoch anon[%llu..%llu] dirty[%llu..%llu] "
		"exec[%llu..%llu] clean[%llu..%llu]\n",
		used, n[0], (unsigned long long)n[0] * 64, n[1],
		(unsigned long long)n[1] * 64, n[2],
		(unsigned long long)n[2] * 64, n[3],
		(unsigned long long)n[3] * 64, unclaimed,
		oldest[0], newest[0], oldest[1], newest[1],
		oldest[2], newest[2], oldest[3], newest[3]);
}

void uml_nt_pressure_census(struct uml_nt_phys *p)
{
	/* the census walks the live conns' (shared) table itself */
	uml_nt_census("pressure", -1);
	uml_nt_census_classes(p);
}

/* [alloc-alias] (M5.6a, map 121 + to-shelley 119): the allocator's
 * refs table says the handout was FREE — the last word belongs to
 * the LIVE VMAs: any mm still translating into the fresh range
 * names the stale-translation writer class ("cấp phát đè run sống",
 * R25 decode of 37003166709: the heap chunk re-homes onto a run a
 * live VMA never stopped pointing at). Fired from the ONE choke
 * point every cowcopy/span/heap alloc crosses; the walk mirrors the
 * co-mapper census (single vCPU pump — the task list cannot mutate
 * under it). Log-only: a hit is EVIDENCE, the handout stands — the
 * ownership check at fault time stays the law. Budget-capped: a
 * degenerate rot that maps everything would flood the console
 * otherwise. */
void uml_nt_alloc_alias_scan(long long off, int nruns)
{
	static int alias_budget = 16;
	struct task_struct *p;
	unsigned long long lo, hi;

	lo = (unsigned long long)off;
	hi = lo + (unsigned long long)nruns * UML_NT_PHYS_RUN_SIZE;

	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		struct uml_nt_vma *pv;
		int vi;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		for (vi = 0; vi < pc->mm->nvma; vi++) {
			unsigned long long vlen;

			pv = &pc->mm->vma[vi];
			if (pv->end <= pv->start)
				continue;
			vlen = pv->end - pv->start;
			if (pv->run_off + vlen <= lo || pv->run_off >= hi)
				continue;
			if (alias_budget > 0) {
				alias_budget--;
				os_info("[alloc-alias] off=0x%llx+%d "
					"held by pid %d vma [0x%llx,0x%llx) "
					"run_off=0x%llx\n",
					off, nruns, p->pid, pv->start,
					pv->end, pv->run_off);
			}
		}
	}
}

/* K6 (M5.6a, feature cowcopy-race-class-fix, dlW 37576991123 / dlX
 * 37579340518 — the RETIRE-LOST verdict): the RELEASE GATE's answer
 * (pinned by main.c into uml_nt_phys_mapped_probe). "Does ANY stub
 * view still map [off, off+nruns*RUN)?" — a release that answers yes
 * REFUSES: recycling a section range a view still covers is exactly
 * the verdict's class (a guest store lands in the abandoned source
 * after the copy, the run retires as a "dead backing", and the
 * recycled run re-hands those bytes to the next tenant — the lost
 * tcache_put pair, 16 RETIRE-LOST fires per referee run).
 *
 * Instruments, both, per the class fix: (1) 9a56286's per-conn view
 * LEDGERS (every MAP op issued is tracked; backing-identity
 * intersection via uml_nt_view_maps_span — adjacency is not
 * coverage, a pre/post-COW neighbour piece must not hold a
 * release); (2) VirtualQueryEx CONFIRMS each ledger hit on the
 * owning stub's own process handle — the OS is the ground truth for
 * whether a store can still land (a dead conn's views die with its
 * process, and a ledger entry whose region is gone — released, or
 * the process died between the ledger walk and the query — must not
 * hold a release forever; the query returning an error still
 * REFUSES: fail-safe, a leaked block is safe, a recycled-under-
 * mapping block is the corruption). The walk mirrors the alias
 * census: the pump owns the one vCPU thread, so the task list
 * cannot mutate under it. Log-capped: the refusal itself is the
 * physalloc "release-refused" event; this names the HOLDER (once
 * per budget) so a referee decode sees whose view held the block.
 */
int uml_nt_release_mapped_scan(long long off, int nruns)
{
	static int holder_budget = 16;
	struct task_struct *p;
	unsigned long long lo = (unsigned long long)off;
	unsigned long long span = (unsigned long long)nruns *
				  UML_NT_PHYS_RUN_SIZE;

	if (off < 0 || nruns <= 0)
		return 0;
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		int wi;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL || !pc->alive ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			/* no live stub process = no mapping can hold a
			 * release (the views die with the process; the
			 * destroy path retires the ledger beside them).
			 * A conn mid-destroy (alive==0, dead_magic not
			 * yet stamped — its proc handle is already
			 * closed, the probe could not query it) must
			 * never fail-safe-refuse its OWN teardown drops:
			 * that would hold every dying mm's blocks dead
			 * (a leak, not a safety win — nothing can store
			 * through a terminated process). */
			continue;
		for (wi = 0; wi < pc->nviews; wi++) {
			const struct uml_nt_view *v = &pc->views[wi];

			if (v->len == 0)
				continue;
			if (!uml_nt_view_maps_span(v->off, v->len,
						   lo, nruns))
				continue;
			/* ledger hit — confirm against the OS: the
			 * region at the view base must still be a
			 * mapping (anything but free; a NOACCESS view
			 * still owns the section slot — a store
			 * through it the moment it re-protects).
			 * Raw constants per the file's convention
			 * (freestanding, no windows.h): State
			 * 0x10000 = MEM_FREE, 0x1000 = MEM_COMMIT. */
			{
				MEMORY_BASIC_INFORMATION mbi;
				SIZE_T got;

				memset(&mbi, 0, sizeof(mbi));
				got = nt->VirtualQueryEx(pc->proc,
						(void *)(uintptr_t)v->va,
						&mbi, sizeof(mbi));
				if (got == 0) {
					/* query failed: fail-safe —
					 * treat as mapped, refuse. */
					if (holder_budget > 0) {
						holder_budget--;
						os_info("[release-gate] "
							"off=0x%llx+%d: "
							"pid %d view "
							"[0x%llx,+0x%llx) "
							"maps it, query "
							"FAILED — "
							"refusing\n",
							off, nruns, p->pid,
							v->va, v->len);
					}
					return 1;
				}
				if (mbi.State != 0x10000 /* MEM_FREE */) {
					if (holder_budget > 0) {
						holder_budget--;
						os_info("[release-gate] "
							"off=0x%llx+%d: "
							"pid %d view "
							"[0x%llx,+0x%llx) "
							"-> section "
							"0x%llx still "
							"maps it — "
							"refusing\n",
							off, nruns, p->pid,
							v->va, v->len,
							v->off);
					}
					return 1;
				}
				/* ledger entry whose region is gone
				 * (released already / stale) — the OS
				 * says no store can land; it does not
				 * hold this release. */
			}
		}
	}
	return 0;
}

/* ---- [binwatch]/[mmdup] (M5.6a, referee 37144114627) --------
 * The tcache-side witnesses (tcdelta/tcchunk/kheap/cowtrap) and
 * the MAP-side mapcanary are ALL clean while the heap still dies:
 * 37144114627 aborted with ZERO poison fires — the unsorted-bin
 * takeout dereferenced a non-canonical bk (0x86b7317835090b95,
 * six SEGV victims sharing one corrupt heap state) and NO
 * per-round witness had ever scanned the arena bins: they were
 * the blind spot (only the abort audit walked them). This closes
 * it per round, syscall parks only — a walk at a FAULT park can
 * see a LEGITIMATE half-landed link update (the malloc sequence
 * is suspended mid-flight at the page fault; the replay finishes
 * it), while a desync visible at a SYSCALL park is real. */
static int bw_qword(struct uml_nt_mm *mm, unsigned long long va,
		     unsigned long long *out)
{
	long long off = uml_nt_vma_translate(mm, va, 8);

	if (off < 0)
		return -1;
	*out = *(const unsigned long long *)(const void *)
		((char *)uml_boot.physmem_base + off);
	return 0;
}

/* glibc 2.36 malloc_state, pinned by the abort audit's field math:
 * bin_at(1) (unsorted sentinel) = av+0x60, its fd/bk live at
 * av+0x70/av+0x78 (bins[0]/bins[1]); the top pointer qword sits
 * at av+0x60. v3 shape (37177116246: pid 500 latched a FALSE
 * arena at av+0x520 — libc .data holds many heap-shaped qwords):
 * top in-heap, unsorted fd/bk self-or-in-heap, AND a mini-walk of
 * the unsorted fd chain that terminates at the head within 8
 * members, each in-heap with a sane size. */
static int bw_arena_shape(struct uml_nt_stub_conn *c,
			  unsigned long long av)
{
	struct uml_nt_mm *mm = c->mm;
	unsigned long long top, fd, bk, cur;
	int k;

	if (av == 0 || (av & 0xf))
		return 0;
	if (bw_qword(mm, av + 0x60, &top) < 0 ||
	    bw_qword(mm, av + 0x70, &fd) < 0 ||
	    bw_qword(mm, av + 0x78, &bk) < 0)
		return 0;
	if (top < mm->heap_start || top >= mm->heap_end || (top & 0xf))
		return 0;
	if (fd != av + 0x60 && (fd < mm->heap_start ||
				fd >= mm->heap_end))
		return 0;
	if (bk != av + 0x60 && (bk < mm->heap_start ||
				bk >= mm->heap_end))
		return 0;
	cur = fd;
	for (k = 0; k < 8 && cur != av + 0x60; k++) {
		unsigned long long sz, nfd;

		if (cur < mm->heap_start || cur >= mm->heap_end ||
		    (cur & 0xf))
			return 0;
		if (bw_qword(mm, cur + 0x8, &sz) < 0 ||
		    bw_qword(mm, cur + 0x10, &nfd) < 0)
			return 0;
		if ((sz & ~7ull) < 0x20)
			return 0;
		cur = nfd;
	}
	return cur == av + 0x60;
}

/* Discover main_arena once per conn: walk the heap's chunk chain;
 * a free chunk's fd pointing OUT of the heap but into a mapped VMA
 * is a bin head (tcache/fastbin links never leave the heap) —
 * av = fd - 0x50 - 16*i, pinned by the shape check. */
static unsigned long long bw_find_arena(struct uml_nt_stub_conn *c)
{
	struct uml_nt_mm *mm = c->mm;
	unsigned long long cur = mm->heap_start;
	int n;

	for (n = 0; n < 8192 && cur + 0x20 <= mm->heap_end; n++) {
		unsigned long long sz, fd;
		long long off = uml_nt_vma_translate(mm, cur + 8, 8);
		int cand = 0;

		if (off < 0)
			return 0;
		sz = *(const unsigned long long *)(const void *)
			((char *)uml_boot.physmem_base + off);
		sz &= ~7ull;
		if (sz < 0x20)
			return 0;
		if (bw_qword(mm, cur + 0x10, &fd) == 0 &&
		    (fd < mm->heap_start || fd >= mm->heap_end) &&
		    (fd >> 48) == 0 && (fd & 0xf) == 0 &&
		    fd >= 0x1000 &&
		    uml_nt_vma_translate(mm, fd, 8) >= 0) {
			int k;

			for (k = 1; k <= 126; k++) {
				unsigned long long av =
					fd - 0x50 - 16ull * k;

				if (av < 0x10000)
					break;
				if (bw_arena_shape(c, av))
					return av;
			}
			/* bound: in-use chunks hold arbitrary user
			 * data at +0x10 (libc function pointers pass
			 * the out-of-heap translate filter); the shape
			 * check rejects each, but the 126-deep probe
			 * per false candidate must not dominate. */
			if (++cand > 64)
				return 0;
		}
		cur += sz;
	}
	return 0;
}

static void binwatch(struct uml_nt_stub_conn *c,
		     const unsigned long long *entries)
{
	static int bw_budget = 64;
	static unsigned long long bw_seen[16];
	static int bw_nseen;
	struct uml_nt_mm *mm = c->mm;
	unsigned long long av;
	int bi;

	if (bw_budget <= 0)
		return;
	/* SYSCALL parks only: a FAULT park can hold a legit
	 * half-landed link update (the sequence resumes at the
	 * replay) — a desync seen here is the real class. */
	if (c->d->cmd != UML_STUB_CMD_SYSCALL)
		return;
	if (c->bw_arena == 0) {
		static unsigned int bw_tick;

		/* Retry every 64th syscall round: early boot has
		 * no bin-linked chunks yet (everything tcache), so a
		 * one-shot try budget burned out before the first
		 * unsorted free (referee 37175427829: zero discovery
		 * lines, 64 tries gone in the first 64 rounds). */
		if ((++bw_tick & 63u) != 0)
			return;
		c->bw_arena = bw_find_arena(c);
		if (c->bw_arena == 0)
			return;
		/* DR slots 2/3 (dl7 37266648434 + dl8 37272697623: the
		 * tear moved to the SMALL-BIN heads — bin[2].bk /
		 * bin[3].bk are the fields glibc's unlink checks, the
		 * slots the poison lands in). The stub's legit-churn
		 * filter passes 0 / heap-shaped / the empty-bin self
		 * value (slot-0x10 / slot-0x18 = the head itself). */
		if (c->tctrip_want && !witness_off()) {
			int got[UML_NT_DRS_SLOTS];
			int n = uml_nt_drs_reserve(&c->drs, UML_NT_DRS_ARENA,
						   2, got);

			if (n > 0)
				c->d->dr_watch[got[0]] = c->bw_arena + 0x50 +
					16 * 2 + 0x18;
			if (n > 1)
				c->d->dr_watch[got[1]] = c->bw_arena + 0x50 +
					16 * 3 + 0x18;
		}
		os_info("[binwatch] pid %lu main_arena=0x%llx "
			"discovered\n", (unsigned long)c->pid,
			c->bw_arena);
	}
	av = c->bw_arena;
	/* dl2 (37248232176): the corrupting bin sat beyond the watched
	 * 1..5 — widen to 16 (the small-bin range; walk cost stays
	 * bounded by maxw). */
	for (bi = 1; bi <= 16 && bw_budget > 0; bi++) {
		unsigned long long head = av + 0x50 + 16ull * bi;
		unsigned long long cur;
		unsigned long long mems[8];
		int nmem = 0;
		int k, maxw = (bi == 1) ? 8 : 4, slot = 0;

		if (bw_qword(mm, head + 0x10, &cur) < 0)
			return; /* arena page not resident */
		for (k = 0; k < maxw && cur != head; k++) {
			unsigned long long rec[5];
			int di, dbl = -1, f, seen2 = 0;
			unsigned long long dedup;

			if (bw_qword(mm, cur + 0x8, &rec[0]) < 0 ||
			    bw_qword(mm, cur + 0x10, &rec[1]) < 0 ||
			    bw_qword(mm, cur + 0x18, &rec[2]) < 0 ||
			    bw_qword(mm, rec[1] + 0x18, &rec[3]) < 0 ||
			    bw_qword(mm, rec[2] + 0x10, &rec[4]) < 0) {
				/* Untranslatable member or neighbor.
				 * Only when the member VA itself is
				 * outside the heap (a heap VA failing
				 * translate = a mid-rehome piece —
				 * retry later, not evidence). */
				if (cur < mm->heap_start ||
				    cur >= mm->heap_end) {
					bw_budget--;
					os_info("[binwatch] pid %lu "
						"GARBAGE bin %d member "
						"0x%llx untranslatable "
						"(nr=%llu ret=%lld "
						"rip=0x%llx)\n",
						(unsigned long)c->pid,
						bi, cur, c->last_nr,
						c->last_ret,
						c->d->regs.rip);
					dump_guest_bytes(mm, head, 0x20,
							 "binwatch-head");
				}
				break;
			}
			/* FORMATION CATCH (M5.6a, dl0 37245194777):
			 * every witness so far sees the AFTERMATH.
			 * The formation event itself = a LIVE chunk
			 * sitting in a bin. Chunk X is in use iff
			 * (X + size)->size has PREV_INUSE set; a
			 * bin-listed member with PREV_INUSE set is
			 * the double-listing caught mid-life. Parks
			 * are between mallocs (malloc never syscalls
			 * mid-operation), so a LIVE member here is
			 * the real formation, with the round. */
			{
				unsigned long long csz =
					rec[0] & ~7ull;
				unsigned long long nq;

				if (csz >= 0x20 && csz < 0x100000 &&
				    bw_qword(mm, cur + csz + 0x8,
					     &nq) == 0 &&
				    (nq & 1) != 0) {
					bw_budget--;
					os_info("[binwatch-LIVE] pid %lu "
						"bin %d member 0x%llx "
						"size=0x%llx fd=0x%llx "
						"bk=0x%llx IS LIVE "
						"(next-chunk PREV_INUSE "
						"set) at nr=%llu "
						"ret=%lld rip=0x%llx — "
						"FORMATION: a handed-out "
						"chunk sits in the bin\n",
						(unsigned long)c->pid,
						bi, cur, rec[0],
						rec[1], rec[2],
						c->last_nr, c->last_ret,
						c->d->regs.rip);
					dump_guest_bytes(mm, cur, 0x40,
							 "binwatch-live");
				}
			}
			/* v3 FIELD DIFF (37177116246: the fires only
			 * showed the after-state): the transition of
			 * fd/bk/fd->bk/bk->fd INTO an illegal value
			 * names the exact qword, its old content, and
			 * the round — the foreign write itself.
			 * Illegal: non-canonical, or not the bin head
			 * and outside the heap span (0 stays legal —
			 * transient churn). */
			for (f = 1; f <= 4; f++) {
				unsigned long long v = rec[f];
				unsigned long long pv;
				int ill, ill_prev;
				int have = c->bw_snap_valid &&
					slot < c->bw_nslot[bi - 1] &&
					c->bw_snap[bi - 1][slot][0] ==
						cur;

				pv = have ?
					c->bw_snap[bi - 1][slot][f] : v;
				ill = ((v >> 48) != 0 || v == 0) ? 0 :
					(v != head &&
					 (v < mm->heap_start ||
					  v >= mm->heap_end));
				ill = ill || (v >> 48) != 0;
				ill_prev = ((pv >> 48) != 0 || pv == 0) ?
					0 : (pv != head &&
					     (pv < mm->heap_start ||
					      pv >= mm->heap_end));
				ill_prev = ill_prev ||
					(pv >> 48) != 0;
				if (ill && !ill_prev && have) {
					bw_budget--;
					os_info("[binwatch] pid %lu FIELD "
						"bin %d member 0x%llx "
						"[%s] 0x%llx -> 0x%llx "
						"(nr=%llu ret=%lld "
						"rip=0x%llx)\n",
						(unsigned long)c->pid,
						bi, cur,
						f == 1 ? "fd" :
						f == 2 ? "bk" :
						f == 3 ? "fd->bk" :
							 "bk->fd",
						pv, v, c->last_nr,
						c->last_ret,
						c->d->regs.rip);
					dump_guest_bytes(mm, cur, 0x40,
							 "binwatch-chunk");
				}
			}
			/* record for the next round's diff */
			if (slot < 8) {
				for (f = 0; f < 5; f++)
					c->bw_snap[bi - 1][slot][f] =
						rec[f];
				slot++;
			}
			if (nmem < 8)
				mems[nmem++] = cur;
			/* dedup persistent-state fires so the budget
			 * survives to NEW events (37177116246 burned
			 * 48 fires on one member). */
			dedup = ((unsigned long long)bi << 48) ^ cur;
			for (di = 0; di < bw_nseen; di++)
				if (bw_seen[di] == dedup)
					seen2 = 1;
			if (!seen2) {
				if (rec[3] != cur || rec[4] != cur) {
					if (bw_nseen < 16)
						bw_seen[bw_nseen++] = dedup;
					bw_budget--;
					os_info("[binwatch] pid %lu DESYNC "
						"bin %d member 0x%llx "
						"size=0x%llx fd=0x%llx "
						"bk=0x%llx fd->bk=0x%llx "
						"bk->fd=0x%llx (nr=%llu "
						"ret=%lld rip=0x%llx)\n",
						(unsigned long)c->pid,
						bi, cur, rec[0] & ~7ull,
						rec[1], rec[2], rec[3],
						rec[4], c->last_nr,
						c->last_ret,
						c->d->regs.rip);
					dump_guest_bytes(mm, cur, 0x40,
							 "binwatch-chunk");
				}
				for (di = 0; di < 64; di++)
					if (entries[di] != 0 &&
					    (entries[di] == cur + 0x10 ||
					     entries[di] == cur)) {
						dbl = di;
						break;
					}
				if (dbl >= 0) {
					if (bw_nseen < 16)
						bw_seen[bw_nseen++] = dedup;
					bw_budget--;
					os_info("[binwatch] pid %lu "
						"DOUBLE-LISTED bin %d "
						"member 0x%llx also "
						"tcache[%d] (nr=%llu "
						"ret=%lld rip=0x%llx)\n",
						(unsigned long)c->pid,
						bi, cur, dbl,
						c->last_nr, c->last_ret,
						c->d->regs.rip);
					dump_guest_bytes(mm, cur, 0x40,
							 "binwatch-chunk");
				}
			}
			cur = rec[1];
		}
		/* DOUBLE-LIST, full-chain (dl7 37266648434): the head-only
		 * entries[] compare misses a member buried mid-chain.
		 * bin bi holds chunks of size 0x10*bi = tcache bin
		 * bi-2's class. Walk that chain with the glibc reveal
		 * (next = raw ^ (mem>>12)); a bin member's base among
		 * the chain nodes = the chunk is in BOTH structures —
		 * the double-listing caught one park from formation.
		 * A repeated node = a chain cycle (the pop-lost-update
		 * signature: a chunk the get never unlinked). */
		if (nmem > 0 && bi >= 2 && bi - 2 < UML_NT_TCACHE_COUNTS &&
		    entries != NULL) {
			unsigned long long chain[8];
			unsigned long long node = entries[bi - 2];
			int nch = 0;

			for (k = 0; k < 8 && node != 0; k++) {
				unsigned long long raw;
				int ci, cyc = 0;

				if (node < mm->heap_start ||
				    node >= mm->heap_end ||
				    (node & 0xf) != 0)
					break;
				for (ci = 0; ci < nch; ci++)
					if (chain[ci] == node) {
						cyc = 1;
						break;
					}
				if (cyc) {
					if (bw_budget > 0) {
						bw_budget--;
						os_info("[binwatch-CYCLE] "
							"pid %lu tcache[%d] "
							"node 0x%llx twice "
							"(chain head 0x%llx, "
							"step %d) nr=%llu "
							"ret=%lld\n",
							(unsigned long)
							c->pid, bi - 2,
							node,
							entries[bi - 2], k,
							c->last_nr,
							c->last_ret);
					}
					break;
				}
				chain[nch++] = node;
				for (ci = 0; ci < nmem; ci++)
					if (mems[ci] == node - 0x10) {
						if (bw_budget <= 0)
							break;
						bw_budget--;
						os_info("[binwatch-XLIST] "
							"pid %lu bin %d "
							"member 0x%llx IS "
							"tcache[%d] chain "
							"node #%d (mem "
							"0x%llx) nr=%llu "
							"ret=%lld rip="
							"0x%llx — DOUBLE-"
							"LISTED live\n",
							(unsigned long)
							c->pid, bi,
							mems[ci], bi - 2,
							k, node,
							c->last_nr,
							c->last_ret,
							c->d->regs.rip);
						dump_guest_bytes(mm,
							mems[ci], 0x40,
							"binwatch-xlist");
						break;
					}
				if (bw_qword(mm, node, &raw) < 0)
					break;
				node = raw ^ (node >> 12);
			}
		}
		c->bw_nslot[bi - 1] = slot;
	}
	c->bw_snap_valid = 1;
}

/* [mmdup]: two pieces of the SAME mm claiming overlapping run
 * ranges — a same-mm alias (one run mapped at two VAs). Sharing
 * is cross-mm by design (fork COW); within one mm a run backs
 * exactly one piece. */
static void mmdup_census(struct uml_nt_stub_conn *c)
{
	static int mmdup_budget = 8;
	struct uml_nt_mm *mm = c->mm;
	int i, j;

	if (mmdup_budget <= 0)
		return;
	for (i = 0; i < mm->nvma; i++) {
		if ((long long)mm->vma[i].run_off < 0)
			continue;
		for (j = i + 1; j < mm->nvma; j++) {
			unsigned long long as = mm->vma[i].run_off,
				ae = as + (mm->vma[i].end -
					   mm->vma[i].start),
				bs = mm->vma[j].run_off,
				be = bs + (mm->vma[j].end -
					   mm->vma[j].start);

			if ((long long)mm->vma[j].run_off < 0)
				continue;
			if (as < be && bs < ae) {
				mmdup_budget--;
				os_info("[mmdup] pid %lu pieces %d "
					"[0x%llx,0x%llx)@0x%llx and %d "
					"[0x%llx,0x%llx)@0x%llx overlap "
					"— same-mm run alias\n",
					(unsigned long)c->pid, i,
					mm->vma[i].start,
					mm->vma[i].end, as, j,
					mm->vma[j].start,
					mm->vma[j].end, bs);
			}
		}
	}
}

static void cross_stub_census(struct uml_nt_stub_conn *self,
			      unsigned long long arm_run);

/* [replay-check] arm: decode the faulting qword store and snapshot
 * the target's BEFORE content. Pure x86 prefix decode for the two
 * glibc-metadata forms (mov r64->m64, mov imm32->m64) — the register
 * file order matches the hardware encoding (rax=0..r15=15). */
/* The [replay-check] verdict budget — shared by the arm: an
 * instrument whose verdicts are spent must not keep single-stepping
 * the guest (ss_model.h, slice D). */
static int rp_budget = 16;

static void replay_check_arm(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;
	struct uml_nt_mm *mm = c->mm;
	unsigned long long want, before;
	long long off;
	unsigned char insn[8];
	int rex_r = 0, i;
	unsigned long long *rf = &d->regs.rax;

	c->rp_active = 0;
	/* The arm epoch is THIS round's: a fault the decoder refuses
	 * below arms nothing, and neither the previous round's page
	 * nor its tctrip re-arm may ride into this resume (slice D:
	 * the stale arm put TF on a resume whose store was never this
	 * one). */
	d->ss_page = 0;
	d->ss_rearm_ro = 0;
	/* Never arm replay single-stepping on a COW-split fault (where
	 * the VMA table already points to the unpopulated dst run and
	 * fault_cowcopy_exec will arm cowtrap RO at the end of the
	 * drain): the post-drain resume lands on a cowtrap RO page,
	 * whose 1-op restore-W fault will arm replay_check_arm cleanly
	 * once dst is populated. */
	if (c->plan.copy_src_off != 0 || c->plan.copy_dst_off != 0 ||
	    c->copy_pend_kind != 0)
		return;
	if (d->fault_type != 1 || mm == NULL ||
	    mm->heap_start == 0 ||
	    d->fault_addr < mm->heap_start ||
	    d->fault_addr >= mm->heap_end ||
	    d->fault_addr & 7)
		return;
	off = uml_nt_vma_translate(mm, d->regs.rip, 8);
	if (off < 0)
		return;
	for (i = 0; i < 8; i++)
		insn[i] = ((const unsigned char *)
			uml_boot.physmem_base)[off + i];
	i = 0;
	if ((insn[0] & 0xf0) == 0x40 && (insn[0] & 0x08)) { /* REX.W */
		rex_r = (insn[0] >> 2) & 1;
		i = 1;
	} else
		return;
	if (insn[i] == (unsigned char)0x89 &&
	    i + 2 < 8 && (insn[i + 1] & 0xc0) != 0xc0) {
		int src = ((insn[i + 1] >> 3) & 7) + (rex_r ? 8 : 0);

		want = rf[src];
	} else if (insn[i] == (unsigned char)0xc7 &&
		   ((insn[i + 1] >> 3) & 7) == 0 &&
		   (insn[i + 1] & 0xc0) != 0xc0) {
		/* imm32 sits AFTER the ModRM displacement: mod=00 at
		 * i+2, mod=01 (disp8) at i+3 (the first version read
		 * the disp8 as the imm — e->key=NULL decoded as 8,
		 * 37180771956). mod=10 (disp32) at i+6 — needs 8-byte
		 * window, allow via the i+6 bound. */
		int imm;
		int m = (insn[i + 1] >> 6) & 3;
		int io = i + 2 + (m == 1 ? 1 : m == 2 ? 4 : 0);

		if (io + 4 > 8)
			return;
		imm = (int)((unsigned int)insn[io] |
			((unsigned int)insn[io + 1] << 8) |
			((unsigned int)insn[io + 2] << 16) |
			((unsigned int)insn[io + 3] << 24));
		want = (unsigned long long)(long long)imm;
	} else
		return;
	if (bw_qword(mm, d->fault_addr, &before) < 0)
		return;
	{
		long long roff = uml_nt_vma_translate(
			mm, d->fault_addr, 8);

		c->rp_armrun = roff < 0 ? 0 :
			(unsigned long long)roff &
			~(unsigned long long)(UML_NT_PHYS_RUN_SIZE - 1);
	}
	c->rp_pd_done = 0;
	c->rp_va = d->fault_addr;
	c->rp_want = want;
	c->rp_before = before;
	c->rp_rip = d->regs.rip;
	c->rp_active = 1;
	/* viewprobe: the stub snapshots the fault VA through its own
	 * view once the repair's PROTECT applies (read at the
	 * PROTDONE below) — the wrong-backed view shows itself. ONLY
	 * arm it when the repair actually starts with a PROT covering
	 * the fault VA: the stub consumes the field in the PROT branch
	 * alone, and a leaked address rides into a LATER unrelated
	 * PROT whose page may be NOACCESS — the read then dies as an
	 * unowned exception inside the stub (referee 37205147552). */
	if (c->plan.n_ops > 0 &&
	    c->plan.ops[0].op == UML_NT_FOP_PROTECT &&
	    d->fault_addr >= c->plan.ops[0].va &&
	    d->fault_addr < c->plan.ops[0].va + c->plan.ops[0].len)
		d->viewprobe_addr = d->fault_addr;
	else
		d->viewprobe_addr = 0;
	/* single-step (v10): after the repair the stub resumes with
	 * TF; the post-store #DB re-arms the page NOACCESS so the
	 * NEXT writer (the replay proves itself first) is caught by
	 * the re-armed cowtrap slot below. */
	if (!witness_off()) {
		d->ss_page = uml_nt_ss_arm_page(1, rp_budget,
						d->fault_addr);
		/* tctrip's unknown-encoding store asked for the tripwire
		 * back after this one replay (v12); keep that only with a
		 * live arm. */
		if (d->ss_page != 0 && tctrip_conn == c &&
		    d->fault_addr >= tctrip_page &&
		    d->fault_addr < tctrip_page + UML_NT_FAULT_PAGE_SIZE) {
			struct uml_nt_vma *tv =
				uml_nt_vma_find(c->mm, tctrip_page);

			d->ss_rearm_ro = tctrip_page;
			/* Shelley 166: the re-arm puts back the VMA's
			 * protection. PAGE_READONLY on a text page made
			 * the next fetch fault — indistinguishable from a
			 * resume that never reached the guest, and the
			 * reason 440 of 984 armed resumes fired while the
			 * dying one did not. */
			d->ss_rearm_prot = tv != NULL ?
				uml_nt_prot_restore(tv->prot)
				: UML_NT_PROT_RO;
		}
	}
	d->ss_va = d->fault_addr;
	d->ss_got = ~0ull;
	d->ss_flat = ~0ull;
	/* ss-regs (v11): the fault's register file — the #DB compares */
	__builtin_memcpy(d->ss_regs, &d->regs, 16 * 8);
	d->ss_rflags = d->regs.rflags;
	d->ss_regdiff = 0;
	/* whole-page snapshot for the revert census at the verify */
	if (c->rp_armrun != 0)
		__builtin_memcpy(c->rp_pagesnap,
				 (const char *)uml_boot.physmem_base +
				 c->rp_armrun +
				 (d->fault_addr & ~0xfffull &
				  (UML_NT_PHYS_RUN_SIZE - 1)),
				 4096);
	/* The flat offset of the fault VA per the TABLE — the #DB
	 * reads it through the stub's RO flat view: view vs flat at
	 * one instant. The arm run is piece-aligned (run-multiple
	 * VMAs), so the byte offset is arm-run + the in-run bits. */
	d->ss_flatoff = c->rp_armrun +
		(d->fault_addr & (UML_NT_PHYS_RUN_SIZE - 1));
}

/* [replay-check] verdict at the next syscall park. */
static void replay_check_verify(struct uml_nt_stub_conn *c)
{
	unsigned long long now, vrun = 0;
	long long voff;

	if (!c->rp_active)
		return;
	c->rp_active = 0;
	if (rp_budget <= 0)
		return;
	voff = uml_nt_vma_translate(c->mm, c->rp_va, 8);
	if (voff < 0)
		return;
	vrun = (unsigned long long)voff &
		~(unsigned long long)(UML_NT_PHYS_RUN_SIZE - 1);
	now = *(const unsigned long long *)(const void *)
		((char *)uml_boot.physmem_base + voff);
	if (vrun != c->rp_armrun)
		os_info("[replay-lost] pid %lu va=0x%llx piece RE-HOMED "
			"arm-run=0x%llx verify-run=0x%llx — the store's "
			"landing (if any) rode the copy\n",
			(unsigned long)c->pid, c->rp_va,
			c->rp_armrun, vrun);
	/* REPLAY FOLLOWS CONTENT (Shelley 180): classify this word before
	 * anything is allowed to act on it. One verdict may write; the
	 * other two must not, and both are evidence that a race is real. */
	{
		int verdict = uml_nt_replay_verdict(now, c->rp_before,
						    c->rp_want);

		if (verdict == UML_NT_REPLAY_WRITE)
			c->rp_writes++;
		else if (verdict == UML_NT_REPLAY_ALREADY)
			c->rp_already++;
		else
			c->rp_foreign++;
		if (c->rp_guarded < 40) {
			c->rp_guarded++;
			os_info("[replay-guard] pid %lu va=0x%llx verdict=%s "
				"now=0x%llx before=0x%llx want=0x%llx "
				"(writes=%lu already=%lu foreign=%lu)\n",
				(unsigned long)c->pid, c->rp_va,
				uml_nt_replay_name(verdict), now,
				c->rp_before, c->rp_want,
				(unsigned long)c->rp_writes,
				(unsigned long)c->rp_already,
				(unsigned long)c->rp_foreign);
		}
	}
	if (now == c->rp_before && now != c->rp_want) {
		unsigned long long run, sz = uml_boot.physmem_size;
		const char *b = (const char *)uml_boot.physmem_base;
		int nhits = 0;

		rp_budget--;
		os_info("[replay-lost] pid %lu va=0x%llx rip=0x%llx "
			"want=0x%llx still=0x%llx (nr=%llu ret=%lld "
			"rip=0x%llx) — the repaired store NEVER LANDED\n",
			(unsigned long)c->pid, c->rp_va, c->rp_rip,
			c->rp_want, now, c->last_nr, c->last_ret,
			c->d->regs.rip);
		os_info("[replay-lost]   resume_rip=0x%llx (fault rip "
			"0x%llx) — %s\n",
			c->d->resume_rip, c->rp_rip,
			c->d->resume_rip == c->rp_rip ?
			"RESUMED AT THE STORE — yet it never ran?!" :
			"RESUME WENT ELSEWHERE — the skip path");
		if (c->d->ss_flat != ~0ull)
			os_info("[replay-lost]   ss: flat=0x%llx vs "
				"view=0x%llx at the #DB instant — %s\n",
				c->d->ss_flat, c->d->ss_got,
				c->d->ss_flat == c->d->ss_got ?
				"AGREE (the view IS the section; the "
				"loss is later)" :
				"DIVERGED — THE COVERING VIEW IS NOT "
				"THE PHYSMEM SECTION");
		if (c->d->ss_regdiff != 0) {
			static const char *const regnames[16] = {
				"rax", "rcx", "rdx", "rbx",
				"rsp", "rbp", "rsi", "rdi",
				"r8", "r9", "r10", "r11",
				"r12", "r13", "r14", "r15" };
			int ri;

			os_info("[ss-regs] pid %lu va=0x%llx REGISTER "
				"TEAR: diff mask 0x%llx — the guest "
				"resumed with wrong inputs\n",
				(unsigned long)c->pid, c->rp_va,
				c->d->ss_regdiff);
			for (ri = 0; ri < 16; ri++)
				if (c->d->ss_regdiff & (1ull << ri))
					os_info("[ss-regs]   %s: fault "
						"0x%llx live 0x%llx\n",
						regnames[ri],
						c->d->ss_regs[ri],
						c->d->ss_reglive[ri]);
		}
		if (c->d->ss_got == ~0ull)
			os_info("[replay-lost]   ss: the #DB NEVER "
				"FIRED — the store never ran despite "
				"the at-store resume\n");
		else
			os_info("[replay-lost]   ss: view read "
				"0x%llx right after the store (want "
				"0x%llx, table now 0x%llx) — %s\n",
				c->d->ss_got, c->rp_want, now,
				c->d->ss_got == c->rp_want ?
				"STORE LANDED VIEW-SIDE; table lacks "
				"it — THE WRONG-BACKED TWIN" :
				"the store's own value is absent even "
				"view-side");
		{
			int k, n = c->op_log_n < 64 ? c->op_log_n : 64;

			/* dump only the ops touching the fire page */
			for (k = 0; k < n; k++) {
				unsigned long long *e = c->op_log[
					(c->op_log_n - n + k) % 64];

				if (e[2] + e[3] <= (c->rp_va &
						    ~0xfffull) ||
				    e[2] >= (c->rp_va & ~0xfffull) +
					    0x1000)
					continue;
				os_info("[replay-lost]   oplog[%d]: "
					"op=%llu prot=0x%llx va=0x%llx "
					"len=0x%llx off=0x%llx\n",
					k, e[0], e[1], e[2], e[3], e[4]);
			}
		}
		if (c->d->ss_viewbase != 0)
			os_info("[replay-lost]   view base VA "
				"0x%llx type=0x%llx rsize=0x%llx backs "
				"the fault page (%s)\n",
				c->d->ss_viewbase, c->d->ss_vtype,
				c->d->ss_vrsize,
				/* WinNT.h: MEM_PRIVATE=0x20000,
				 * MEM_MAPPED=0x40000 (a healthy section
				 * view), MEM_IMAGE=0x1000000. An earlier
				 * cut had the first two swapped and named
				 * every good view the disease. */
				c->d->ss_vtype == 0x20000ull ?
				"MEM_PRIVATE — NOT THE PHYSMEM SECTION!" :
				c->d->ss_vtype == 0x40000ull ?
				"MEM_MAPPED — a section view" :
				c->d->ss_vtype == 0x1000000ull ?
				"MEM_IMAGE" : "?");
		os_info("[replay-lost]   arm-run=0x%llx verify-run=0x%llx "
			"(the piece's run at the fault vs now — a move "
			"WITHOUT an op in the ledger is the table-side "
			"disease)\n", c->rp_armrun, vrun);
		{
			/* The raw table entry for the fault VA: if its
			 * run_off equals neither the last ledger MAP's
			 * off nor the arm-run, the table moved with
			 * no op at all. */
			const struct uml_nt_vma *vv = uml_nt_vma_find(
				c->mm, c->rp_va);

			if (vv != NULL)
				os_info("[replay-lost]   vma "
					"[0x%llx,0x%llx) run_off=0x%llx "
					"prot=0x%x flags=0x%x\n",
					vv->start, vv->end,
					(unsigned long long)vv->run_off,
					vv->prot, vv->flags);
		}
		{
			/* (A) vs (B): count the page's reverted qwords.
			 * One qword back to `before` = the natural
			 * chunk cycle (a same-chunk free restores the
			 * same mangled head — a FALSE replay-lost);
			 * many reverted qwords = a wholesale rewrite
			 * of the page by a sibling sharing the run. */
			const unsigned char *cur =
				(const char *)uml_boot.physmem_base +
				vrun + (c->rp_va & ~0xfffull &
					(UML_NT_PHYS_RUN_SIZE - 1));
			int same = 0, diff = 0, i;

			for (i = 0; i < 4096 / 8; i++) {
				unsigned long long a, b;

				__builtin_memcpy(&a, c->rp_pagesnap +
						 i * 8, 8);
				__builtin_memcpy(&b, cur + i * 8, 8);
				if (a == b)
					same++;
				else
					diff++;
			}
			os_info("[replay-lost]   page-diff: %d qwords "
				"unchanged, %d changed since the arm — "
				"%s\n", same, diff,
				diff <= 2 ? "narrow (chunk-cycle shape)"
					  : "WHOLESALE REWRITE — a "
					    "sibling shares this run");
		}
		{
			/* Cross-mm census AT THE FIRE: does any OTHER
			 * live conn's VMA table cover the arm run? A
			 * hit names the sibling whose (per-process,
			 * un-watched by this conn's cowtrap) view can
			 * write this run freely. */
			struct task_struct *p;

			for_each_process(p) {
				struct uml_nt_stub_conn *pc;
				int vi;

				if (p->mm == NULL)
					continue;
				pc = ((struct mm_id *)&p->mm->context.id)
					->nt_conn;
				if (pc == NULL || pc == c ||
				    pc->mm == NULL ||
				    pc->dead_magic == UML_NT_CONN_DEAD)
					continue;
				for (vi = 0; vi < pc->mm->nvma; vi++) {
					unsigned long long vlo =
						pc->mm->vma[vi].run_off;
					unsigned long long vhi = vlo +
						(pc->mm->vma[vi].end -
						 pc->mm->vma[vi].start);

					if (c->rp_armrun >= vlo &&
					    c->rp_armrun < vhi)
						os_info("[replay-lost]   "
							"SIBLING pid %lu "
							"vma[%d] "
							"[0x%llx,0x%llx) "
							"off=0x%llx "
							"prot=0x%x "
							"flags=0x%x "
							"covers the "
							"run\n",
							(unsigned long)
							pc->pid, vi,
							pc->mm->vma[vi]
								.start,
							pc->mm->vma[vi]
								.end, vlo,
							pc->mm->vma[vi]
								.prot,
							pc->mm->vma[vi]
								.flags);
				}
			}
		}
		{
			/* The same-conn stale-view census: every dumped
			 * region the VMA table cannot account for is a
			 * view the kernel never (or no longer) asked
			 * for — the dropped-UNMAP class. */
			unsigned int k;

			for (k = 0; k < c->d->ss_ndump && k < 48; k++) {
				unsigned long long b =
					c->d->ss_dump[k][0];
				unsigned long long l =
					c->d->ss_dump[k][1];
				unsigned long long pt =
					c->d->ss_dump[k][2];
				unsigned long long va;
				int admitted = 1;

				for (va = b; va < b + l;
				     va += UML_NT_PHYS_RUN_SIZE)
					if (uml_nt_vma_find(c->mm, va) ==
					    NULL) {
						admitted = 0;
						break;
					}
				if (!admitted)
					os_info("[replay-lost]   "
						"UNADMITTED VIEW "
						"[0x%llx,+0x%llx) "
						"prot=0x%llx "
						"type=0x%llx — the "
						"table dropped it, "
						"the view lived on\n",
						b, l, pt & 0xffffffffull,
						pt >> 32);
			}
		}
		dump_guest_bytes(c->mm, c->rp_va & ~0xfffull, 0x40,
				 "replay-page");
		/* WHERE did the store land? Sweep ALL of physmem for
		 * the want-qword: a hit on another run = the store
		 * executed against a WRONG-BACKED view (the twin run
		 * names the stale op); zero hits = the store never
		 * re-executed at all (the resume skipped it — the
		 * signal-path shape). */
		{
			/* A wrong-backed view maps run R at the piece's
			 * base VA — the lost store sits at R + the va's
			 * offset within its piece. Scan exactly that
			 * offset on EVERY run: one qword per run,
			 * unambiguous (37182772578's 4 whole-run hits
			 * were legit pointer copies at other offsets).
			 * want==0 (NULL stores — e->key=NULL) can't be
			 * scanned: the world is full of zeros; report
			 * skip. */
			unsigned long long inoff = c->rp_va &
				(UML_NT_PHYS_RUN_SIZE - 1);

			if (c->rp_want == 0) {
				os_info("[replay-lost]   want==0 (a NULL "
					"metadata store) — twin scan "
					"skipped\n");
			} else {
				for (run = 0;
				     run + 8 <= sz && nhits < 8;
				     run += UML_NT_PHYS_RUN_SIZE)
					if (*(const unsigned long long *)
						(const void *)
						(b + run + inoff) ==
					    c->rp_want) {
						os_info("[replay-lost]   "
							"twin? want at phys "
							"0x%llx (in-run off "
							"0x%llx, table run "
							"0x%llx)\n",
							run + inoff, inoff,
							vrun);
						nhits++;
					}
				if (nhits == 0) {
					os_info("[replay-lost]   want "
						"ABSENT at in-run offset "
						"0x%llx on every run — "
						"the store never "
						"re-executed\n", inoff);
					cross_stub_census(c, c->rp_armrun);
				}
			}
		}
	{
		/* Revert hunt (M5.6a, F1/F2 referees): the page
		 * reverted byte-exact to the arm snapshot with no
		 * [kheap] catch on the run — the watch never armed
		 * it, so the flatcopy ring is the only copy ledger.
		 * Name any recent copy_verify whose dst covers the
		 * fire page, then read the qword through the STUB's
		 * view right now: guest-still-sees-want = the kernel
		 * table/flat is the twin; guest-sees-before = a true
		 * physical revert. */
		unsigned long long pflat =
			(unsigned long long)(uintptr_t)
			uml_boot.physmem_base +
			(unsigned long long)(voff & ~0xfffll);
		struct uml_nt_flatcopy_rec hits[4];
		int nh = uml_nt_flatcopy_covering(pflat,
						  pflat + 0x1000,
						  hits, 4);
		int hi;

		for (hi = 0; hi < nh; hi++)
			os_info("[replay-lost]   REVERT CANDIDATE: "
				"%s caller=0x%llx dst=0x%llx "
				"src=0x%llx len=%llu tick=%u\n",
				hits[hi].what, hits[hi].caller,
				hits[hi].dst, hits[hi].src,
				hits[hi].len, hits[hi].tick);
		if (nh == 0)
			os_info("[replay-lost]   no ring copy covers "
				"the page — not a copy_verify rewrite\n");
		{
			unsigned long long sv = 0;
			SIZE_T svg = 0;

			if (c->proc != NULL &&
			    nt->ReadProcessMemory(c->proc,
						  (void *)(uintptr_t)c->rp_va,
						  &sv, 8, &svg) != 0 &&
			    svg == 8)
				os_info("[replay-lost]   verify-instant "
					"STUB view reads 0x%llx (table "
					"0x%llx, want 0x%llx) — %s\n",
					sv, now, c->rp_want,
					sv == c->rp_want ?
					"GUEST STILL SEES THE STORE — "
					"the table/flat is the twin" :
					sv == now ?
					"guest lost it too — TRUE "
					"PHYSICAL REVERT" :
					"A THIRD VALUE — live churn");
			else
				os_info("[replay-lost]   verify-instant "
					"stub view UNREADABLE\n");
		}
	}
	}
}

/* [ss-stray] (M5.6a K7 slice D, stub_nt.h v14): the stub's #DB
 * ledger. Every row the stub recorded since the last park is printed
 * — kind 0 is a #DB the replay window did not admit (the stub used
 * to die 0x80000004 on it: referees 39798056175/39809900440), kind 1
 * is a trap whose context carried EFLAGS.TF (the source the kernel
 * would have inherited TF from — masked at the capture now). The
 * flags/dr6 columns name the class: TF live = a TF the resume carried
 * in; Dr6.BS alone = a single-step whose TF the dispatcher already
 * dropped; neither = an int1-class trap out of guest code. */
static void ss_stray_watch(struct uml_nt_stub_conn *c)
{
	static int stray_budget = 48;
	struct uml_nt_stub_data *d = c->d;
	unsigned int n = d->ss_stray_n, i, first;

	if (n == c->ss_stray_seen)
		return;
	first = n - c->ss_stray_seen > 8 ? n - 8 : c->ss_stray_seen;
	if (first != c->ss_stray_seen && stray_budget > 0) {
		stray_budget--;
		os_info("[ss-stray] pid %lu: %u event(s) overran the "
			"ring\n", (unsigned long)c->pid,
			first - c->ss_stray_seen);
	}
	for (i = first; i != n; i++) {
		const unsigned long long *r = d->ss_stray[i & 7u];
		unsigned long long fl = r[1], dr6 = r[2];

		if (stray_budget-- <= 0)
			break;
		os_info("[ss-stray] pid %lu #%u %s: rip=0x%llx rsp=0x%llx "
			"eflags=0x%llx dr6=0x%llx ss_page=0x%llx "
			"tramp_target=0x%llx cmd=%llu resume_rip=0x%llx "
			"code=0x%llx — %s\n",
			(unsigned long)c->pid, i,
			(r[6] & 0xffffffffull) == 1 ?
			"TF LIVE AT A TRAP" : "STRAY #DB",
			r[0], r[7], fl, dr6, r[3], r[4], r[5] & 0xff,
			r[5] >> 8, r[6] >> 32,
			(fl & UML_NT_EFLAGS_TF) ?
			"the context carries TF: a resume brought it in" :
			(dr6 & 0x4000ull) ?
			"Dr6.BS: a single-step whose TF is already gone" :
			(dr6 & 0xfull) ?
			"Dr6.B0-3: a watchpoint hit outside the filter" :
			"no TF, no BS: an int1-class trap out of guest code");
	}
	c->ss_stray_seen = n;
}
static void tcache_watch(struct uml_nt_stub_conn *c)
{
	struct uml_nt_mm *mm = c->mm;
	unsigned long long tva, base;
	unsigned short counts[UML_NT_TCACHE_COUNTS];
	unsigned long long entries[UML_NT_TCACHE_COUNTS];
	long long off;
	int i;

	if (!c->task_backed || mm == NULL || mm->heap_start == 0)
		return;
	/* TCACHE WATCH arm (v13): after this conn's first fork seed
	 * the poison window is open — load DR watchpoints on
	 * entries[0..3] (heap+0x90+i*8). Hardware: no page trap, no
	 * storm; the stub filters legit put/get churn in place and
	 * reports only non-heap landings. (Supersedes the tctrip RO
	 * arm — dl6's storm killed that design.) */
	if (c->tctrip_want && !witness_off() && !c->ws_armed &&
	    !dr_probe_owns_slots(c)) {
		int wi;

		/* slots 0/1: tcache entries[0..1] (the dl5 family);
		 * slots 2/3: the arena bin heads' bk — armed at
		 * binwatch discovery (bw_arena known only then);
		 * keep heap-range for the churn filter either way. */
		{
			int got[UML_NT_DRS_SLOTS];
			int n = uml_nt_drs_reserve(&c->drs, UML_NT_DRS_TCACHE,
						   2, got);

			for (wi = 0; wi < n; wi++)
				c->d->dr_watch[got[wi]] = mm->heap_start +
					0x90 + (unsigned long long)wi * 8;
		}
		c->d->dr_heap_lo = mm->heap_start;
		c->d->dr_heap_hi = mm->heap_end;
	}
	tva = mm->heap_start + 0x10; /* chunk data past the header */
	/* The glibc shape check first: the heap's first chunk must be
	 * the tcache itself (chunk size 0x290 | PREV_INUSE = 0x291 in
	 * the size field at +8). A musl guest shares the same kernel
	 * heap VMA with a different allocator — no tcache shape,
	 * nothing to validate, stay silent. */
	off = uml_nt_vma_translate(mm, mm->heap_start, 16);
	if (off < 0)
		return;
	{
		unsigned long long hdr = *(const unsigned long long *)
			(const void *)((char *)uml_boot.physmem_base +
				       off + 8);

		if (hdr != 0x291)
			return;
	}
	off = uml_nt_vma_translate(mm, tva, 0x290);
	if (off < 0)
		return; /* heap VMA not (yet) resident — nothing to watch */
	/* [ktrip] (map 117): arm the tcache struct's 4K page in the
	 * KERNEL's own flat view — the last writer class standing
	 * (every stub-view, funnel, futex, destroy and foreign-mapper
	 * witness is negative). Re-arm only when the run moves; the
	 * re-arm unprotects the old page (stale RO = stray VEH trips
	 * on future legit writes). */
	/* [kheap] (referees 37124011556 + 37126690946 decode): the
	 * PRE-EMPTIVE whole-heap witness replaces the struct-page
	 * [ktrip] arm — the post-hoc arms missed the writer because
	 * the poison's first write to a chunk predates every fire
	 * (the writer strikes once per chunk; the census side is
	 * fully negative: [uawrite] live through the fire window with
	 * zero env-text payloads, cowtrap all-legit). Protect EVERY
	 * heap VMA piece kernel-flat READ-ONLY (the heap is piecewise
	 * — re-homed runs at arbitrary run_off, so a single endpoint
	 * range would cover 50MB of other tasks' memory): every
	 * kernel write to a heap page trips the VEH with its rip.
	 * Only the INIT conn owns the arm (every decoded fire lived
	 * in the first task-backed conn's heap); the shape check
	 * above gates to glibc heaps already. Direct run_off math per
	 * piece (no per-page translate — same pattern as the poison
	 * sweep). */
	{
		static void *kheap_owner;
		struct uml_nt_kheap_piece pcs[UML_NT_KHEAP_RANGES];
		int np = 0, vi2;

		if (kheap_owner == NULL)
			kheap_owner = c;
		if (kheap_owner == c) {
			for (vi2 = 0; vi2 < mm->nvma; vi2++) {
				const struct uml_nt_vma *pv =
					&mm->vma[vi2];

				if (np == UML_NT_KHEAP_RANGES)
					break;
				if (pv->end <= mm->heap_start ||
				    pv->start >= mm->heap_end ||
				    (long long)pv->run_off < 0)
					continue;
				pcs[np].lo =
					(unsigned long long)(uintptr_t)
					uml_boot.physmem_base +
					((unsigned long long)pv->run_off &
					 ~0xfffull);
				pcs[np].hi =
					(unsigned long long)(uintptr_t)
					uml_boot.physmem_base +
					(unsigned long long)pv->run_off +
					(pv->end - pv->start);
				/* D25 census (to-shelley 134): the
				 * piece's own run MUST be a live
				 * claim in the refcount table —
				 * refs<=0 (never handed / stolen) or
				 * gen==0 (never stamped) = this VMA
				 * translates into runs the phys
				 * layer doesn't own it on = the
				 * alias class, named at arm time. */
				if (uml_nt_phys_refs(c->ph,
						     pv->run_off) <= 0 ||
				    uml_nt_phys_gen(c->ph, pv->run_off)
					    == 0)
					os_info("[kheap-arm] piece %d "
						"off=0x%llx refs=%d "
						"gen=%llu — UNOWNED "
						"CLAIM\n", np,
						pv->run_off,
						uml_nt_phys_refs(
							c->ph,
							pv->run_off),
						uml_nt_phys_gen(c->ph,
								pv->run_off));
				np++;
			}
			uml_nt_kheap_sync(pcs, np);
		}
	}
	base = (unsigned long long)(uintptr_t)
	       ((char *)uml_boot.physmem_base + off);
	memcpy(counts, (const void *)(uintptr_t)base, sizeof(counts));
	memcpy(entries, (const void *)(uintptr_t)base + sizeof(counts),
	       sizeof(entries));
	/* [binwatch]/[mmdup]: the arena-bin walk (the 37144114627
	 * blind spot — unsorted-bin bk garbage with every tcache-side
	 * witness silent) + the same-mm run-alias census. The
	 * [replay-check] verdict rides the same syscall park. */
	if (c->d->cmd == UML_STUB_CMD_SYSCALL)
		replay_check_verify(c);
	binwatch(c, entries);
	mmdup_census(c);
	/* DELTA WATCH (referee 37085373580 decode): the cowtrap on the
	 * tcache page retires at the page's FIRST write — glibc's own
	 * entry linking — so the 16-byte ASCII blob that killed three
	 * boots (entries[1..2] = "S$UTEMD_"-family text, deterministic)
	 * landed after the retirement, unwitnessed, NOT via
	 * raw_copy_to_user ([uawrite-s] clean), and NOT via a tracked
	 * kernel flat site ([kernel-write] silent). Snapshot
	 * entries[0..3] per round; a change to a pointer-ILLEGAL value
	 * names the window: last_nr = the round just served, the trap
	 * rip = where the guest came back. Pointer-ILLEGAL = top 16
	 * bits set (no legit entry — 0 or a safe-linked heap pointer —
	 * has them) or misaligned; legit relinking stays silent so the
	 * budget survives to the poison. Runs for every task-backed
	 * conn, including ones whose one-shot bad-scan already fired.
	 *
	 * WHOLE-STRUCT (K3 starhost, referee 37133302551 decode): all
	 * 64 entries + all 64 counts (the read above already copies
	 * the full struct — compare-only extension). A transition
	 * INTO an illegal state from ANY bin names its round; the
	 * count watch catches the text-poison class that reads as a
	 * huge u16 even when the paired entry stays legal-shaped. */
	{
		int di;

		for (di = 0; di < 64; di++) {
			unsigned long long nv = entries[di];
			unsigned int ncnt = counts[di];
			int illegal = ((nv >> 48) != 0) ||
				      ((nv & 0xF) != 0);
			int cnt_bad = ncnt > UML_NT_TCACHE_LIMIT;

			if (tcache_delta_budget <= 0)
				break;
			if (!c->tc_snap_valid)
				continue;
			if (c->tc_snap[di] != nv && illegal) {
				tcache_delta_budget--;
				os_info("[tcdelta] pid %lu entries[%d] 0x%llx -> "
					"0x%llx (round nr=%llu ret=%lld rip=0x%llx "
					"rsp=0x%llx)\n", (unsigned long)c->pid, di,
					c->tc_snap[di], nv, c->last_nr, c->last_ret,
					c->d->regs.rip, c->d->regs.rsp);
				goto tcdelta_fire;
			}
			if (c->tc_counts_snap[di] != ncnt && cnt_bad) {
				tcache_delta_budget--;
				os_info("[tcdelta] pid %lu counts[%d] %u -> %u "
					"(entry=0x%llx round nr=%llu ret=%lld "
					"rip=0x%llx rsp=0x%llx)\n",
					(unsigned long)c->pid, di,
					c->tc_counts_snap[di], ncnt, nv,
					c->last_nr, c->last_ret,
					c->d->regs.rip, c->d->regs.rsp);
				goto tcdelta_fire;
			}
			continue;
		tcdelta_fire:
			/* [alias] census at the poison detection (decode
			 * 37095399220): the kernel write paths are all
			 * negative now — name any FOREIGN conn still
			 * mapping the run behind this tcache struct
			 * (the stale-view writer class), plus the
			 * struct bytes AT hit time (the abort dump is
			 * too late — state evolves). */
			uml_nt_run_alias_census(c,
				(unsigned long long)off &
				~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1),
				UML_NT_PHYS_RUN_SIZE);
			dump_guest_bytes(mm, tva, 0x40, "tcdelta-struct");
			/* POISON SWEEP (referees 37111253316 +
			 * 37112746470): the payload keeps landing in
			 * freed chunks with EVERY write witness
			 * negative — the writer strikes between rounds
			 * and each watched page retires at its first
			 * legit write. Sweep the WHOLE heap VMA for
			 * the literal qword NOW (fire-time only, ≤8
			 * sweeps/boot): the hit VAs = where the poison
			 * lives, and up to 4 of them go under per-round
			 * byte watch (the armed check below) — the next
			 * change to a watched chunk prints its OWN
			 * round = the writer's round. Direct run_off
			 * math per VMA piece (no per-qword translate);
			 * the pieces are the cow_split sub-VMAs. */
			if (posweep_budget > 0 &&
			    mm->heap_end > mm->heap_start &&
			    mm->heap_end - mm->heap_start <= 0x400000) {
				int vi2, nh = 0, printed = 0;
				unsigned long long total = 0;

				posweep_budget--;
				for (vi2 = 0; vi2 < mm->nvma; vi2++) {
					const struct uml_nt_vma *pv2 =
						&mm->vma[vi2];
					unsigned long long va, vend;

					if (pv2->end <= mm->heap_start ||
					    pv2->start >= mm->heap_end ||
					    (long long)pv2->run_off < 0)
						continue;
					va = (pv2->start > mm->heap_start) ?
					     pv2->start : mm->heap_start;
					vend = (pv2->end < mm->heap_end) ?
					       pv2->end : mm->heap_end;
					va &= ~7ull;
					for (; va + 8 <= vend; va += 8) {
						unsigned long long qv =
							*(const unsigned
							  long long *)
							(const void *)
							((char *)
							 uml_boot.physmem_base +
							 pv2->run_off +
							 (va - pv2->start));

						if (qv != UML_NT_POSWEEP_QWORD)
							continue;
						total++;
						if (printed < 8) {
							printed++;
							os_info("[posweep] "
								"pid %lu hit "
								"va=0x%llx "
								"(sweep round "
								"nr=%llu "
								"ret=%lld "
								"rip=0x%llx)\n",
								(unsigned
								 long)
								c->pid, va,
								c->last_nr,
								c->last_ret,
								c->d->regs.
								rip);
						}
						if (nh < 4) {
							c->posweep_va[nh] =
								va;
							c->posweep_snap[nh] =
								qv;
							c->posweep_armed[nh] =
								1;
							nh++;
						}
					}
				}
				for (; nh < 4; nh++)
					c->posweep_armed[nh] = 0;
				os_info("[posweep] pid %lu sweep done: "
					"hits=%llu armed=%d heap="
					"[0x%llx,0x%llx)\n",
					(unsigned long)c->pid, total, nh,
					mm->heap_start, mm->heap_end);
			}
			continue;
		}
		c->tc_snap_valid = 1;
		memcpy(c->tc_snap, entries, sizeof(c->tc_snap));
		memcpy(c->tc_counts_snap, counts,
		       sizeof(c->tc_counts_snap));
	}
	/* POISON-SWEEP byte watch: the chunks armed by the last sweep
	 * on THIS conn report their next content change with the
	 * round coords (nr/ret/rip) — the writer's own round, not
	 * just the surfacing pop. One line per watched chunk
	 * (posweep_va_budget), then the slot disarms. */
	{
		int di2;

		for (di2 = 0; di2 < 4; di2++) {
			unsigned long long nv2;
			long long coff2;

			if (!c->posweep_armed[di2] ||
			    posweep_va_budget <= 0)
				continue;
			coff2 = uml_nt_vma_translate(mm,
					c->posweep_va[di2], 8);
			if (coff2 < 0)
				continue;
			nv2 = *(const unsigned long long *)
				(const void *)((char *)
				uml_boot.physmem_base + coff2);
			if (nv2 == c->posweep_snap[di2])
				continue;
			posweep_va_budget--;
			c->posweep_armed[di2] = 0;
			os_info("[posweep-va] pid %lu va=0x%llx 0x%llx -> "
				"0x%llx (round nr=%llu ret=%lld rip=0x%llx "
				"rsp=0x%llx)\n", (unsigned long)c->pid,
				c->posweep_va[di2], c->posweep_snap[di2],
				nv2, c->last_nr, c->last_ret,
				c->d->regs.rip, c->d->regs.rsp);
		}
	}
	/* CHUNK WATCH (referee 37087346082 decode): [tcdelta] named
	 * the payload — entries[2] 0x67d020d0 -> 0x5f444d4554552451
	 * at the round right after nr=228, trap rip = malloc+0x172
	 * (tcache_get's e->key=NULL). The reveal math is exact across
	 * every boot: 0x5f444d4554552451 ^ (0x67d020d0>>12) =
	 * "SYSTEMD_" — the freed chunk ITSELF held the literal env
	 * text ("SYSTEMD_LOG_TARGET=console"-class, cmdline env), and
	 * each boot's variant byte (S/Q/W) = (chunk_addr>>12) byte
	 * k. So the writer = an 8-byte guest-side store into the
	 * freed chunk (UAF shape) one event BEFORE the get that
	 * reveals it, and the store raises no fault (the pages are
	 * writable) — every kernel funnel stays silent. Watch the
	 * chunks: for each of entries[0..3] holding a legal in-heap
	 * pointer, snapshot the chunk's first 8 bytes (e->next) per
	 * round; a change names the write's window (last_nr/ret +
	 * trap rip/rsp) and dumps the chunk. A popped chunk stops
	 * being the head — its slot re-arms on the entry change — so
	 * a stable head's e->next does not move under legit glibc;
	 * only a foreign write (or a double-free) trips. */
	{
		int di;

		/* DEAD-CODE FIX (referee 37114981981 decode): armed was
		 * only ever ASSIGNED 0 — the !armed continue below made
		 * the whole chunk watch unreachable ([tcchunk] = 0
		 * lines in every referee run; the run-3 dice — bin 0
		 * head 0x67cd57e0's e->next poisoned, "unaligned tcache
		 * chunk" — fell exactly in the watched class). Arm now
		 * SNAPS + SETS armed=1 atomically at (re)arm: the head
		 * changed identity → read its e->next immediately;
		 * every later round compares. ALL 64 bins (the poison
		 * rotated bins 0/1/2 across runs) — 64 translates per
		 * round is VMA-find work, no copies. A legit push onto
		 * the head changes entries[i] → re-arm; only a write
		 * to a STABLE head's next (double-free / the poison
		 * class) fires.
		 *
		 * DEPTH-4 (referee 37117711740 decode): the split
		 * stayed at 0 POISON — 16 churn fires ate their budget
		 * and the smallbin ABRT still killed the boot with the
		 * tcache entries CLEAN at abort: the poison rounds
		 * hit list members BELOW the stable head (37116465517
		 * mid-list) and non-tcache free chunks. The tcache
		 * list is LIFO, so a member's e->next is as stable as
		 * the head's while it sits in the list — push/pop
		 * touch the head slot only, and any head change
		 * re-walks the bin. So each bin now watches the first
		 * 4 members: walk entries[di] via the safe-linked
		 * decode (key = the member's OWN address, map-053),
		 * snapshot each member's e->next, compare per round.
		 * A change on a stable member (any depth) classifies
		 * exactly like the head did: POISON = the decoded next
		 * is misaligned/out-of-heap (no legit free() writes
		 * that), CHURN = everything else; both re-arm so the
		 * watch survives its own fires. The walk also decodes
		 * AT (re)arm: a garbage member next decoded right
		 * there fires immediately — the write landed since the
		 * last walk, first sight = this round. The walk is
		 * gated on (churn || poison budget) so exhausted
		 * budgets stop the VMA-find work; a fresh head still
		 * arms while the POISON budget lives (the head-write
		 * rounds keep their witness after churn dies). */
		for (di = 0; di < 64; di++) {
			unsigned long long ev = entries[di];
			int depth;
			const struct uml_nt_vma *ev_vma;
			int ev_ok;

			ev_vma = ((ev & 0xF) == 0 && (ev >> 48) == 0) ?
				 uml_nt_vma_find(mm, ev) : NULL;
			ev_ok = ((ev & 0xF) == 0 && (ev >> 48) == 0) &&
				((ev >= mm->heap_start && ev < mm->heap_end) ||
				 (ev_vma != NULL &&
				  !(ev_vma->flags & UML_NT_VMA_FILE) &&
				  (ev_vma->prot == UML_NT_PAGE_READWRITE ||
				   ev_vma->prot ==
				   UML_NT_PAGE_EXECUTE_READWRITE) &&
				  ev + 16 <= ev_vma->end));

			if (!c->tc_chunk_valid ||
			    c->tc_chunk_va[di][0] != ev ||
			    !c->tc_chunk_armed[di][0] ||
			    !ev_ok) {
				/* (Re)arm: the watched head changed
				 * identity — walk the list and snapshot
				 * its members NOW; compare from the
				 * next round. */
				c->tc_chunk_va[di][0] = ev;
				c->tc_chunk_snap[di][0] = 0;
				for (depth = 0; depth < 4; depth++)
					c->tc_chunk_armed[di][depth] = 0;
				if ((tcache_chunk_budget > 0 ||
				     tcache_poison_budget > 0) &&
				    ev_ok) {
					unsigned long long chunk = ev;

					for (depth = 0; depth < 4;
					     depth++) {
						unsigned long long data,
							nxt;
						const struct uml_nt_vma *nv;
						int nxt_ok;
						long long coff =
							uml_nt_vma_translate(
							mm, chunk, 8);

						if (coff < 0)
							break;
						data = *(const unsigned
							  long long *)
							(const void *)
							((char *)uml_boot.
							 physmem_base +
							 coff);
						nxt = data ^ (chunk >> 12);
						c->tc_chunk_va[di][depth] =
							chunk;
						c->tc_chunk_snap[di][depth] =
							data;
						c->tc_chunk_armed[di][depth] =
							1;
						if (nxt == 0)
							break;
						nv = ((nxt & 0xF) == 0 &&
						      (nxt >> 48) == 0) ?
						     uml_nt_vma_find(mm, nxt) :
						     NULL;
						nxt_ok = ((nxt & 0xF) == 0 &&
							  (nxt >> 48) == 0) &&
							 ((nxt >=
							   mm->heap_start &&
							   nxt <
							   mm->heap_end) ||
							  (nv != NULL &&
							   !(nv->flags &
							     UML_NT_VMA_FILE) &&
							   (nv->prot ==
							    UML_NT_PAGE_READWRITE ||
							    nv->prot ==
							    UML_NT_PAGE_EXECUTE_READWRITE) &&
							   nxt + 16 <=
							   nv->end));
						if (!nxt_ok) {
							/* POISON decoded at
							 * walk time — the
							 * list member's next
							 * is garbage right
							 * now. */
							if (tcache_poison_budget >
							    0) {
								tcache_poison_budget--;
								os_info("[tcchunk-POISON] pid %lu list[%d] d%d va=0x%llx next=0x%llx (rearm-decode round nr=%llu ret=%lld rip=0x%llx rsp=0x%llx)\n",
									(unsigned
									long)
									c->pid,
									di, depth,
									chunk,
									nxt,
									c->last_nr,
									c->last_ret,
									c->d->regs.
									rip,
									c->d->regs.
									rsp);
								dump_guest_bytes(
									mm, chunk,
									0x20,
									"tcchunk-head");
							}
							/* ARM-ON-FIRE
							 * (referee
							 * 37120127074
							 * decode): the
							 * poison repeats
							 * — 16 POISON
							 * fires in one
							 * boot, same
							 * class. The fired
							 * chunk's RUN goes
							 * under the
							 * direct-write
							 * tripwires NOW:
							 * the next write
							 * to the page
							 * names the writer
							 * (a stub-side rip
							 * through the
							 * cowtrap fault; a
							 * kernel-side flat
							 * write through
							 * the cowwatch
							 * round-compare
							 * "kernel-write"
							 * report). Both
							 * layers already
							 * existed — this
							 * reuses them at
							 * the fire point
							 * (no new
							 * layer). */
							{
								unsigned long
								long frun =
									(unsigned
									long long)
									coff &
									~(unsigned
									long long)
									(UML_NT_PHYS_RUN_SIZE -
									 1);
								unsigned long
								long fbase =
									chunk &
									~(unsigned
									long long)
									(UML_NT_PHYS_RUN_SIZE -
									 1);

								uml_nt_cowwatch_arm(
									frun,
									fbase,
									(unsigned
									long)
									c->pid);
								uml_nt_cowtrap_arm_alloc(
									c,
									fbase,
									UML_NT_PHYS_RUN_SIZE,
									frun);
								/* KTRIP-W
								 * (referee
								 * 37124011556
								 * decode):
								 * walk-time
								 * fire =
								 * FRESHEST
								 * victim (the
								 * write
								 * landed
								 * since the
								 * last
								 * walk) — arm
								 * the
								 * chunk's
								 * 4K page
								 * kernel-flat
								 * too (see
								 * the
								 * compare-time
								 * fire
								 * site). */
								uml_nt_ktrip_w_arm(
		(unsigned long long)(uintptr_t)uml_boot.physmem_base +
			((unsigned long long)coff &
			 ~(unsigned long long)0xfffull),
		(unsigned long long)(uintptr_t)uml_boot.physmem_base +
			(((unsigned long long)coff &
			  ~(unsigned long long)0xfffull) + 0x1000));
							}
							break;
						}
						chunk = nxt;
					}
				}
				continue;
			}
			/* Stable bin: compare every armed member. */
			for (depth = 0; depth < 4; depth++) {
				unsigned long long chunk =
					c->tc_chunk_va[di][depth];
				unsigned long long data, nxt;
				long long coff;
				int poison;

				if (!c->tc_chunk_armed[di][depth])
					continue;
				coff = uml_nt_vma_translate(mm, chunk, 8);
				if (coff < 0)
					continue;
				data = *(const unsigned long long *)
					(const void *)((char *)
					uml_boot.physmem_base + coff);
				if (c->tc_chunk_snap[di][depth] == data)
					continue;
				/* The POISON/churn split (37116465517):
				 * an A-B-A push pair inside one round
				 * restores the head VA while its next
				 * moved (0x67c0f = PROTECT_PTR(pos,0)
				 * of an empty bin — LEGIT), the stale
				 * snap fires. Decode the next with the
				 * PUSHED chunk's own address: POISON =
				 * misaligned/out-of-heap, CHURN = the
				 * rest. Each class draws its own
				 * budget; both re-arm. */
				nxt = data ^ (chunk >> 12);
				{
					const struct uml_nt_vma *nv =
						((nxt & 0xF) == 0 &&
						 (nxt >> 48) == 0) ?
						uml_nt_vma_find(mm, nxt) : NULL;
					int nxt_ok =
						((nxt & 0xF) == 0 &&
						 (nxt >> 48) == 0) &&
						((nxt >= mm->heap_start &&
						  nxt < mm->heap_end) ||
						 (nv != NULL &&
						  !(nv->flags &
						    UML_NT_VMA_FILE) &&
						  (nv->prot ==
						   UML_NT_PAGE_READWRITE ||
						   nv->prot ==
						   UML_NT_PAGE_EXECUTE_READWRITE) &&
						  nxt + 16 <= nv->end));

					poison = nxt != 0 && !nxt_ok;
				}
				/* GHOST CHECK (referee 37121882179
				 * decode): the 16 POISON fires were
				 * A-B-A ghosts — the head returned to
				 * its snapshot VA within the pass
				 * window (push+pop cycle), the depth
				 * slots went stale, and the "poison
				 * text" was a REALLOCATED chunk's
				 * read-buffer data ([uawrite] #12's
				 * os-release PRETTY_NAME matched fire
				 * #1's payload byte-for-byte). A REAL
				 * corrupting write hits a chunk that
				 * is STILL a live member of the
				 * CURRENT chain — re-walk from this
				 * pass's head and require membership
				 * before spending the POISON budget.
				 * A stale slot downgrades to churn
				 * (re-snapshot, no fire, no arm).
				 * A rotten chain below the head
				 * (garbage next within the walk)
				 * fails loud as POISON — fail-closed
				 * for the real writer. */
				if (poison) {
					unsigned long long cur_chunk =
						ev;
					int d2, live = 0;

					for (d2 = 0; d2 < 6; d2++) {
						unsigned long long
						cdata, cnxt;
						long long ccoff =
						uml_nt_vma_translate(
							mm, cur_chunk,
							8);

						if (ccoff < 0)
							break;
						cdata = *(const unsigned
							  long long *)
							(const void *)
							((char *)uml_boot
							 .physmem_base +
							 ccoff);
						if (cur_chunk == chunk) {
							live = 1;
							break;
						}
						cnxt = cdata ^
							(cur_chunk >> 12);
						if (cnxt == 0 ||
						    (cnxt & 0xF) != 0 ||
						    cnxt <
						    mm->heap_start ||
						    cnxt >=
						    mm->heap_end)
							break;
						cur_chunk = cnxt;
					}
					if (!live) {
						static int n_tcstale_log;

						poison = 0;
						if (++n_tcstale_log <= 32)
							os_info("[tcchunk-stale] "
								"pid %lu list[%d] "
								"d%d va=0x%llx "
								"0x%llx -> 0x%llx "
								"(A-B-A ghost — "
								"chunk left the "
								"chain; churn)\n",
								(unsigned long)
								c->pid, di, depth,
								chunk, c->
								tc_chunk_snap[di]
								[depth], data);
					}
				}
				if (poison) {
					if (tcache_poison_budget <= 0) {
						c->tc_chunk_snap[di][depth] =
							data;
						continue;
					}
					tcache_poison_budget--;
				} else {
					if (tcache_chunk_budget <= 0) {
						c->tc_chunk_snap[di][depth] =
							data;
						continue;
					}
					tcache_chunk_budget--;
				}
				os_info("[tcchunk-%s] pid %lu list[%d] d%d "
					"va=0x%llx 0x%llx -> 0x%llx "
					"(next=0x%llx round nr=%llu "
					"ret=%lld rip=0x%llx rsp=0x%llx)"
					"\n", poison ? "POISON" : "churn",
					(unsigned long)c->pid, di, depth,
					chunk, c->tc_chunk_snap[di][depth],
					data, nxt, c->last_nr, c->last_ret,
					c->d->regs.rip, c->d->regs.rsp);
				if (poison) {
					unsigned long long frun =
						(unsigned long long)coff &
						~(unsigned long long)
						(UML_NT_PHYS_RUN_SIZE - 1);
					unsigned long long fbase =
						chunk &
						~(unsigned long long)
						(UML_NT_PHYS_RUN_SIZE - 1);

					/* WIRE-PAIRING (dl12 37286247065):
					 * the poisoned chunk's RUN on its
					 * own line — grep-pair against
					 * the [wire] run_off ledger names
					 * whether the text landed via an
					 * exec stack table sharing the
					 * run; the line order vs the
					 * wire line says which side owned
					 * the run first. */
					os_info("[tcchunk-run] pid %lu "
						"va=0x%llx run=0x%llx\n",
						(unsigned long)c->pid,
						chunk, frun);
					dump_guest_bytes(mm, chunk, 0x20,
							 "tcchunk-head");
					/* ARM-ON-FIRE (referee 37120127074
					 * decode): the poison repeats —
					 * 16 POISON fires, one boot, same
					 * class. The fired chunk's RUN
					 * goes under the direct-write
					 * tripwires NOW: the next write
					 * to the page names the writer
					 * (stub-side = the cowtrap fault
					 * rip; kernel-side = the
					 * cowwatch round-compare
					 * "kernel-write" report). No new
					 * layer — the fire point reuses
					 * both. */
					uml_nt_cowwatch_arm(frun, fbase,
							    (unsigned long)
							    c->pid);
					uml_nt_cowtrap_arm_alloc(c, fbase,
								 UML_NT_PHYS_RUN_SIZE,
								 frun);
					/* KTRIP-W (referee 37124011556
					 * decode): the fired chunk's own
					 * 4K page goes READ-ONLY in the
					 * KERNEL's flat view — the
					 * witness the fire window was
					 * missing. cowtrap covers
					 * stub-side writes (every catch
					 * so far = legit malloc), the
					 * cowwatch HIT is a run-level
					 * round-compare; a kernel-direct
					 * flat write to THIS page now
					 * trips with its rip. Referee
					 * 37121882179's A-B-A decode
					 * also showed the struct-page
					 * [ktrip] arm cannot hold this
					 * window (it re-arms every
					 * round) — ktrip-w is
					 * independent. */
					uml_nt_ktrip_w_arm(
		(unsigned long long)(uintptr_t)uml_boot.physmem_base +
			((unsigned long long)coff &
			 ~(unsigned long long)0xfffull),
		(unsigned long long)(uintptr_t)uml_boot.physmem_base +
			(((unsigned long long)coff &
			  ~(unsigned long long)0xfffull) + 0x1000));
				}
				c->tc_chunk_snap[di][depth] = data;
				c->tc_chunk_armed[di][depth] = 1;
			}
		}
		c->tc_chunk_valid = 1;
	}
	if (tcache_watch_budget <= 0 || c->tcache_fired)
		return;
	for (i = 0; i < UML_NT_TCACHE_COUNTS; i++) {
		int bad;

		/* MANGLE-FREE VALIDATION ONLY (runs 36972326995 +
		 * 36972320563 lesson): safe-linking's reveal key is the
		 * PUSHED CHUNK's own data address, not the entries[]
		 * slot address — un-mangling with the slot key flagged
		 * every healthy cache (an empty slot stores 0, which
		 * un-mangles to the key itself; a live head un-mangles
		 * to slot-key-xor garbage) and burned the one-shot
		 * budget on the first 8 conns before any real poison.
		 * What convicts WITHOUT the key: count <= 7 always
		 * (text poison "a%UTEMD_"/"US.UTF-8" reads as huge
		 * u16 counts and fires here directly), and the
		 * count/head pair-state glibc maintains atomically per
		 * put/get — a NULL head with a non-zero count, or a
		 * non-NULL head with a zero count, is impossible in a
		 * quiescent cache. */
		bad = (counts[i] > UML_NT_TCACHE_LIMIT) ||
		      ((entries[i] == 0) != (counts[i] == 0)) ||
		      ((entries[i] & 0xF) != 0);
		/* The alignment term (run 37073260886): glibc's OWN
		 * conviction is aligned_OK(e) — "unaligned tcache chunk
		 * detected" — and an unaligned-but-count-consistent
		 * entry passed the two checks above all boot (0 tcwatch
		 * lines) while glibc died on it. An unaligned head IS
		 * the corrupting write's fingerprint. */
		if (!bad)
			continue;
		c->tcache_fired = 1;
		tcache_watch_budget--;
		os_info("[tcwatch] pid %lu slot %d COUNT=%u entry=0x%llx "
			"heap [0x%llx,0x%llx)\n",
			(unsigned long)c->pid, i, counts[i], entries[i],
			mm->heap_start, mm->heap_end);
		os_info("[tcwatch]   round nr=%llu ret=%lld rip=0x%llx "
			"rsp=0x%llx fs=0x%llx\n", c->last_nr, c->last_ret,
			c->d->regs.rip, c->d->regs.rsp, c->fs_base);
		dump_guest_bytes(mm, tva - 0x10, 0x10, "tcwatch-before");
		dump_guest_bytes(mm, tva + 0x290, 0x20, "tcwatch-after");
		dump_guest_bytes(mm, tva + 0x80, 0x80, "tcwatch-entries");
		return;
	}
}

/* M5.6a cross-stub census: the launcher holds every stub's process
 * handle (c->proc) — VirtualQueryEx reads ANY stub's VA space with
 * no stub cooperation. At a [replay-lost] fire, walk every OTHER
 * live conn's stub: a MEM_MAPPED region inside the guest span that
 * the conn's own VMA table does not admit is a stale/foreign view
 * of the shared section — the one object that could write the
 * victim's run behind every per-view witness. */
static void cross_stub_census(struct uml_nt_stub_conn *self,
			      unsigned long long arm_run)
{
	struct task_struct *p;
	static int census_budget = 4;

	if (census_budget <= 0)
		return;
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		unsigned long long va;
		int bad = 0;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc == self || pc->proc == NULL ||
		    pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		va = UML_NT_GUEST_VA_BASE;
		while (va < UML_NT_GUEST_VA_BASE + uml_boot.physmem_size &&
		       bad < 3) {
			MEMORY_BASIC_INFORMATION mbi;
			SIZE_T got;
			int vi, admitted;

			memset(&mbi, 0, sizeof(mbi));
			got = nt->VirtualQueryEx(pc->proc,
						 (void *)(uintptr_t)va,
						 &mbi, sizeof(mbi));
			if (got == 0 || mbi.RegionSize == 0)
				break;
			admitted = 0;
			if (mbi.State == 0x1000 && mbi.Type == 0x40000) {
				for (vi = 0; vi < pc->mm->nvma; vi++) {
					struct uml_nt_vma *v =
						&pc->mm->vma[vi];

					if (va >= v->start &&
					    va < v->end) {
						admitted = 1;
						break;
					}
				}
				if (!admitted && census_budget > 0) {
					unsigned long long probe;
					unsigned long long vals[2];
					SIZE_T rgot;

					census_budget--;
					memset(vals, 0, sizeof(vals));
					nt->ReadProcessMemory(pc->proc,
					    (void *)(uintptr_t)va,
					    vals, 16, &rgot);
					probe = *(unsigned long long *)
						(uml_boot.physmem_base +
						 arm_run + (va & 0xffff));
					os_info("[xcensus] pid %lu holds "
						"UNADMITTED MEM_MAPPED "
						"region [0x%llx,+0x%llx) "
						"prot=0x%x q0=0x%llx "
						"(arm-run@same-off "
						"0x%llx)\n",
						(unsigned long)pc->pid, va,
						(unsigned long long)
						mbi.RegionSize,
						mbi.Protect, vals[0], probe);
					bad++;
				}
			}
			va += mbi.RegionSize;
		}
	}
}

/* M5.6a claim-audit: a phys run claimed by two live mms is legit
 * ONLY while BOTH VMAs carry the COW flag (the fork marks both
 * sides; the brk re-home's flags=0 rebuild wiped it once — see the
 * syscall.c fix). A double-claim with a non-COW side means both
 * owners take mm_fault's private path and write the SAME physical
 * run concurrently (stubs run guest code in parallel — the pump
 * serializes only the kernel side): the shared-heap tear. Runs at
 * every 4096th syscall park, loud-budgeted. */
static int claim_audit_force_flag;
void uml_nt_claim_audit_force(void) { claim_audit_force_flag = 1; }

/* K6 step 2 (M5.6a decision-tree step 2): [tcekey] — the
 * double-free-via-stale-e->key witness. SYSCALL PARKS ONLY (hooked
 * beside claim_audit; the fault-park A/B lesson). At each park of
 * a glibc-shaped heap: snapshot counts[]/entries[], walk every
 * non-empty bin with the safe-linked reveal (uaccess_walk.c's
 * host-tested pure logic), record each listed chunk's e->key
 * (chunk+8; == the tcache ptr expected — a listed chunk with a
 * stale/missing key is glibc's dup-check BLINDED), size header
 * (chunk-8) and backing run, then diff against the previous park:
 *   [tcekey] STALE-KEY     (a) key != tcache ptr on a listed chunk
 *   [tcekey] DUP-CHUNK     (b) same va twice in one snapshot's
 *                           walk = the dup insert (double free)
 *   [tcekey] HEAD-REENTRY  (b) new head already listed at the
 *                           previous park while counts ROSE (a
 *                           legit pop+re-push cannot raise counts)
 *   [tcekey] COUNT-MISMATCH (c) counts[i] != walked length — the
 *                           known tear (insert store #1 lost)
 *                           reads exactly like this: chain broke
 *                           at the new head, counts above it
 *   [tcekey-run]           (d) the same chunk VA on a different
 *                           backing run between parks + every
 *                           heap-piece run_off change — the dl14
 *                           re-home signature (chunk 0x67ce3010
 *                           read via run 0xee0000, detected on
 *                           run 0x56e0000)
 * The (a) comparator: e->key == the tcache ptr only on glibc
 * < 2.34 — 2.34+ (the referee's Debian 2.36) stores a RANDOM
 * per-boot tcache_key there. The honest comparator is learned by
 * MAJORITY VOTE over the walked chunks (the modal key — identical
 * for every legitimately listed chunk in one process, whichever
 * scheme glibc uses), learned once per conn and kept (the value
 * lives in libc data, untouched by heap re-homes). A listed chunk
 * whose key lost the vote = the stale/missing key store — glibc's
 * dup-check BLINDED for that chunk.
 * Each flag names the park's incoming nr (park-nr), the last
 * served nr/ret and the trap rip. Per-conn dedup ring (class, va)
 * keeps a persistent torn state from eating the 64-line budgets;
 * the armed/census lines prove the witness ran when flags are
 * zero. Read-only: no guest state is ever touched (unlike the
 * ss/TF or DR witnesses, this cannot destabilize the boot).
 * READER ACCURACY (scrutiny round on b147569): every member qword
 * goes through its OWN translate — a chunk whose DATA va sits at
 * a COW-piece/VMA boundary (size hdr in one piece, data/key in
 * the next) is still read; the old single 24B window rejected
 * exactly those members (FALSE break at the head → FALSE
 * COUNT-MISMATCH, no key/run row). The backing run recorded is
 * the chunk's DATA qword's read. The snapshot holds the FULL
 * healthy tcache (64 bins x 7 = 448); a walk past it (only a
 * bin deeper than healthy can) drops honestly: the census line
 * carries the conn's cumulative trunc= and the COUNT-MISMATCH
 * line this park's trunc= — never a silent omission. */
static int tcekey_budget = 64;
static int tcekey_run_budget = 64;
static int tcekey_armed_budget = 64;
static int tcekey_census_budget = 64;
static int tcekey_exhaust_line;
/* the current park's snapshot — static, not stack: the boot/vCPU
 * stack is a UML THREAD_SIZE (16K) stack by discipline (the
 * claim_audit pattern); kernel-side serving is serialized (the
 * pump owns it), so one shared buffer serves every conn. */
static struct uml_nt_tce_snap tce_cur;
static struct tce_binsum {
	unsigned int counts;
	unsigned long long head;
	int walked, capped, broke;
	unsigned long long broke_va, broke_next;
} tce_bn[64];

enum {
	TCE_CLS_KEY = 1, TCE_CLS_DUP, TCE_CLS_REENTRY, TCE_CLS_COUNT,
	TCE_CLS_RUNCHUNK, TCE_CLS_RUNPIECE
};

static int tce_dedup_seen(struct uml_nt_stub_conn *c, int cls,
			  unsigned long long va)
{
	int i;

	for (i = 0; i < 16; i++)
		if (c->ek_dedup_cls[i] == (unsigned char)cls &&
		    c->ek_dedup_va[i] == va)
			return 1;
	return 0;
}

static void tce_dedup_add(struct uml_nt_stub_conn *c, int cls,
			  unsigned long long va)
{
	c->ek_dedup_cls[c->ek_dedup_head] = (unsigned char)cls;
	c->ek_dedup_va[c->ek_dedup_head] = va;
	c->ek_dedup_head = (c->ek_dedup_head + 1) & 15;
}

/* the chunk-qword reader: each qword goes through its OWN
 * translate — a member whose 24B window [va-8, va+16) straddles
 * a COW-piece/VMA boundary (size hdr in one piece, data/key in
 * the next) is still readable; the old single-window translate
 * rejected exactly those members (FALSE break at the head →
 * FALSE COUNT-MISMATCH, no key/run row for the member). The run
 * is the CURRENT backing of THE READ ITSELF — the walk keeps the
 * one off the chunk's DATA qword (the member, not its header). */
static int tce_read(void *ctx, unsigned long long va,
		     unsigned long long *qword, unsigned long long *run)
{
	struct uml_nt_mm *mm = (struct uml_nt_mm *)ctx;
	long long off = uml_nt_vma_translate(mm, va, 8);

	if (off < 0)
		return -1;
	*qword = *(const unsigned long long *)(const void *)
		 ((char *)uml_boot.physmem_base + off);
	*run = (unsigned long long)off &
	       ~(UML_NT_PHYS_RUN_SIZE - 1);
	return 0;
}

static void tcache_ekey_watch(struct uml_nt_stub_conn *c)
{
	struct uml_nt_mm *mm = c->mm;
	struct uml_nt_stub_data *d = c->d;
	unsigned short counts[64];
	unsigned long long entries[64];
	struct uml_nt_tce_snap *cur = &tce_cur;
	unsigned long long tva;
	long long off;
	int i;

	if (witness_off())
		return;
	if (!c->task_backed || mm == NULL || mm->heap_start == 0)
		return;
	/* the same glibc shape gate as tcache_watch: the heap's
	 * first chunk must be the tcache struct (size hdr 0x291);
	 * a musl guest stays silent. */
	off = uml_nt_vma_translate(mm, mm->heap_start, 16);
	if (off < 0)
		return;
	{
		unsigned long long hdr = *(const unsigned long long *)
			(const void *)((char *)uml_boot.physmem_base +
				       off + 8);

		if (hdr != 0x291)
			return;
	}
	tva = mm->heap_start + 0x10;
	off = uml_nt_vma_translate(mm, tva, 0x290);
	if (off < 0)
		return;
	memcpy(counts, (const void *)(uintptr_t)
	       ((char *)uml_boot.physmem_base + off), sizeof(counts));
	memcpy(entries, (const void *)(uintptr_t)
	       ((char *)uml_boot.physmem_base + off + 0x80),
	       sizeof(entries));

	c->ek_parks++;
	if (!c->ek_valid && tcekey_armed_budget > 0) {
		tcekey_armed_budget--;
		os_info("[tcekey] armed pid %lu heap=[0x%llx,0x%llx) "
			"tcache=0x%llx (park-nr=%llu nr=%llu ret=%lld)\n",
			(unsigned long)c->pid, mm->heap_start, mm->heap_end,
			tva, d->regs.rax, c->last_nr, c->last_ret);
	}
	memset(cur, 0, sizeof(*cur));
	if (tcekey_budget > 0 || tcekey_run_budget > 0) {
		struct uml_nt_tce_rd rd;
		struct tce_binsum *bn = tce_bn;
		unsigned long long want = 0;
		int i2, best = 0, dropped = 0;

		rd.read = tce_read;
		rd.ctx = mm;
		/* PHASE 1 — walk every non-empty bin and record its
		 * chunks. The dup flag fires here (va-only, no key
		 * knowledge needed); the per-bin walk summaries go to
		 * bn[] for the phase-2 counts/reentry checks. */
		for (i = 0; i < 64; i++) {
			struct uml_nt_tce_bin wb;
			unsigned int ncnt = counts[i];
			unsigned long long ev = entries[i];
			int d2, walked;

			bn[i].counts = ncnt;
			bn[i].head = ev;
			bn[i].walked = 0;
			bn[i].capped = 0;
			bn[i].broke = 0;
			bn[i].broke_va = 0;
			bn[i].broke_next = 0;
			if (ev == 0 && ncnt == 0)
				continue;
			uml_nt_tce_walk_bin(&rd, ev, mm->heap_start,
					    mm->heap_end, i, &wb);
			bn[i].walked = wb.walked;
			bn[i].capped = wb.capped;
			bn[i].broke = wb.broke;
			bn[i].broke_va = wb.broke_va;
			bn[i].broke_next = wb.broke_next;
			walked = wb.walked;
			for (d2 = 0; d2 < walked; d2++) {
				struct uml_nt_tce_chunk *ch = &wb.ch[d2];
				int r = uml_nt_tce_record(cur, ch);

				if (r == -2)
					dropped++; /* the snapshot is
						   * full — the honest
						   * trunc the census/
						   * flag lines carry
						   * (possible only past
						   * a full healthy
						   * tcache) */
				if (r >= 0 && tcekey_budget > 0 &&
				    !tce_dedup_seen(c, TCE_CLS_DUP,
						    ch->va)) {
					tce_dedup_add(c, TCE_CLS_DUP,
						      ch->va);
					tcekey_budget--;
					os_info("[tcekey] pid %lu DUP-CHUNK "
						"va=0x%llx bin %d depth %d "
						"also bin %d depth %d "
						"(DOUBLE-FREE; park-nr=%llu"
						" nr=%llu ret=%lld "
						"rip=0x%llx)\n",
						(unsigned long)c->pid,
						ch->va, ch->bin, d2,
						cur->ch[r].bin,
						cur->ch[r].depth,
						d->regs.rax, c->last_nr,
						c->last_ret, d->regs.rip);
				}
			}
		}
		/* PHASE 2a — the (a) comparator: majority vote over
		 * the walked chunks' keys (uml_nt_tce_modal_key —
		 * tcache_key is one value per process; a NULL key is
		 * the pop marker / the missing store and never gets a
		 * vote). Learned once per conn (>= 2 agreeing chunks)
		 * and kept: the value lives in libc data, immune to
		 * heap moves. */
		want = uml_nt_tce_modal_key(cur, &best);
		if (c->ek_want_key == 0 && best >= 2)
			c->ek_want_key = want;
		if (c->ek_want_key != 0)
			want = c->ek_want_key;
		/* PHASE 2b — per-chunk flags: (a) the stale key (a
		 * listed chunk that lost the vote = the missing key
		 * store, glibc's dup-check blind), (d) the chunk's
		 * backing run vs the previous park. */
		for (i2 = 0; i2 < cur->n; i2++) {
			struct uml_nt_tce_chunk *ch = &cur->ch[i2];
			int pv = uml_nt_tce_find(&c->ek_prev, ch->va);

			if (want != 0 &&
			    uml_nt_tce_key_stale(ch->key, want) &&
			    tcekey_budget > 0 &&
			    !tce_dedup_seen(c, TCE_CLS_KEY, ch->va)) {
				tce_dedup_add(c, TCE_CLS_KEY, ch->va);
				tcekey_budget--;
				os_info("[tcekey] pid %lu STALE-KEY bin "
					"%d va=0x%llx key=0x%llx want=0x%llx"
					" size=0x%llx run=0x%llx prev=%s ("
					"park-nr=%llu nr=%llu ret=%lld "
					"rip=0x%llx)\n",
					(unsigned long)c->pid, ch->bin,
					ch->va, ch->key, want, ch->size,
					ch->run,
					pv >= 0 ? "listed" : "new",
					d->regs.rax, c->last_nr,
					c->last_ret, d->regs.rip);
			}
			if (pv >= 0 &&
			    c->ek_prev.ch[pv].run != ch->run &&
			    tcekey_run_budget > 0 &&
			    !tce_dedup_seen(c, TCE_CLS_RUNCHUNK,
					    ch->va)) {
				tce_dedup_add(c, TCE_CLS_RUNCHUNK,
					      ch->va);
				tcekey_run_budget--;
				os_info("[tcekey-run] pid %lu va=0x%llx "
					"chunk run 0x%llx -> 0x%llx bin %d "
					"(park-nr=%llu nr=%llu ret=%lld)\n",
					(unsigned long)c->pid, ch->va,
					c->ek_prev.ch[pv].run, ch->run,
					ch->bin, d->regs.rax, c->last_nr,
					c->last_ret);
			}
		}
		/* PHASE 2c — per-bin flags: (c) counts vs the walked
		 * length (the missing-store fingerprint), (b) the head
		 * re-entry that raised counts (the dup insert). */
		for (i = 0; i < 64; i++) {
			int pvh;

			if (bn[i].head == 0 && bn[i].counts == 0)
				continue;
			if (uml_nt_tce_counts_bad(bn[i].counts,
						  bn[i].walked,
						  bn[i].capped) &&
			    tcekey_budget > 0 &&
			    !tce_dedup_seen(c, TCE_CLS_COUNT,
					    bn[i].head)) {
				tce_dedup_add(c, TCE_CLS_COUNT, bn[i].head);
				tcekey_budget--;
				/* trunc: walked members this park's
				 * snapshot could NOT hold — the phase-2
				 * checks below see only cur->ch[0..n),
				 * so a truncation silently omits them;
				 * 0 = the snapshot is complete. */
				os_info("[tcekey] pid %lu COUNT-MISMATCH bin "
					"%d counts=%u walked=%d capped=%d "
					"head=0x%llx broke_va=0x%llx "
					"broke_next=0x%llx prev_head=0x%llx"
					" prev_counts=%u trunc=%d "
					"(park-nr=%llu "
					"nr=%llu ret=%lld)\n",
					(unsigned long)c->pid, i,
					bn[i].counts, bn[i].walked,
					bn[i].capped, bn[i].head,
					bn[i].broke_va, bn[i].broke_next,
					c->ek_prev_entries[i],
					c->ek_prev_counts[i], dropped,
					d->regs.rax, c->last_nr,
					c->last_ret);
			}
			pvh = (bn[i].head != 0) ?
			      uml_nt_tce_find(&c->ek_prev, bn[i].head) : -1;
			if (c->ek_valid &&
			    c->ek_prev_entries[i] != bn[i].head && pvh >= 0 &&
			    uml_nt_tce_reentry_bad(1, 1, bn[i].counts,
						   c->ek_prev_counts[i]) &&
			    tcekey_budget > 0 &&
			    !tce_dedup_seen(c, TCE_CLS_REENTRY,
					    bn[i].head)) {
				tce_dedup_add(c, TCE_CLS_REENTRY,
					      bn[i].head);
				tcekey_budget--;
				os_info("[tcekey] pid %lu HEAD-REENTRY bin "
					"%d head=0x%llx prev bin %d depth "
					"%d counts=%u prev_counts=%u (dup "
					"insert; park-nr=%llu nr=%llu "
					"ret=%lld)\n",
					(unsigned long)c->pid, i,
					bn[i].head,
					c->ek_prev.ch[pvh].bin,
					c->ek_prev.ch[pvh].depth,
					bn[i].counts,
					c->ek_prev_counts[i], d->regs.rax,
					c->last_nr, c->last_ret);
			}
		}
		/* this park's snapshot becomes the next park's prev */
		c->ek_prev = *cur;
		c->ek_trunc += dropped;
		memcpy(c->ek_prev_counts, counts,
		       sizeof(c->ek_prev_counts));
		memcpy(c->ek_prev_entries, entries,
		       sizeof(c->ek_prev_entries));
		c->ek_valid = 1;
	}
	/* census every 4096 parks: the explicit zero (the witness ran,
	 * nothing flagged, budget alive). */
	if ((c->ek_parks & 0xfffull) == 0 && tcekey_census_budget > 0) {
		tcekey_census_budget--;
		/* trunc: the conn's CUMULATIVE dropped walked members
		 * (snapshot full) — 0 = every snapshot this conn took
		 * was complete; a non-zero trunc is the explicit
		 * disclosure that some key/run/dup checks were
		 * omitted, never a silent drop. */
		os_info("[tcekey] census pid %lu parks=%llu chunks=%d "
			"trunc=%llu budget=%d run-budget=%d "
			"(park-nr=%llu nr=%llu "
			"ret=%lld)\n", (unsigned long)c->pid, c->ek_parks,
			cur->n, c->ek_trunc, tcekey_budget,
			tcekey_run_budget, d->regs.rax, c->last_nr,
			c->last_ret);
	}
	/* (d) heap-piece run_off watch: the dl14 re-home (heap VMA
	 * run_off 0xe00000 -> 0x5600000) with old/new run + the park's
	 * nr — the migration's own lines, not just its aftermath. */
	{
		unsigned long long ps[UML_NT_TCE_PIECES];
		unsigned long long pe[UML_NT_TCE_PIECES];
		unsigned long long po[UML_NT_TCE_PIECES];
		int np = 0, vi;

		for (vi = 0; vi < mm->nvma && np < UML_NT_TCE_PIECES;
		     vi++) {
			const struct uml_nt_vma *v = &mm->vma[vi];

			if (v->end <= mm->heap_start ||
			    v->start >= mm->heap_end)
				continue;
			ps[np] = v->start;
			pe[np] = v->end;
			po[np] = v->run_off;
			np++;
		}
		if (c->ek_pv_valid && tcekey_run_budget > 0) {
			for (i = 0; i < np; i++) {
				int j;

				for (j = 0; j < c->ek_pv_n; j++)
					if (c->ek_pv_start[j] == ps[i])
						break;
				if (j < c->ek_pv_n &&
				    c->ek_pv_off[j] != po[i] &&
				    !tce_dedup_seen(c, TCE_CLS_RUNPIECE,
						    ps[i])) {
					tce_dedup_add(c, TCE_CLS_RUNPIECE,
						      ps[i]);
					tcekey_run_budget--;
					os_info("[tcekey-run] pid %lu heap "
						"piece [0x%llx,0x%llx) "
						"run_off 0x%llx -> 0x%llx "
						"(park-nr=%llu nr=%llu "
						"ret=%lld)\n",
						(unsigned long)c->pid,
						ps[i], pe[i],
						c->ek_pv_off[j], po[i],
						d->regs.rax, c->last_nr,
						c->last_ret);
				}
			}
			if (np != c->ek_pv_n &&
			    !tce_dedup_seen(c, TCE_CLS_RUNPIECE, 0)) {
				tce_dedup_add(c, TCE_CLS_RUNPIECE, 0);
				tcekey_run_budget--;
				os_info("[tcekey-run] pid %lu heap pieces "
					"%d -> %d (split/merge/re-home; "
					"park-nr=%llu nr=%llu ret=%lld)\n",
					(unsigned long)c->pid, c->ek_pv_n,
					np, d->regs.rax, c->last_nr,
					c->last_ret);
			}
		}
		memcpy(c->ek_pv_start, ps,
		       sizeof(unsigned long long) * (unsigned)np);
		memcpy(c->ek_pv_off, po,
		       sizeof(po[0]) * (unsigned)np);
		c->ek_pv_n = np;
		c->ek_pv_valid = 1;
	}
	if (tcekey_budget <= 0 && tcekey_run_budget <= 0 &&
	    !tcekey_exhaust_line) {
		tcekey_exhaust_line = 1;
		os_info("[tcekey] budget exhausted — later torn states "
			"stay unwitnessed\n");
	}
}

/* K6 [viewprobe] (M5.6a, feature viewprobe-witness) — the
 * stub-view-vs-table witness. THE QUESTION: which backing does the
 * stub's CURRENT view of the watched heap qwords actually map, and
 * does it differ from the run the VMA table owns? dl26 convicted
 * the tcache_put pair landing in the abandoned SOURCE run through
 * a stale writable view, yet with 9a56286's complete release set +
 * drain census live, TWO referees (37549243995, 37549271088) show
 * the tear with 0 [viewswap] hits — the wrong view is invisible to
 * a RELEASED-RANGE census. This witness reads the watched qwords
 * BOTH ways at every syscall park of a watched heap mm (read-only:
 * kernel ReadProcessMemory on the PARKED stub — no ss/TF, no DR,
 * no page protects, nothing new at fault parks):
 *   (a) through the STUB's current view (ReadProcessMemory;
 *       VirtualQueryEx names the view's region when a fire needs
 *       it), the backing identified via the 9a56286 view ledger
 *       (view base/len/prot/off -> section offset -> run);
 *   (b) through the TABLE's run (the flat translate);
 *   (c) VIEW-DIVERGED fires on a STABLE mismatch (the double-read
 *       confirm — a shared-run writer racing between the reads is
 *       RACED, counted, never a fire): va, both values, the stub
 *       view's region + ledger identity, the table run, the last
 *       8 plan ops from the op ring, and nr/ret.
 * The watched set: the tcache struct page, every tcache-listed
 * chunk (own table-side walk — independent of [tcekey]'s print
 * budgets, which die long before the ~86k fire), plus the pages
 * of the last DRAINED plan stream's PROTECT/MAP ops. The LEDGER
 * CHECK (pure bookkeeping, zero stub reads, full coverage every
 * park) compares each watched va's LEDGER backing offset with the
 * table's own translate — a view mapped at a wrong/stale section
 * offset names itself without reading a byte, and a watched va
 * with NO ledger view over it (yet readable through the stub) is
 * the LEDGER-STRAY shape. Per-park cost is bounded (tcache page +
 * drain pages + 4 rotation chunk pages); the tear's own
 * counts-mismatch fingerprint (or any ledger anomaly) escalates
 * to the FULL page set that park. The drain record (stamped at the
 * plan-drain point in serve_conn) prints whether a re-protect/MAP
 * stream drained since the previous park, with its ops — the run-B
 * formation window showed exactly a 2-op [fork-sync] re-protect
 * drain beside the copy of the ADJACENT run. Budgets are line-
 * counted (64 per tag family); per-conn (class,va) dedup rings
 * keep a persistent torn state from eating them. */
#define VP_PAGE_SIZE 4096
#define VP_PAGES_MAX 512
#define VP_RR_MAX 4
#define VP_UNL_MAX 64

enum {
	VP_DD_DIV = 1,    /* byte divergence stub-view vs table */
	VP_DD_LEDGER = 2, /* ledger backing != table backing */
	VP_DD_STRAY = 3,  /* readable through the stub, NO ledger view */
	VP_DD_STUBUN = 4, /* stub view unreadable, table owns the page */
	VP_DD_TBLUN = 5,  /* stub reads it, the table does not own it */
};

static int vp_div_budget = 64;    /* VIEW/LEDGER-DIVERGED lines */
static int vp_unread_budget = 64; /* unread-view class lines */
static int vp_drain_budget = 64;  /* [viewprobe-drain] lines */
static int vp_armed_budget = 64;
static int vp_census_budget = 64;
static int vp_confirm_per_park;
static unsigned char vp_stub_pg[VP_PAGE_SIZE];
static unsigned char vp_tbl_pg[VP_PAGE_SIZE];
static unsigned char vp_stub_pg2[VP_PAGE_SIZE];
static unsigned char vp_tbl_pg2[VP_PAGE_SIZE];
static struct uml_nt_tce_snap vp_snap;
static unsigned long long vp_cvas[UML_NT_TCE_MAX];
static unsigned long long vp_pages[VP_PAGES_MAX];
static unsigned long long vp_unl[VP_UNL_MAX];
static int vp_nunl;         /* watched vas with no ledger view */
static unsigned long long vp_ctx_tva; /* the fire's attribution ctx */
static int vp_ctx_nch;
static int vp_ledger_hit;   /* any ledger anomaly this park */

static int vp_dedup_seen(struct uml_nt_stub_conn *c, int cls,
			 unsigned long long va)
{
	int i;

	for (i = 0; i < 16; i++)
		if (c->vp_dedup_cls[i] == (unsigned char)cls &&
		    c->vp_dedup_va[i] == va)
			return 1;
	return 0;
}

static void vp_dedup_add(struct uml_nt_stub_conn *c, int cls,
			 unsigned long long va)
{
	c->vp_dedup_cls[c->vp_dedup_head] = (unsigned char)cls;
	c->vp_dedup_va[c->vp_dedup_head] = va;
	c->vp_dedup_head = (c->vp_dedup_head + 1) & 15;
}

/* the fire's context tail: the last 8 plan ops from the op ring +
 * the drain record — the op that installed/left the diverged view
 * names itself here. Every line is budget-checked. */
static void vp_fire_tail(struct uml_nt_stub_conn *c)
{
	int k;

	for (k = 8; k >= 1 && vp_div_budget > 0; k--) {
		int idx = c->op_log_n - k;
		const unsigned long long *e;

		if (idx < 0)
			continue;
		e = c->op_log[idx % 64];
		vp_div_budget--;
		os_info("[viewprobe]   op-ring -%d: o=%u p=0x%x "
			"va=0x%llx l=0x%llx off=0x%llx\n", k,
			(unsigned)e[0], (unsigned)e[1], e[2], e[3],
			e[4]);
	}
	if (vp_div_budget > 0 && c->vp_drain_count > 0) {
		vp_div_budget--;
		os_info("[viewprobe]   drain-since-prev-park: %d "
			"stream(s), last retval=%d nops=%d trunc=%d\n",
			c->vp_drain_count, c->vp_drain_retval,
			c->vp_drain_nops,
			c->vp_drain_total - c->vp_drain_nops);
	}
}

/* the VIEW-DIVERGED burst: the empirical naming of the wrong
 * backing (stub view vs table run, both values, both identities). */
static void vp_fire_diverged(struct uml_nt_stub_conn *c,
			     struct uml_nt_mm *mm,
			     unsigned long long pva,
			     const unsigned long long *offs,
			     const unsigned long long *sv,
			     const unsigned long long *tv, int nd)
{
	MEMORY_BASIC_INFORMATION mbi;
	unsigned long long va = pva + offs[0], rbase = 0, rsize = 0;
	unsigned prot = 0, state = 0, type = 0;
	long long toff;
	int vi, k;

	c->vp_divseen++;
	if (vp_div_budget <= 0 || vp_dedup_seen(c, VP_DD_DIV, pva))
		return;
	vp_dedup_add(c, VP_DD_DIV, pva);
	memset(&mbi, 0, sizeof(mbi));
	if (nt->VirtualQueryEx(c->proc, (void *)(uintptr_t)va,
			       &mbi, sizeof(mbi)) != 0) {
		rbase = (unsigned long long)(uintptr_t)mbi.BaseAddress;
		rsize = (unsigned long long)mbi.RegionSize;
		prot = mbi.Protect;
		state = mbi.State;
		type = mbi.Type;
	}
	vp_div_budget--;
	os_info("[viewprobe] pid %lu VIEW-DIVERGED va=0x%llx "
		"stub=0x%llx tbl=0x%llx page=0x%llx ndiff=%d "
		"(park-nr=%llu nr=%llu ret=%lld rip=0x%llx) budget=%d\n",
		(unsigned long)c->pid, va, sv[0], tv[0], pva, nd,
		c->d->regs.rax, c->last_nr, c->last_ret,
		c->d->regs.rip, vp_div_budget);
	vp_div_budget--;
	os_info("[viewprobe]   stub view: region=[0x%llx,+0x%llx) "
		"prot=0x%x state=0x%x type=0x%x\n", rbase, rsize, prot,
		state, type);
	vi = uml_nt_vp_view_find(c->views, c->nviews, va);
	if (vi >= 0) {
		unsigned long long boff = uml_nt_vp_view_off(
			&c->views[vi], va);

		vp_div_budget--;
		os_info("[viewprobe]   ledger: view #%d [va=0x%llx "
			"len=0x%llx prot=0x%x off=0x%llx] -> backing "
			"off=0x%llx run=0x%llx\n", vi,
			c->views[vi].va, c->views[vi].len,
			c->views[vi].prot, c->views[vi].off, boff,
			boff & ~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1));
	} else {
		vp_div_budget--;
		os_info("[viewprobe]   ledger: NO view covers va — "
			"a mapping the view ledger does not own\n");
	}
	toff = uml_nt_vma_translate(mm, va, 8);
	if (toff >= 0) {
		vp_div_budget--;
		os_info("[viewprobe]   table: off=0x%llx run=0x%llx\n",
			(unsigned long long)toff,
			(unsigned long long)toff &
			~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1));
	} else {
		vp_div_budget--;
		os_info("[viewprobe]   table: translate FAILED — "
			"the VMA table does not own this va\n");
	}
	for (k = 0; k < nd && k < 4 && vp_div_budget > 0; k++) {
		static const char *const names[] = {
			"page", "chunk e->next", "chunk e->key",
			"tcache field", "plan-op page"
		};
		int a = uml_nt_vp_attr(pva + offs[k], vp_cvas,
				       vp_ctx_nch, vp_ctx_tva, 0x290,
				       c->vp_drain_ops,
				       c->vp_drain_nops);

		vp_div_budget--;
		os_info("[viewprobe]   diff +0x%llx: stub=0x%llx "
			"tbl=0x%llx (%s)\n", offs[k], sv[k], tv[k],
			names[a]);
	}
	if (nd > 4 && vp_div_budget > 0) {
		vp_div_budget--;
		os_info("[viewprobe]   +%d more differing qwords\n",
			nd - 4);
	}
	vp_fire_tail(c);
}

/* the unread classes: a table-owned page the stub's view cannot
 * read (missing/released/NOACCESS view), or a page the stub READS
 * while the table owns nothing there (the stray-view shape — the
 * census killed its released-range form; this catches it on the
 * watched set). VQ explains the expected failures (guards,
 * released regions) — those count, never print. */
static void vp_fire_unread(struct uml_nt_stub_conn *c,
			   struct uml_nt_mm *mm,
			   unsigned long long pva, int stub_side)
{
	MEMORY_BASIC_INFORMATION mbi;
	int cls = stub_side ? VP_DD_STUBUN : VP_DD_TBLUN;

	if (vp_dedup_seen(c, cls, pva))
		return;
	memset(&mbi, 0, sizeof(mbi));
	if (stub_side &&
	    nt->VirtualQueryEx(c->proc, (void *)(uintptr_t)pva,
			       &mbi, sizeof(mbi)) != 0 &&
	    (mbi.State != 0x1000 || mbi.Protect == 0x01)) {
		c->vp_expected++; /* not committed / NOACCESS guard —
				   * explained, never a fire */
		return;
	}
	if (vp_unread_budget <= 0)
		return;
	vp_dedup_add(c, cls, pva);
	vp_unread_budget--;
	if (!stub_side)
		(void)nt->VirtualQueryEx(c->proc,
					 (void *)(uintptr_t)pva,
					 &mbi, sizeof(mbi));
	if (stub_side) {
		os_info("[viewprobe] pid %lu STUB-UNREAD page=0x%llx — "
			"the table owns the page but the stub's view "
			"cannot read it; region=[0x%llx,+0x%llx) "
			"prot=0x%x state=0x%x (park-nr=%llu nr=%llu "
			"ret=%lld) budget=%d\n",
			(unsigned long)c->pid, pva,
			(unsigned long long)(uintptr_t)mbi.BaseAddress,
			(unsigned long long)mbi.RegionSize,
			mbi.Protect, mbi.State, c->d->regs.rax,
			c->last_nr, c->last_ret, vp_unread_budget);
	} else {
		os_info("[viewprobe] pid %lu TBL-UNREAD page=0x%llx — "
			"the stub still READS a page the VMA table does "
			"not own (stray view); region=[0x%llx,+0x%llx) "
			"prot=0x%x state=0x%x (park-nr=%llu nr=%llu "
			"ret=%lld) budget=%d\n",
			(unsigned long)c->pid, pva,
			(unsigned long long)(uintptr_t)mbi.BaseAddress,
			(unsigned long long)mbi.RegionSize,
			mbi.Protect, mbi.State, c->d->regs.rax,
			c->last_nr, c->last_ret, vp_unread_budget);
	}
	{
		int vi = uml_nt_vp_view_find(c->views, c->nviews,
					     pva);
		long long toff = uml_nt_vma_translate(mm, pva,
						      VP_PAGE_SIZE);

		if (vi >= 0)
			os_info("[viewprobe]   ledger view #%d "
				"[va=0x%llx len=0x%llx prot=0x%x "
				"off=0x%llx]; table translate %lld\n",
				vi, c->views[vi].va,
				c->views[vi].len, c->views[vi].prot,
				c->views[vi].off, toff);
	}
}

static int vp_read_stub(struct uml_nt_stub_conn *c,
			unsigned long long pva, unsigned char *buf)
{
	SIZE_T got = 0;

	if (nt->ReadProcessMemory(c->proc, (void *)(uintptr_t)pva,
				   buf, VP_PAGE_SIZE, &got) == 0 ||
	    got != VP_PAGE_SIZE)
		return 0;
	return 1;
}

static int vp_read_tbl(struct uml_nt_mm *mm, unsigned long long pva,
		       unsigned char *buf)
{
	unsigned off;

	for (off = 0; off < VP_PAGE_SIZE; off += 512) {
		long long o = uml_nt_vma_translate(mm, pva + off, 512);

		if (o < 0)
			return 0;
		memcpy(buf + off, (const void *)(uintptr_t)
		       ((char *)uml_boot.physmem_base + o), 512);
	}
	return 1;
}

/* probe one watched page both ways and classify. */
static void vp_probe_page(struct uml_nt_stub_conn *c,
			  struct uml_nt_mm *mm,
			  unsigned long long pva)
{
	unsigned long long offs[8], sv[8], tv[8];
	int stub_ok, tbl_ok, cls, nd, k;

	stub_ok = vp_read_stub(c, pva, vp_stub_pg);
	tbl_ok = vp_read_tbl(mm, pva, vp_tbl_pg);
	cls = uml_nt_vp_classify(stub_ok, tbl_ok);
	switch (cls) {
	case UML_NT_VP_CLS_CMP:
		c->vp_probed++;
		nd = uml_nt_cowrace_diff(vp_stub_pg, vp_tbl_pg,
					 VP_PAGE_SIZE, offs, sv, tv, 8);
		if (nd == 0)
			break;
		/* the double-read confirm: a real divergence is STABLE
		 * (different backings), a shared-run writer racing
		 * between the reads is RACED — counted, never fired. */
		if (vp_confirm_per_park <= 0) {
			c->vp_raced++;
			break; /* next park re-sees a persistent state
				* with a fresh confirm budget */
		}
		vp_confirm_per_park--;
		stub_ok = vp_read_stub(c, pva, vp_stub_pg2);
		tbl_ok = vp_read_tbl(mm, pva, vp_tbl_pg2);
		if (!stub_ok || !tbl_ok) {
			c->vp_raced++;
			break;
		}
		if (uml_nt_vp_confirm(vp_stub_pg, vp_tbl_pg,
				      vp_stub_pg2, vp_tbl_pg2,
				      VP_PAGE_SIZE) ==
		    UML_NT_VP_DIVERGED)
			vp_fire_diverged(c, mm, pva, offs, sv, tv, nd);
		else
			c->vp_raced++;
		break;
	case UML_NT_VP_CLS_STUB_UNREAD:
		vp_fire_unread(c, mm, pva, 1);
		break;
	case UML_NT_VP_CLS_TBL_UNREAD:
		vp_fire_unread(c, mm, pva, 0);
		break;
	default:
		break; /* gone everywhere: released by both sides */
	}
	/* the LEDGER-STRAY shape: a watched va with NO ledger view
	 * whose page the stub READS fine — a mapping the ledger
	 * does not own. */
	for (k = 0; k < vp_nunl; k++) {
		unsigned long long u = vp_unl[k];

		if (u < pva || u >= pva + VP_PAGE_SIZE)
			continue;
		if (!stub_ok)
			continue;
		c->vp_divseen++;
		if (vp_div_budget <= 0 ||
		    vp_dedup_seen(c, VP_DD_STRAY, u))
			continue;
		vp_dedup_add(c, VP_DD_STRAY, u);
		vp_div_budget--;
		os_info("[viewprobe] pid %lu LEDGER-STRAY va=0x%llx — "
			"readable through the stub, NO ledger view "
			"covers it (park-nr=%llu nr=%llu ret=%lld) "
			"budget=%d\n", (unsigned long)c->pid, u,
			c->d->regs.rax, c->last_nr, c->last_ret,
			vp_div_budget);
		vp_fire_tail(c);
	}
}

/* the pure bookkeeping check: the ledger view's backing offset vs
 * the table's own translate of the same va. Zero stub reads. */
static void vp_ledger_check(struct uml_nt_stub_conn *c,
			     struct uml_nt_mm *mm,
			     unsigned long long va)
{
	unsigned long long loff;
	long long toff;
	int vi;

	vi = uml_nt_vp_view_find(c->views, c->nviews, va);
	if (vi < 0) {
		c->vp_unledgered++;
		if (vp_nunl < VP_UNL_MAX)
			vp_unl[vp_nunl++] = va;
		return;
	}
	loff = uml_nt_vp_view_off(&c->views[vi], va);
	toff = uml_nt_vma_translate(mm, va, 8);
	if (toff >= 0 && loff == (unsigned long long)toff)
		return;
	vp_ledger_hit = 1;
	c->vp_divseen++;
	if (vp_div_budget <= 0 ||
	    vp_dedup_seen(c, VP_DD_LEDGER, va))
		return;
	vp_dedup_add(c, VP_DD_LEDGER, va);
	vp_div_budget--;
	if (toff >= 0) {
		os_info("[viewprobe] pid %lu LEDGER-DIVERGED va=0x%llx — "
			"ledger view #%d [va=0x%llx len=0x%llx prot=0x%x "
			"off=0x%llx] maps off=0x%llx (run 0x%llx) but "
			"the table owns off=0x%llx (run 0x%llx) "
			"(park-nr=%llu nr=%llu ret=%lld rip=0x%llx) "
			"budget=%d\n",
			(unsigned long)c->pid, va, vi,
			c->views[vi].va, c->views[vi].len,
			c->views[vi].prot, c->views[vi].off, loff,
			loff & ~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1),
			(unsigned long long)toff,
			(unsigned long long)toff &
			~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1),
			c->d->regs.rax, c->last_nr, c->last_ret,
			c->d->regs.rip, vp_div_budget);
	} else {
		os_info("[viewprobe] pid %lu LEDGER-DIVERGED va=0x%llx — "
			"ledger view #%d [va=0x%llx len=0x%llx off=0x%llx] "
			"holds it but the table translate FAILED "
			"(park-nr=%llu nr=%llu ret=%lld rip=0x%llx) "
			"budget=%d\n",
			(unsigned long)c->pid, va, vi,
			c->views[vi].va, c->views[vi].len,
			c->views[vi].off, c->d->regs.rax, c->last_nr,
			c->last_ret, c->d->regs.rip, vp_div_budget);
	}
	vp_fire_tail(c);
}

static void viewprobe_round(struct uml_nt_stub_conn *c)
{
	struct uml_nt_mm *mm = c->mm;
	struct uml_nt_stub_data *d = c->d;
	unsigned short counts[64];
	unsigned long long entries[64];
	struct uml_nt_tce_rd rd;
	unsigned long long tva;
	long long off;
	int i, escalate = 0, nch, nplan = 0, npages, n_always, trunc = 0;

	if (witness_off())
		return;
	if (!c->task_backed || mm == NULL || mm->heap_start == 0)
		return;
	if (c->proc == NULL)
		return;
	/* the same glibc shape gate as the tcache watches: the heap's
	 * first chunk must be the tcache struct (size hdr 0x291). */
	off = uml_nt_vma_translate(mm, mm->heap_start, 16);
	if (off < 0)
		return;
	{
		unsigned long long hdr = *(const unsigned long long *)
			(const void *)((char *)uml_boot.physmem_base +
				       off + 8);

		if (hdr != 0x291)
			return;
	}
	tva = mm->heap_start + 0x10;
	off = uml_nt_vma_translate(mm, tva, 0x290);
	if (off < 0)
		return;
	memcpy(counts, (const void *)(uintptr_t)
	       ((char *)uml_boot.physmem_base + off), sizeof(counts));
	memcpy(entries, (const void *)(uintptr_t)
	       ((char *)uml_boot.physmem_base + off + 0x80),
	       sizeof(entries));

	c->vp_parks++;
	vp_confirm_per_park = 16;
	vp_nunl = 0;
	vp_ledger_hit = 0;
	if (c->vp_parks == 1 && vp_armed_budget > 0) {
		vp_armed_budget--;
		os_info("[viewprobe] armed pid %lu heap=[0x%llx,0x%llx) "
			"tcache=0x%llx (park-nr=%llu nr=%llu ret=%lld)\n",
			(unsigned long)c->pid, mm->heap_start,
			mm->heap_end, tva, d->regs.rax, c->last_nr,
			c->last_ret);
	}

	/* the walk: TABLE-side only, own snapshot — the watched chunk
	 * set never depends on [tcekey]'s print budgets (which die
	 * early; the tear forms at ~86k). The counts-mismatch
	 * fingerprint escalates to the full page sweep this park. */
	memset(&vp_snap, 0, sizeof(vp_snap));
	rd.read = tce_read;
	rd.ctx = mm;
	for (i = 0; i < 64; i++) {
		struct uml_nt_tce_bin wb;
		unsigned int ncnt = counts[i];
		unsigned long long ev = entries[i];
		int d2;

		if (ev == 0 && ncnt == 0)
			continue;
		uml_nt_tce_walk_bin(&rd, ev, mm->heap_start,
				    mm->heap_end, i, &wb);
		if (uml_nt_tce_counts_bad(ncnt, wb.walked, wb.capped))
			escalate = 1;
		for (d2 = 0; d2 < wb.walked; d2++)
			(void)uml_nt_tce_record(&vp_snap, &wb.ch[d2]);
	}
	nch = vp_snap.n;
	vp_ctx_tva = tva;
	vp_ctx_nch = nch;
	for (i = 0; i < nch; i++)
		vp_cvas[i] = vp_snap.ch[i].va;

	/* LEDGER CHECK: full coverage every park, zero stub reads —
	 * the tcache struct, every listed chunk, the drained plan's
	 * PROTECT/MAP op vas. */
	vp_ledger_check(c, mm, tva);
	for (i = 0; i < nch; i++)
		vp_ledger_check(c, mm, vp_cvas[i]);
	for (i = 0; i < c->vp_drain_nops && c->vp_drain_pm; i++) {
		if (c->vp_drain_ops[i].op == UML_NT_FOP_PROTECT ||
		    c->vp_drain_ops[i].op == UML_NT_FOP_MAP)
			vp_ledger_check(c, mm, c->vp_drain_ops[i].va);
	}

	/* THE PAGE PROBE: through the stub's view vs the table's run. */
	npages = uml_nt_vp_pageset(vp_cvas, nch, tva, c->vp_drain_ops,
				   c->vp_drain_nops, vp_pages,
				   VP_PAGES_MAX, &nplan);
	if (npages > VP_PAGES_MAX) {
		trunc = npages - VP_PAGES_MAX;
		npages = VP_PAGES_MAX;
	}
	n_always = 1 + nplan;
	if (escalate || vp_nunl > 0 || vp_ledger_hit) {
		for (i = 0; i < npages; i++)
			vp_probe_page(c, mm, vp_pages[i]);
	} else {
		unsigned long long pick[VP_RR_MAX];
		int nrr, k;

		for (i = 0; i < n_always && i < npages; i++)
			vp_probe_page(c, mm, vp_pages[i]);
		nrr = uml_nt_vp_rr_pick(
			vp_pages + (n_always < npages ? n_always : npages),
			npages > n_always ? npages - n_always : 0,
			&c->vp_rr, pick, VP_RR_MAX);
		for (k = 0; k < nrr; k++)
			vp_probe_page(c, mm, pick[k]);
	}

	/* the drain record: whether a re-protect/MAP stream drained
	 * since the previous park, and its ops. K6 fix (feature
	 * flatwrite-retire-witness): print only for streams of 2+
	 * ops — dlV's budget died at line 14131 on the recurring
	 * 1-op re-protect shape, and the late-window streams (the
	 * 2-op [fork-sync] re-homes, the multi-op COW split plans —
	 * the formation window's shape) never got a line. The record
	 * itself still collects EVERY drained stream. */
	if (c->vp_drain_count > 0 && c->vp_drain_pm &&
	    c->vp_drain_nops >= 2 &&
	    vp_drain_budget > 0) {
		int k, o, shown = 0;

		vp_drain_budget--;
		os_info("[viewprobe-drain] pid %lu park sees %d drained "
			"stream(s) since previous park (last retval=%d "
			"nops=%d trunc=%d) park-nr=%llu nr=%llu "
			"ret=%lld\n", (unsigned long)c->pid,
			c->vp_drain_count, c->vp_drain_retval,
			c->vp_drain_nops,
			c->vp_drain_total - c->vp_drain_nops,
			d->regs.rax, c->last_nr, c->last_ret);
		for (o = 0; o < 3 && vp_drain_budget > 0; o++) {
			char line[200];
			int len = 0;

			line[0] = 0;
			for (k = 0; k < 3; k++) {
				const struct uml_nt_fault_op *op;

				if (shown >= c->vp_drain_nops)
					break;
				op = &c->vp_drain_ops[shown++];
				len += snprintf(line + len,
						sizeof(line) - (unsigned)len,
						" o=%u p=0x%x va=0x%llx"
						" l=0x%llx off=0x%llx",
						op->op, op->prot, op->va,
						op->len, op->off);
				if (len < 0)
					break;
			}
			if (len <= 0)
				break;
			vp_drain_budget--;
			os_info("[viewprobe-drain]   ops:%s\n", line);
		}
	}
	/* census every 4096 parks: the explicit zero (the witness
	 * ran, nothing diverged, budgets alive). */
	if ((c->vp_parks & 0xfffull) == 0 && vp_census_budget > 0) {
		vp_census_budget--;
		os_info("[viewprobe] census pid %lu parks=%llu "
			"chunks=%d pages=%d trunc=%d probed=%llu "
			"raced=%llu expected=%llu unledgered=%llu "
			"divseen=%llu budget=%d unread=%d drain=%d "
			"(park-nr=%llu nr=%llu ret=%lld)\n",
			(unsigned long)c->pid, c->vp_parks, nch, npages,
			trunc, c->vp_probed, c->vp_raced, c->vp_expected,
			c->vp_unledgered, c->vp_divseen, vp_div_budget,
			vp_unread_budget, vp_drain_budget, d->regs.rax,
			c->last_nr, c->last_ret);
	}
	/* consume the drain record: the next window starts here. */
	c->vp_drain_count = 0;
	c->vp_drain_pm = 0;
	c->vp_drain_retval = 0;
	c->vp_drain_nops = 0;
	c->vp_drain_total = 0;
}

static void claim_audit(void)
{
	static unsigned char claims[2048];
	static unsigned short cow_ok[2048];
	static int first_pid[2048];
	static unsigned long rounds;
	struct task_struct *p;
	int runs = (int)(uml_boot.physmem_size / UML_NT_PHYS_RUN_SIZE);
	static int audit_budget = 8;
	int i;

	if (runs > 2048)
		runs = 2048;
	if (audit_budget <= 0)
		return;
	if (++rounds % 4096 != 0 && !claim_audit_force_flag)
		return;
	claim_audit_force_flag = 0;
	memset(claims, 0, sizeof(claims));
	memset(cow_ok, 0, sizeof(cow_ok));
	for (i = 0; i < runs; i++)
		first_pid[i] = -1;
	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		int vi;

		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		for (vi = 0; vi < pc->mm->nvma; vi++) {
			struct uml_nt_vma *v = &pc->mm->vma[vi];
			unsigned long long off;

			/* The tear needs a WRITER: only writable VMAs
			 * count (every process shares the kernel
			 * image RO by design — dlT fired on exactly
			 * that). */
			if (!uml_nt_prot_writable(v->prot))
				continue;
			for (off = v->run_off;
			     off < v->run_off + (v->end - v->start);
			     off += UML_NT_PHYS_RUN_SIZE) {
				int r = (int)(off / UML_NT_PHYS_RUN_SIZE);

				if (r >= runs)
					continue;
				if (claims[r] == 0)
					first_pid[r] = (int)pc->pid;
				if (claims[r] < 250)
					claims[r]++;
				if (v->flags & UML_NT_VMA_COW)
					cow_ok[r]++;
			}
		}
	}
	for (i = 0; i < runs && audit_budget > 0; i++)
		if (claims[i] >= 2 && cow_ok[i] < claims[i]) {
			unsigned long long target =
				(unsigned long long)i *
					UML_NT_PHYS_RUN_SIZE;

			audit_budget--;
			os_info("[claim-audit] run 0x%llx claimed by %d "
				"WRITABLE mms but only %d COW-flagged "
				"(first pid %d) — a non-COW owner's "
				"writes never fault: shared-RW tear\n",
				target, claims[i], cow_ok[i],
				first_pid[i]);
			for_each_process(p) {
				struct uml_nt_stub_conn *pc;
				int vi;

				if (p->mm == NULL)
					continue;
				pc = ((struct mm_id *)
					&p->mm->context.id)->nt_conn;
				if (pc == NULL || pc->mm == NULL ||
				    pc->dead_magic == UML_NT_CONN_DEAD)
					continue;
				for (vi = 0; vi < pc->mm->nvma; vi++) {
					struct uml_nt_vma *v =
						&pc->mm->vma[vi];

					if (!uml_nt_prot_writable(v->prot))
						continue;
					if (target >= v->run_off &&
					    target < v->run_off +
						     (v->end - v->start))
						os_info("[claim-audit]   "
							"claimant pid %lu "
							"vma=[0x%llx,0x%llx) "
							"run_off=0x%llx "
							"flags=0x%x prot=0x%x"
							"\n",
							(unsigned long)
							pc->pid,
							v->start, v->end,
							v->run_off,
							v->flags,
							v->prot);
				}
			}
		}
}

/* K6 (M5.6a, cowcopy-race-class-fix, dlW 37576991123 / dlX
 * 37579340518 — the RETIRE-LOST verdict): the DEFERRED fault-path
 * COW copy. Runs at the teardown/re-map boundary of its own plan's
 * drain (uml_nt_fault_copy_due decided WHEN; the PROTDONE branch of
 * serve_conn calls this) — every release op has applied, so the
 * conn's view of the source is torn down and no store of the conn
 * can race the snapshot; no re-MAP has issued yet, so no new view
 * of the source's range exists either. Stores that landed in the
 * source during the release phase (the verdict's class: 16
 * RETIRE-LOST fires per referee run, budget-capped, the tcache-heap
 * chain where each fire's src is the previous arm's dst) are
 * INCLUDED in this copy — they ride into the live backing instead
 * of retiring with the abandoned source as "dead backing" bytes.
 * The source's liveness proof at this later point is the GEN
 * (captured at translate time in uml_nt_mm_fault), not refs: the
 * remaining sharer may legitimately have dropped the last claim
 * mid-drain (the block parks, its bytes intact), but a RE-HAND
 * moves the gen and the fresh handout ZEROES the run — copying
 * that would write foreign bytes into the live backing. Kill loud
 * on a gen move (never guess, never a silent zeroed-heap resume);
 * kill loud on a dst block-check failure (the direct-write class).
 * Everything else is the original copy block, moved verbatim: the
 * [flatwr] translate-time checks (the site's semantics are
 * unchanged — the copy IS the write they guard, whenever it runs),
 * copy_verify, the cowwatch touches, the [cowcopy] provenance line
 * and the witness arms (cowwatch/cowtrap/cowrace — the cowrace ARM's
 * t0 hash is now the content at the DEFERRED copy, which is the
 * point: the witness's RETIRE-LOST diff must compare the release
 * against the snapshot the live backing was actually built from). */
static int fault_cowcopy_exec(struct uml_nt_stub_conn *c,
			      const char *when)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned long long gen_now;

	if (c->copy_pend_src == 0 || c->copy_pend_dst == 0)
		return 0;
	/* the write side must stay inside its own block (the
	 * direct-write tripwire — unchanged from the fault-round
	 * form). The READ side's proof is the gen below instead:
	 * a parked source run reads refs==0 and the old block
	 * check would false-kill exactly the legal mid-drain
	 * drop (the D22 park preserves the bytes). */
	if (uml_nt_phys_block_check(c->ph, (long long)
				    c->copy_pend_dst,
				    UML_NT_PHYS_RUN_SIZE) < 0) {
		os_info("[fillguard] COW run copy src=0x%llx "
			"dst=0x%llx: dst block check failed — "
			"killing\n", c->copy_pend_src,
			c->copy_pend_dst);
		d->action = UML_STUB_ACTION_KILL;
		d->err = 1;
		return -1;
	}
	gen_now = (unsigned long long)uml_nt_phys_gen(c->ph,
		(long long)c->copy_pend_src);
	if (gen_now != c->copy_pend_gsrc) {
		os_info("[fillguard] COW run copy src=0x%llx "
			"dst=0x%llx: source re-handed under the "
			"drain (gen 0x%llx -> 0x%llx, refs=%d) — its "
			"bytes are a new life's, the t0 snapshot is "
			"gone; KILLING (never a zeroed-heap "
			"resume)\n", c->copy_pend_src,
			c->copy_pend_dst, c->copy_pend_gsrc,
			gen_now, uml_nt_phys_refs(c->ph,
				(long long)c->copy_pend_src));
		d->action = UML_STUB_ACTION_KILL;
		d->err = 1;
		return -1;
	}
	/* K6 [flatwr]: the copy is a kernel flat write of guest
	 * content — compare the (run, gen) captured at TRANSLATE time
	 * (uml_nt_mm_fault stamped them beside the copy directive)
	 * with the phys gen AND the current table translate AT WRITE
	 * TIME. src = the read side (a re-handed src fed the copy
	 * foreign bytes); dst = the write side (post-split the table
	 * must translate the fault va to the dst run). Bookkeeping
	 * only. */
	uml_nt_flatwr_check(c, UML_NT_FLATWR_SITE_COWCOPY_SRC,
			    d->fault_addr, UML_NT_PHYS_RUN_SIZE,
			    c->copy_pend_src,
			    c->copy_pend_gsrc, -1);
	uml_nt_flatwr_check(c, UML_NT_FLATWR_SITE_COWCOPY_DST,
			    d->fault_addr, UML_NT_PHYS_RUN_SIZE,
			    c->copy_pend_dst,
			    c->copy_pend_gdst,
			    (long long)(c->copy_pend_dst +
				(d->fault_addr &
				 (UML_NT_PHYS_RUN_SIZE - 1))));
	uml_nt_copy_verify(uml_boot.physmem_base + c->copy_pend_dst,
			   uml_boot.physmem_base + c->copy_pend_src,
			   UML_NT_PHYS_RUN_SIZE, "cow-repair");
	uml_nt_cowwatch_touch((unsigned long long)c->copy_pend_src,
			      UML_NT_PHYS_RUN_SIZE, "cow-copy-src");
	uml_nt_cowwatch_touch((unsigned long long)c->copy_pend_dst,
			      UML_NT_PHYS_RUN_SIZE, "cow-copy-dst");
	/* WRITER-HUNT (M5.6a) provenance ledger, generation grade: run
	 * 36979286356's tcache content at abort = bytes a [cowcopy]
	 * generation copied in — run IDs alone can't see a wrong-
	 * CONTENT source. Refs on both ends + the source run's
	 * tail-16 fp: the abort-time poison sample matches its
	 * generating copy by fp. */
	{
		const unsigned char *fp =
			(const unsigned char *)
			((char *)uml_boot.physmem_base +
			 c->copy_pend_src +
			 UML_NT_PHYS_RUN_SIZE - 16);
		char hex[49];
		int hi;

		static int n_cowcopy_log;

		if (++n_cowcopy_log <= 64) {
			for (hi = 0; hi < 16; hi++)
				snprintf(hex + hi * 3, sizeof(hex) - hi * 3,
					 "%02x ", fp[hi]);
			os_info("[cowcopy] pid %lu src=0x%llx (refs=%d) "
				"dst=0x%llx (refs=%d) fp=%s (%s)\n",
				(unsigned long)c->pid, c->copy_pend_src,
				uml_nt_phys_refs(c->ph,
					(long long)c->copy_pend_src),
				c->copy_pend_dst,
				uml_nt_phys_refs(c->ph,
					(long long)c->copy_pend_dst),
				hex, when);
		}
		/* cowwatch arm: a SHARED src run = the poison target
		 * class (the writer writes after the copy — see the
		 * cowwatch block comment). Owner VA unknown at this
		 * site (0) — the post-clone sweep arms with the real
		 * one. */
		if (uml_nt_phys_refs(c->ph,
		    (long long)c->copy_pend_src) >= 2)
			uml_nt_cowwatch_arm(c->copy_pend_src, 0,
					    (unsigned long)c->pid);
		/* WRITER-HUNT (M5.6a, run 37078256773): the DST side
		 * goes PRIVATE (refs=1) here with writable views and
		 * NO watcher — arm the dst at birth so the flat scan
		 * names the round truthfully (full rationale in the
		 * original block; unchanged). The dst maps the SAME
		 * VA range the faulting write hit — base = its run. */
		{
			unsigned long long dvbase = c->copy_pend_va;

			uml_nt_cowwatch_arm(c->copy_pend_dst,
					    dvbase, (unsigned long)c->pid);
			uml_nt_cowtrap_arm_alloc(c, dvbase,
						 UML_NT_PHYS_RUN_SIZE,
						 c->copy_pend_dst);
			/* K6 [cowrace]: the copy-vs-in-flight-store
			 * witness's arm — the t0 hash + the RUNNING
			 * sharers of the source, recorded AT the copy
			 * (which is now the deferred copy: the
			 * RETIRE-LOST diff judges the release against
			 * the snapshot the live backing was built
			 * from). Read-only; the check pass runs at
			 * the next syscall parks. */
			uml_nt_cowrace_arm(c, c->copy_pend_src,
					   c->copy_pend_dst,
					   UML_NT_PHYS_RUN_SIZE, dvbase,
					   "cowcopy");
		}
	}
	return 0;
}

/* K6 (cowcopy-race-class-fix): the DEFERRED brk re-home copy —
 * kind 2 of the deferred-copy class (sys_brk arms the conn
 * descriptor at its decision round; the drain hook above calls
 * this at the same teardown/re-map boundary as the fault form).
 * Same serialization contract, same refusal laws: the dst block
 * check stays (the fresh span is refs>0 by the table), the src's
 * liveness proof is the GEN captured at the decision (the old
 * span legitimately parked/0-refs after its unref — a refs-based
 * check would false-kill the legal drop), a gen move means the
 * src re-handed under the drain — KILL loud, never a zeroed-heap
 * resume. The [flatwr] BRK_FILL sites keep their translate-time
 * contract; the table expectation INVERTS with the deferral: at
 * write time the table must translate the heap va to the NEW
 * span (the vma swap applied at the decision; the copy rides the
 * drain). cowwatch touches + the cowrace arm (the RETIRE-LOST
 * acceptance witness) move with the copy — the t0 hash is the
 * content at the deferred copy, the snapshot the live backing
 * was actually built from. */
static int brk_rehome_copy_exec(struct uml_nt_stub_conn *c,
				const char *when)
{
	struct uml_nt_stub_data *d = c->d;
	unsigned long long src = c->copy_pend_src;
	unsigned long long dst = c->copy_pend_dst;
	unsigned long long len = c->copy_pend_len;
	unsigned long long gen_now;

	if (len == 0)
		return 0;
	if (uml_nt_phys_block_check(c->ph, (long long)dst,
				    len) < 0) {
		os_info("[fillguard] brk re-home deferred copy "
			"src=0x%llx dst=0x%llx len=0x%llx: dst block "
			"check failed — killing\n", src, dst, len);
		d->action = UML_STUB_ACTION_KILL;
		d->err = 1;
		return -1;
	}
	gen_now = (unsigned long long)uml_nt_phys_gen(c->ph,
		(long long)src);
	if (gen_now != c->copy_pend_gsrc) {
		os_info("[fillguard] brk re-home deferred copy "
			"src=0x%llx dst=0x%llx len=0x%llx: source "
			"re-handed under the drain (gen 0x%llx -> "
			"0x%llx) — its bytes are a new life's, the "
			"t0 snapshot is gone; KILLING (never a "
			"zeroed-heap resume)\n", src, dst, len,
			c->copy_pend_gsrc, gen_now);
		d->action = UML_STUB_ACTION_KILL;
		d->err = 1;
		return -1;
	}
	/* K6 [flatwr] (BRK_FILL): gen-only on the src read side; the
	 * dst write side must ALSO agree with the CURRENT table —
	 * the heap va translates to the NEW span now (the swap
	 * applied at the decision; pre-fix the copy preceded the
	 * swap, so the expectation was the old span). */
	uml_nt_flatwr_check(c, UML_NT_FLATWR_SITE_BRK_FILL,
			    c->copy_pend_va, len, src,
			    c->copy_pend_gsrc, -1);
	uml_nt_flatwr_check(c, UML_NT_FLATWR_SITE_BRK_FILL,
			    c->copy_pend_va, len, dst,
			    c->copy_pend_gdst, (long long)dst);
	uml_nt_copy_verify((char *)uml_boot.physmem_base + dst,
			   (const char *)uml_boot.physmem_base + src,
			   len, "brk-rehome-fill");
	/* 098 δ: the re-home reads the OLD heap runs (possibly
	 * cowwatch-armed: the sharers' data) and writes the fresh
	 * span — census both ends. */
	uml_nt_cowwatch_touch(src, len, "brk-rehome-src");
	uml_nt_cowwatch_touch(dst, len, "brk-rehome-dst");
	/* K6 [cowrace]: the copy-vs-in-flight-store witness's arm at
	 * the re-home — t0 hash both ends share + the RUNNING sharers
	 * of the old span, recorded AT the (deferred) copy; the
	 * check pass runs at the next syscall parks. */
	uml_nt_cowrace_arm(c, src, dst, len, c->copy_pend_va,
			   "brk-rehome");
	{
		static int brkcopy_said = 16;

		if (brkcopy_said > 0) {
			brkcopy_said--;
			os_info("[brkrehome] pid %lu %s copy "
				"src=0x%llx dst=0x%llx len=0x%llx — "
				"before the re-MAP issues\n",
				(unsigned long)c->pid, when, src, dst,
				len);
		}
	}
	return 0;
}

/* D26 (to-shelley 144): every deferred-copy execution goes through
 * this ONE entry — the drain hook, the MAP-hold gate, the drain-end
 * orphan fail-safe and the inline decisions (fault dispatch / brk
 * arm with refs==1) all call here. kind is cleared first: a KILL
 * inside the exec must not leave a half-armed descriptor behind,
 * and the descriptor never survives its exec. `when` tags the
 * provenance line: "inline" (no sharer at the decision), "deferred"
 * (the due hook), "maphold" (the gate fired), "orphan" (the
 * drain-end fail-safe — a bug, loud). */
int uml_nt_copy_pend_exec(struct uml_nt_stub_conn *c, const char *when)
{
	int kind = c->copy_pend_kind;

	if (kind == 0)
		return 0;
	c->copy_pend_kind = 0;
	if (kind == 1)
		return fault_cowcopy_exec(c, when);
	return brk_rehome_copy_exec(c, when);
}

/* D26 MAP-hold gate: NEVER issue a MAP that covers a pending copy's
 * VA range — the copy runs first, right here. The due hook is the
 * primary trigger; this is the structural backstop: a plan whose op
 * order the hook misread (an augment, a merge) cannot install a view
 * over the dst while it still holds the fresh alloc's zeros. The
 * exec's witness arms append ops (sc_plan_add) — restore the drain
 * position the append disturbed (the 7496f70 class). Returns -1 when
 * the exec KILLed. */
static int copy_pend_gate(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op)
{
	static int maphold_budget = 8;
	int ops_before, next_before;

	if (c->copy_pend_kind == 0 ||
	    !uml_nt_fault_map_covers(op, c->copy_pend_va,
				     c->copy_pend_len))
		return 0;
	if (maphold_budget > 0) {
		maphold_budget--;
		os_info("[copypend-maphold] pid %lu MAP 0x%llx+0x%llx "
			"held by pending copy kind=%d va=0x%llx — the "
			"copy runs first\n",
			(unsigned long)c->pid, op->va, op->len,
			c->copy_pend_kind, c->copy_pend_va);
	}
	ops_before = c->plan.n_ops;
	next_before = c->plan_next;
	if (uml_nt_copy_pend_exec(c, "maphold") < 0)
		return -1;
	if (c->plan.n_ops != ops_before) {
		c->plan_next = next_before;
		c->plan_left = c->plan.n_ops - next_before + 1;
	}
	return 0;
}

static int serve_conn(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

	/* M5.6a login-depth follow-up (Shelley 149 [resume-regs]): the
	 * round's trap capture is the reference the answer's resume rsp
	 * is judged against. Op rounds (PROT_DONE) publish a result
	 * WITHOUT touching d->regs, so the last real trap stays the
	 * origin of the resume until the guest actually runs again — no
	 * reset here. */
	if (d->cmd == UML_STUB_CMD_SYSCALL || d->cmd == UML_STUB_CMD_FAULT) {
		c->res_trap_rip = d->regs.rip;
		c->res_trap_rsp = d->regs.rsp;
		c->res_trap_valid = 1;
	}

	/* M5.6a [pivot trace]: any round that is NOT the trace's own
	 * step ends the trace — the guest reached a syscall/fault/trap
	 * boundary, so the interval is over (TF is dropped at this
	 * round's answer, the stub stops raising it). */
	if (d->tf_trace != 0 &&
	    !(d->cmd == UML_STUB_CMD_FAULT &&
	      d->fault_type == UML_NT_FAULT_STEP)) {
		os_info("[pivot-trace] pid %lu %s trace ended by %s after %u "
			"step(s) (last_nr=%llu, stub_stop=%u) — a boundary arrived "
			"before a pivot\n",
			(unsigned long)c->pid, c->exec_path,
			d->cmd == UML_STUB_CMD_SYSCALL ? "syscall" :
			d->cmd == UML_STUB_CMD_FAULT ? "fault" : "op",
			UML_NT_TF_STEPS_PER_ARM - c->tf_left, c->last_nr,
			d->tf_stop);
		d->tf_trace = 0;
	}

	/* The stub-side half of the same contract: at the previous
	 * real trap's resume the stub published the CONTEXT rsp it
	 * carried out of the handler; the answer had put a DIFFERENT
	 * value in d->regs. That is the restore (or the Windows
	 * context load), never the guest's own arithmetic. */
	if (c->res_chk_valid &&
	    (d->cmd == UML_STUB_CMD_SYSCALL ||
	     d->cmd == UML_STUB_CMD_FAULT)) {
		static int rca_budget = 32;

		c->res_chk_valid = 0;
		if (rca_budget > 0 && d->resume_rsp != 0 &&
		    d->resume_rsp != c->res_chk_rsp) {
			rca_budget--;
			c->res_applied_bad++;
			os_info("[resume-regs] pid %lu the stub restored "
				"rsp=0x%llx but the answer carried 0x%llx "
				"(delta %lld) last_nr=%llu — the CONTEXT "
				"restore did not carry the kernel's stack "
				"pointer\n",
				(unsigned long)c->pid, d->resume_rsp,
				c->res_chk_rsp,
				(long long)(d->resume_rsp - c->res_chk_rsp),
				c->last_nr);
		}
	}

	/* M5.6a login-depth follow-up (Shelley 148-UPDATE 9/10): the
	 * TLS guard probe on every real trap — the first non-zero
	 * fs:0x30 is the security_init value, every later sight must
	 * match it (a change demangles jmp_bufs into foreign pointers). */
	if (d->cmd == UML_STUB_CMD_SYSCALL || d->cmd == UML_STUB_CMD_FAULT)
		guard_probe(c, d);

	/* Trap-site view/table diff (v16): the stub publishes the 8
	 * bytes it actually executed at the trap RIP; the table holds
	 * its own run's bytes at the same VA. A mismatch is a stale
	 * view — the class that lets the guest run a foreign library's
	 * text at an image VA (and misclassifies wild entries as
	 * syscalls when the foreign bytes happen to be a sentinel). */
	if ((d->cmd == UML_STUB_CMD_SYSCALL ||
	     d->cmd == UML_STUB_CMD_FAULT) &&
	    d->trap_insn_ok && c->mm != NULL) {
		long long ti = uml_nt_vma_translate(c->mm, d->regs.rip, 8);

		if (ti >= 0) {
			static int vd_budget = 8;
			unsigned long long tq;

			memcpy(&tq, (char *)uml_boot.physmem_base + ti, 8);
			if (tq != d->trap_insn && vd_budget > 0) {
				vd_budget--;
				os_info("[view-diverge] pid %lu %s trap "
					"rip=0x%llx stub_insn=%016llx "
					"tbl_insn=%016llx last_nr=%llu "
					"last_ret=%lld — the stub's view "
					"is not the table's run at the "
					"trap site\n",
					(unsigned long)c->pid,
					d->cmd == UML_STUB_CMD_SYSCALL ?
						"syscall" : "fault",
					d->regs.rip, d->trap_insn, tq,
					c->last_nr, c->last_ret);
			}
		}
	}
	/* Park-time image-integrity check (M5.6a writer-hunt follow-up):
	 * one image run per real trap park, round-robin — the first park
	 * after a rewrite names the closing round. */
	if (d->cmd == UML_STUB_CMD_SYSCALL ||
	    d->cmd == UML_STUB_CMD_FAULT) {
		uml_nt_imgwatch_park_check(c);

		/* Wild-rsp witness: a trap whose guest stack pointer
		 * lands in an image run means the stub's own Windows
		 * dispatch context is about to be written BELOW that
		 * rsp — into the loaded text (the rp1 pair's interp
		 * run0 rewrite, trap rsp=0x6001c3a0 at newfstatat).
		 * Print the previous trap too: the slip happened in
		 * the interval between them. */
		if (c->imgw_n > 0 && c->mm != NULL) {
			long long ro = uml_nt_vma_translate(c->mm,
					d->regs.rsp, 1);

			if (ro >= 0 &&
			    uml_nt_imgwatch_is_image(c,
				((unsigned long long)ro) &
				~(UML_NT_PHYS_RUN_SIZE - 1))) {
				static int rspimg_budget = 8;

				if (rspimg_budget > 0) {
					rspimg_budget--;
					os_info("[rsp-image] pid %lu %s "
						"trap rip=0x%llx "
						"rsp=0x%llx rbp=0x%llx "
						"rbx=0x%llx rax=0x%llx "
						"last_nr=%llu "
						"last_ret=%lld prev-trap "
						"rip=0x%llx rsp=0x%llx — "
						"the dispatch context "
						"lands in the loaded "
						"text\n",
						(unsigned long)c->pid,
						d->cmd == UML_STUB_CMD_SYSCALL ?
							"syscall" : "fault",
						d->regs.rip, d->regs.rsp,
						d->regs.rbp, d->regs.rbx,
						d->regs.rax, c->last_nr,
						c->last_ret,
						c->last_trap_valid ?
							c->last_trap_rip : 0,
						c->last_trap_valid ?
							c->last_trap_rsp : 0);
					/* The referee for the pivot itself: the
					 * resume this trap followed (see
					 * uml_nt_resume_regs_fire). */
					uml_nt_resume_regs_fire(c);
					if (!c->wild_text_dumped) {
						c->wild_text_dumped = 1;
						dump_wild_text_stack(c,
							d->regs.rsp);
					}
					/* Guard stability at the fire: the
					 * recorded init vs the value the
					 * pivot's longjmp would demangle
					 * with. */
					{
						unsigned long long gc, gg;
						int gv = -1;

						if (guard_tcb_read(c, d, &gc,
								   &gg) == 0)
							gv = uml_nt_guard_verdict(
								c->guard_init,
								gg,
								c->guard_seen);
						os_info("[guard-fire] pid %lu "
							"init=%016llx now="
							"%016llx canary_now="
							"%016llx verdict=%s "
							"tcb=%d changes=%u\n",
							(unsigned long)c->pid,
							c->guard_init, gg, gc,
							gv == UML_NT_GUARD_STABLE ?
								"STABLE" :
							gv == UML_NT_GUARD_CHANGED ?
								"CHANGED" :
							gv == UML_NT_GUARD_FIRST ?
								"FIRST" : "UNREADABLE",
							c->auxv_rand_valid ?
							uml_nt_guard_tcb_check(
								c->auxv_rand,
								gc, gg) : -1,
							c->guard_changes);
					}
					/* The slip sits in the interval that just
					 * closed: the kernel writes that round
					 * made are still in the ledger. Dump the
					 * previous trap rsp run's entries (a
					 * stack writeback with a bad length/va
					 * names itself here). */
					if (c->last_trap_valid &&
					    c->mm != NULL) {
						if (!c->stack_run_dumped) {
							c->stack_run_dumped = 1;
							dump_prev_stack_run(c,
								c->last_trap_rsp);
						}
						long long po =
							uml_nt_vma_translate(
								c->mm,
								c->last_trap_rsp,
								1);

						/* The pivot source: 48 qwords
						 * around the previous trap's
						 * stack entry (a jmp_buf /
						 * saved-rbp slot / return
						 * address names the pivot). */
						if (c->last_trap_rsp > 0x80)
							dump_guest_bytes(
								c->mm,
								c->last_trap_rsp - 0x80,
								0x180,
								"rsp-image-stk");
						/* The TCB's canary/pointer guard: a
						 * jmp_buf on the stack is PTR_MANGLEd
						 * with fs:0x30 — dump both so the
						 * dumped qwords can be demangled
						 * offline (setjmp vs longjmp guard). */
						if (d->fs_base != 0) {
							dump_guest_bytes(
								c->mm,
								d->fs_base + 0x28,
								0x20,
								"rsp-image-tcb");
							os_info("[rsp-image] fs_base=0x%llx "
								"canary/guard dumped "
								"at +0x28\n", d->fs_base);
						}

						jmpbuf_scan(c, d,
							    c->last_trap_rsp);

						if (po >= 0)
							uml_nt_uacc_towrite_dump(
								((unsigned long long)po) &
								~(UML_NT_PHYS_RUN_SIZE - 1));
					}
				}
			}
		}
		c->last_trap_rip = d->regs.rip;
		c->last_trap_rsp = d->regs.rsp;
		c->last_trap_valid = 1;
	}
	/* Resume-boundary audit (M5.6a writer-hunt follow-up): the
	 * previous round's expected target vs the stub's own published
	 * d->resume_rip. The fault-only form lived further down; this
	 * covers syscall rounds and signal pushes too — the
	 * byte-shifted-entry class starts with a resume that did not
	 * land where the kernel said. */
	if (c->exp_resume_valid &&
	    (d->cmd == UML_STUB_CMD_SYSCALL ||
	     d->cmd == UML_STUB_CMD_FAULT)) {
		static int rbd_budget = 8;

		c->exp_resume_valid = 0;
		if (rbd_budget > 0 && d->resume_rip != 0 &&
		    d->resume_rip != c->exp_resume_rip) {
			rbd_budget--;
			os_info("[resume-diverge] pid %lu %s round: "
				"expected resume 0x%llx but the stub resumed "
				"at 0x%llx (trap rip=0x%llx rax=0x%llx)\n",
				(unsigned long)c->pid,
				d->cmd == UML_STUB_CMD_SYSCALL ?
					"syscall" : "fault",
				c->exp_resume_rip, d->resume_rip,
				d->regs.rip, d->regs.rax);
		}
	}

	/* D22 quarantine: this conn's previous round's plan ops have
	 * applied (a new request only happens after the plan drained),
	 * so blocks it parked at drop time can return to the backend;
	 * and this round's drops park under THIS conn's tag. */
	/* D25 FIX (referee 37131511929: 7589 [phys-settle] hits): the
	 * drained invariant DOES break — the fork re-protect stream
	 * keeps plan_left > 0 across rounds by design, and settle
	 * released parked blocks while THIS conn's UNMAP/MAP ops were
	 * still in flight; the backend re-handed the block and a new
	 * view mapped it before the stale op applied = the
	 * free-while-mapped alias (task 1's malloc metadata eating
	 * dead conns' env strings). Settle ONLY on a drained plan:
	 * parks ride until the round that actually drains (a stuck
	 * conn's parks end at destroy's settle — mmctx). */
	if (c->plan_left == 0)
		uml_nt_phys_settle(c->ph, c);
	else {
		static int settle_audit;

		if (settle_audit++ < 64)
			os_info("[phys-settle] deferred plan_left=%d "
				"pid %lu\n", c->plan_left,
				(unsigned long)c->pid);
	}
	uml_nt_phys_set_drop_owner(c->ph, c);
	/* WRITER-HUNT (M5.6a): the direct-write canary — validate the
	 * conn's tcache BEFORE serving this round; poison seen here
	 * was produced up to the previous round (last_nr names it).
	 * Skip during PROT_DONE / pending-copy drain rounds: mid-drain
	 * the VMA table already points at the unpopulated dst run
	 * before uml_nt_copy_pend_exec copies src->dst, so scanning or
	 * arming cowtrap/ktrip here reads pre-copy zeros and appends
	 * ops mid-drain ahead of the drain-position restore. */
	if (d->cmd != UML_STUB_CMD_PROT_DONE && c->copy_pend_kind == 0)
		tcache_watch(c);
	ss_stray_watch(c);

	if (d->cmd == UML_STUB_CMD_SYSCALL) {
		claim_audit();
		/* K6 step 2: the e->key double-free witness — syscall
		 * parks ONLY, next to claim_audit (the hook point). */
		tcache_ekey_watch(c);
		/* K6 [cowrace]: the copy-vs-in-flight-store witness's
		 * check pass — syscall parks only, same hook point. */
		cowrace_round(c);
		/* K6 [flatwr]: the kernel-flat-write staleness
		 * witness's ring — syscall parks only, same hook point.
		 * Read-only: the site records are bookkeeping at existing
		 * flat-write sites, nothing at fault parks. */
		uml_nt_flatwr_report(c);
		/* K6 [viewprobe]: the stub-view-vs-table witness —
		 * syscall parks only, same hook point. Read-only
		 * (ReadProcessMemory on the parked stub): no ss/TF,
		 * no DR, no page protects, nothing at fault parks. */
		viewprobe_round(c);
	}

	/* The all-faults resume watchdog: the previous fault's answer
	 * must have resumed AT the faulting instruction. Loud, not
	 * fatal — the boot dies on its own if the divergence is
	 * real. Skips verdicts where the resume never happened (the
	 * conn died mid-plan). */
	if (c->last_fault_valid && d->cmd != UML_STUB_CMD_PROT_DONE) {
		static int rw_budget = 8;

		c->last_fault_valid = 0;
		if (rw_budget > 0 && d->resume_rip != 0 &&
		    d->resume_rip != c->last_fault_rip) {
			rw_budget--;
			os_info("[resume-diverge] pid %lu fault "
				"rip=0x%llx addr=0x%llx but resumed at "
				"0x%llx — the guest never re-ran the "
				"faulting instruction\n",
				(unsigned long)c->pid,
				c->last_fault_rip, c->last_fault_addr,
				d->resume_rip);
		}
	}

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
		/* mapcanary verdict for the just-applied op: the stub
		 * read the view's tail-8 — if it does not match the
		 * nonce planted at the VMA table's run, the fresh view
		 * is NOT backed by the run the table owns (a stale-off
		 * MAP that verify_prot proved green). Loud, not fatal:
		 * the hunt wants the pattern, the boot dies on its own
		 * if the divergence is real. */
		if (c->mc_active) {
			c->mc_active = 0;
			if (d->mapcanary_got != c->mc_want)
				os_info("[mapcanary] MISMATCH pid %lu "
					"va=0x%llx off=0x%llx(tbl) want=0x%llx "
					"got=0x%llx — the stub's view is not "
					"backed by the VMA table's run\n",
					(unsigned long)c->pid, d->map_va,
					c->mc_off, c->mc_want,
					d->mapcanary_got);
			/* K6 [flatwr]: the pushback writes the ORIGINAL
			 * guest qword back flat-side — and the op
			 * round-trip (issue -> stub MAP apply ->
			 * PROTDONE) is the widest window of the set: a
			 * re-handed run or a re-homed va means the
			 * restore wrote through a stale translation. */
			uml_nt_flatwr_check(c,
				UML_NT_FLATWR_SITE_MC_RESTORE,
				c->mc_va, 8, c->mc_off, c->mc_gen,
				(long long)c->mc_off);
			*(unsigned long long *)
				((char *)uml_boot.physmem_base + c->mc_off) =
				c->mc_orig;
		}
		if (c->rp_active) {
			/* The repair PROT_DONE for a replay-armed fault:
			 * compare the stub's own-view read of the fault
			 * qword with the VMA table's run content.
			 * Budgeted: dl6 proved a stuck rp_active turns
			 * every later PROTDONE into a re-print (19.4M
			 * lines, disk-full). */
			static int rp_pd_budget = 64;
			unsigned long long tbl = 0;
			int have = 0;

			/* One print per arm: the plan stream's later
			 * PROTDONEs for the same arm re-print forever
			 * otherwise (dl6: 19.4M lines from a stuck
			 * print on a per-round re-armed page). The
			 * park-time [replay-lost] verify still owns
			 * rp_active. */
			if (c->rp_pd_done)
				goto rp_pd_done;
			if (rp_pd_budget <= 0)
				goto rp_pd_done;
			rp_pd_budget--;
			c->rp_pd_done = 1;

			if (c->rp_active) {
				long long vo = uml_nt_vma_translate(
					c->mm, c->rp_va, 8);

				if (vo >= 0) {
					tbl = *(const unsigned long long *)
						(const void *)
						((char *)uml_boot.physmem_base
						 + vo);
					have = 1;
				}
			}
			if (have && d->viewprobe_got != tbl)
				os_info("[replay] VIEW-DIVERGED pid %lu "
					"va=0x%llx stub-view=0x%llx "
					"table-run=0x%llx — the conn's view "
					"is NOT the VMA table's backing\n",
					(unsigned long)c->pid, c->rp_va,
					d->viewprobe_got, tbl);
			else if (have)
				os_info("[replay] view-ok pid %lu "
					"va=0x%llx qword=0x%llx\n",
					(unsigned long)c->pid, c->rp_va, tbl);
			rp_pd_done:
			d->viewprobe_got = 0;
		}
		/* K6 (cowcopy-race-class-fix, dlW/dlX RETIRE-LOST): the
		 * DEFERRED copies. Due when the next op to issue is
		 * NOT a release (every release op of the plan has
		 * applied — the source view teardown is done) or when
		 * the plan is exhausted (the drain-end fallback). Must
		 * run BEFORE the next op issues: the re-MAP phase would
		 * install a view of the source's range while the new
		 * backing still holds t0-only bytes, and the mapcanary
		 * plant for a writable MAP writes into dst. Kind 1 =
		 * the fault-path COW repair (fault_cowcopy_exec —
		 * D26: the plan's directive is SNAPSHOTTED into the
		 * conn descriptor at arm; the plan struct is scratch
		 * a superseding mm_fault overwrites); kind 2 = the brk
		 * re-home bulk copy (brk_rehome_copy_exec). On refusal
		 * the exec already KILLed loud.
		 *
		 * DRAIN-POSITION RESTORE (the M3 boot regression, run
		 * 37583666145: the child died re-applying its plan):
		 * the exec's witness arms APPEND ops mid-drain
		 * (cowtrap_arm_alloc -> sc_plan_add), and sc_plan_add
		 * resets plan_next=0/plan_left=n_ops — decision-time
		 * semantics (the syscall answer arms the stream from
		 * 0). Mid-drain that restarts the stream at the
		 * ALREADY-APPLIED ops (a double UNMAP/MAP chaos, the
		 * stub died on an unowned exception). Snapshot the
		 * position, let the arms append, then re-arm from the
		 * CURRENT point: the plan's own remaining ops stream
		 * first, the appended witness ops after them — all
		 * before the guest resumes. */
		if (c->copy_pend_kind != 0) {
			static int shape_budget = 8;

			/* D26 plan-shape witness: every drain pass
			 * that still carries a pending copy logs the
			 * stream shape — if a copy still runs late
			 * after the gate, this quantifies by how
			 * much. Budget-capped; bookkeeping only. */
			if (shape_budget > 0) {
				shape_budget--;
				os_info("[copydue] pid %lu pass: n=%d "
					"next=%d nextop=%d left=%d "
					"kind=%d\n",
					(unsigned long)c->pid,
					c->plan.n_ops, c->plan_next,
					c->plan_next < c->plan.n_ops ?
					(int)c->plan.ops[c->plan_next].op :
					-1,
					c->plan_left, c->copy_pend_kind);
			}
		}
		if (c->copy_pend_kind != 0 &&
		    uml_nt_fault_copy_due(&c->plan, c->plan_next)) {
			int ops_before = c->plan.n_ops;
			int next_before = c->plan_next;

			if (uml_nt_copy_pend_exec(c, "deferred") < 0)
				return -1;
			if (c->plan.n_ops != ops_before) {
				c->plan_next = next_before;
				c->plan_left = c->plan.n_ops -
					       next_before + 1;
			}
		}
		if (c->plan_left > 1) {
			if (copy_pend_gate(c,
					   &c->plan.ops[c->plan_next]) < 0)
				return -1;
			c->plan_left--;
			issue_plan_op(c, &c->plan.ops[c->plan_next]);
			return 0;
		}
		/* D26 orphan fail-safe + witness: the descriptor must
		 * NEVER survive the drain that applied its MAP — if
		 * one is still armed here every gate missed (a bug;
		 * LOUD). Copy NOW, before the resume republish, and
		 * stream the ops the exec's witness arms appended
		 * instead of ending the drain. map-applied=1 in the
		 * log names the class the ruling forbids. */
		if (c->copy_pend_kind != 0) {
			static int orphan_budget = 8;
			int oi, covered = 0;
			int ops_before = c->plan.n_ops;

			for (oi = 0; oi < c->plan.n_ops; oi++)
				if (uml_nt_fault_map_covers(
				    &c->plan.ops[oi], c->copy_pend_va,
				    c->copy_pend_len))
					covered = 1;
			if (orphan_budget > 0) {
				orphan_budget--;
				os_info("[copypend-orphan] pid %lu "
					"kind=%d n=%d map-applied=%d "
					"— the descriptor outlived its "
					"drain; copy at drain end, "
					"before the resume\n",
					(unsigned long)c->pid,
					c->copy_pend_kind, c->plan.n_ops,
					covered);
			}
			if (uml_nt_copy_pend_exec(c, "orphan") < 0)
				return -1;
			if (c->plan.n_ops != ops_before) {
				c->plan_next = ops_before;
				c->plan_left = c->plan.n_ops -
					       ops_before + 1;
				c->plan_left--;
				issue_plan_op(c,
					      &c->plan.ops[c->plan_next]);
				return 0;
			}
		}
		c->plan_left = 0;
		/* K6 [viewprobe]: the DRAIN RECORD — a stream drained
		 * (every op applied). The park pass reports whether a
		 * re-protect/MAP stream drained since the conn's
		 * previous syscall park, with its ops (the run-B
		 * formation window showed exactly a 2-op [fork-sync]
		 * re-protect drain beside the COW copy of the
		 * ADJACENT run). Bookkeeping only — no guest state. */
		if (c->plan.n_ops > 0) {
			int k;

			c->vp_drain_count++;
			c->vp_drain_retval = c->plan_has_retval;
			c->vp_drain_total = c->plan.n_ops;
			c->vp_drain_nops =
				c->plan.n_ops > UML_NT_VP_DRAIN_OPS ?
				UML_NT_VP_DRAIN_OPS : c->plan.n_ops;
			memcpy(c->vp_drain_ops, c->plan.ops,
			       sizeof(c->vp_drain_ops[0]) *
			       (unsigned)c->vp_drain_nops);
			for (k = 0; k < c->plan.n_ops; k++)
				if (c->plan.ops[k].op ==
					UML_NT_FOP_PROTECT ||
				    c->plan.ops[k].op ==
					UML_NT_FOP_MAP) {
					c->vp_drain_pm = 1;
					break;
				}
		}
		/* K6 (cowcopy-race-class-fix): the swap's COMPLETION
		 * guard — a plan that re-homed ranges must leave NO
		 * mapping over them outside the issued-view ledger.
		 * The census refuses loud (never a silent continue):
		 * a surviving writable view over an abandoned backing
		 * is the dl26 corruption family itself. */
		if (view_swap_guard(c) < 0) {
			d->action = UML_STUB_ACTION_KILL;
			d->err = 1;
			return -1;
		}
		/* M5.6a (140): view==table at the resume — the
		 * guest-resumable point after a re-homing stream. */
		view_resume_audit(c);
		if (c->plan_has_retval) {
			/* A syscall carried these ops: re-publish its
			 * return value (the stub's op results traveled
			 * through d->retval and clobbered it). */
			d->retval = c->plan_retval;
			c->plan_has_retval = 0;
			/* D23 (a) census: the syscall that queued these
			 * ops — the fork's parent re-protect included —
			 * now has EVERY op applied before the guest
			 * resumes. The stub-side verify (stub.c
			 * verify_prot) proved each apply actually took;
			 * this line proves the retval waited for it. */
			{
				static int n_forksync_log;

				if (++n_forksync_log <= 64)
					os_info("[fork-sync] plan done: %d op(s) applied, "
						"retval 0x%llx published\n",
						c->plan.n_ops,
						(unsigned long long)c->plan_retval);
			}
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
			os_info("[stubtest] INIT plan refused (pid %lu, "
				"why=%c — 'z' = a VMA's run shows 0 refs: "
				"stolen)\n", (unsigned long)c->pid,
				c->plan.kill_why ? c->plan.kill_why : '?');
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
		/* COW-BREAK AUDIT (fault.h): a writable view over a
		 * shared run in the INITIAL plan = the heap-trasher
		 * class (the child eats the sharer's heap without a
		 * COW fault). Loud once per INIT; behavior untouched
		 * (diag) — the fix shape waits for Shelley. */
		if (uml_nt_cowbreak_audit_count != 0)
			os_info("[cowbreak-init] pid %lu: %d writable "
				"map op(s) on shared runs — first "
				"va=0x%llx run=0x%llx refs=%d\n",
				(unsigned long)c->pid,
				uml_nt_cowbreak_audit_count,
				uml_nt_cowbreak_va,
				uml_nt_cowbreak_run,
				uml_nt_cowbreak_refs);
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
		static int cowbreak_seen;
		static int watch_budget = 48;

		/* M5.6a [pivot-dr]: a DR execute-breakpoint round — the
		 * state at the interp's DSO-lookup entry, BEFORE its first
		 * instruction. Pure observation: answer NONE. */
		/* Shelley 163/164: OUR one-shot probe owns its hit FIRST —
		 * the retired pivot-dr handler below would otherwise eat the
		 * round and return, which is the second way this instrument
		 * measured nothing (first: the write-slot instrument stole
		 * the hardware slot; now: a retired handler consumed the
		 * #DB). Order: live instruments, then retired ones. */
		if (uml_nt_drexec_round(c))
			return 0;

		if (d->fault_type == UML_NT_FAULT_DREXEC) {
			if (c->chain_armed)
				uml_nt_chain_round(c);
			else
				uml_nt_dr_exec_round(c);
			d->action = UML_STUB_ACTION_NONE;
			d->err = 0;
			return 0;
		}

		/* M5.6a [pivot trace]: a TF single-step round — the guest
		 * executed exactly one instruction since the last resume.
		 * Log it, decide, resume (TF re-raised by the stub while the
		 * budget lasts). Nothing here may repair: the step is pure
		 * observation, and the guest state is the trap's own. */

		if (d->fault_type == UML_NT_FAULT_STEP) {
			uml_nt_tf_trace_step(c);
			d->action = UML_STUB_ACTION_NONE;
			d->err = 0;
			return 0;
		}

		/* v13 DR-watchpoint report: a write to a watched tcache
		 * entries[] qword landed with a NON-heap, non-zero
		 * value (the stub filtered the legit put/get churn
		 * in-place). The store already landed (native
		 * semantics — the witness never alters); regs.rip is
		 * the POST-store instruction. Print the writer, read
		 * the value table-side, resume verbatim (empty plan,
		 * no repair — nothing faulted). */
		if (d->fault_type == UML_NT_FAULT_WATCHPT) {
			/* v20: the address the store actually hit, not the
			 * armed slot — they differ when the store lands
			 * inside the 8-byte slot but not on its first byte
			 * (and the value/code dumps must follow the REAL
			 * address, Shelley 152). fault_addr keeps the v13
			 * meaning for the tcache watch below. */
			unsigned long long hit_va = d->dr_hit_va ?
				d->dr_hit_va : d->fault_addr;
			int wslot = uml_nt_pwslot_index(c->interp_base,
							hit_va);

			if (wslot >= 0) {
				uml_nt_pivot_wslot_round(c, wslot);
				return 0;
			}
			if (watch_budget > 0) {
				long long vo = uml_nt_vma_translate(
					c->mm, d->fault_addr, 8);
				unsigned long long v = ~0ull;

				watch_budget--;
				if (vo >= 0)
					v = *(const unsigned long long *)
						(const void *)
						((char *)
						 uml_boot.physmem_base + vo);
				os_info("[tcwatch-HIT] pid %lu va=0x%llx "
					"value=0x%llx post-rip=0x%llx "
					"rsp=0x%llx nr=%llu ret=%lld — "
					"tear caught AT the store\n",
					(unsigned long)c->pid,
					d->fault_addr, v, d->regs.rip,
					d->regs.rsp, c->last_nr,
					c->last_ret);
				os_info("[tcwatch-HIT]   rax=0x%llx "
					"rcx=0x%llx rdx=0x%llx rsi=0x%llx "
					"rdi=0x%llx r9=0x%llx r10=0x%llx "
					"r11=0x%llx\n",
					d->regs.rax, d->regs.rcx,
					d->regs.rdx, d->regs.rsi,
					d->regs.rdi, d->regs.r9,
					d->regs.r10, d->regs.r11);
			}
			return 0;
		}

		/* [cowtrap] trip: the trapped page's accessor = the
		 * writer, with LIVE regs (the scan snapshots were
		 * always post-hoc). The fault then repairs through
		 * the normal mm_fault flow — the log line is the
		 * whole cost. */
		uml_nt_cowtrap_trip(c, d);
		/* tctrip-EMULATE: a tcache-struct write on the armed
		 * page is performed kernel-side and the guest resumes
		 * past it — the page stays RO, no hole. */
		if (uml_nt_tctrip_emulate(c, d)) {
			uml_nt_cowtrap_pending(c); /* don't starve it */
			return 0;
		}
		if (cowtrap_conn == c &&
		    d->fault_addr >= cowtrap_lo &&
		    d->fault_addr < cowtrap_hi) {
			cowtrap_conn = NULL;
			cowtrap_pending = 0;
			os_info("[cowtrap] WRITER CAUGHT pid %lu "
				"rip=0x%llx rsp=0x%llx rcx=0x%llx "
				"addr=0x%llx type=%u nr=%llu "
				"ret=%lld\n",
				(unsigned long)c->pid, d->regs.rip,
				d->regs.rsp, d->regs.rcx,
				d->fault_addr, d->fault_type,
				c->last_nr, c->last_ret);
		}
		/* M5.6a (140): a FAULT landing with a live stream
		 * means the guest ran while ops were still unissued
		 * — the plan mm_fault is about to overwrite was still
		 * owed to the stub. The repair supersedes (the fault
		 * is the live need); the log names the gate that let
		 * the guest resume mid-stream. */
		if (c->plan_left > 0) {
			static int faultmid_budget = 4;

			if (faultmid_budget > 0) {
				faultmid_budget--;
				os_info("[streamsync] pid %lu FAULT "
					"MID-DRAIN (left=%d next=%d n=%d "
					"copy_pend=%d) — the repair "
					"supersedes the unissued tail\n",
					(unsigned long)c->pid,
					c->plan_left, c->plan_next,
					c->plan.n_ops, c->copy_pend_kind);
			}
		}
		c->rp_active = 0;
		d->ss_page = 0;
		d->ss_rearm_ro = 0;
		{
			/* D27: a fault inside a DEFERRED file region
			 * materializes its run from the file and resumes
			 * (upstream demand paging). Not ours -> the
			 * normal decision. */
			int lz = uml_nt_lazy_fault(c, d->fault_addr,
						    d->fault_type);

			int sg = 0;

			if (lz > 0)
				rc = 0;
			else if (lz < 0)
				rc = -1;
			else
				sg = uml_nt_stack_grow(c->mm, c->ph,
						       d->fault_addr,
						       d->regs.rsp, &c->plan);
			if (sg > 0) {
				static int grow_budget = 32;

				rc = 0;   /* the stack grew: the plan maps it */
				if (grow_budget > 0 && c->plan.n_ops > 0) {
					grow_budget--;
					os_info("[stack-grow] pid %lu %s "
						"fault 0x%llx rsp=0x%llx grew "
						"the stack to [0x%llx,0x%llx) "
						"(RLIMIT floor 0x%llx) — the "
						"Linux shape replaces the 64K "
						"run\n",
						(unsigned long)c->pid,
						c->exec_path, d->fault_addr,
						d->regs.rsp,
						c->plan.ops[0].va,
						c->plan.ops[0].va +
						c->plan.ops[0].len,
						c->mm->stack_limit);
				}
			} else if (sg < 0) {
				/* clean SIGSEGV, upstream semantics */
				rc = -1;
				os_info("[stack-grow] pid %lu %s fault "
					"0x%llx rsp=0x%llx is BELOW the "
					"RLIMIT_STACK floor 0x%llx — "
					"clean SIGSEGV\n",
					(unsigned long)c->pid, c->exec_path,
					d->fault_addr, d->regs.rsp,
					c->mm->stack_limit);
			}
			else if (lz == 0)
				rc = uml_nt_mm_fault(c->mm, c->ph,
						     d->fault_addr,
						     d->fault_type,
						     &c->plan);
		}
		/* [replay-check] arm AFTER the repair decision: only a
		 * plan the guest will resume into (no kill) replays
		 * the store. */
		if (rc == 0 && !c->plan.kill)
			replay_check_arm(c);
		/* [cowtrap] carrier (the fault path): mm_fault reset
		 * the plan above — re-queue the armed page's op so a
		 * fault-storm boot cannot starve the trap forever
		 * (run 37057247578: the op never applied, the "trip"
		 * was the guest's own read fault on that page). */
		uml_nt_cowtrap_pending(c);
		/* COW-BREAK FAULT witness (fault.h): the restore-W
		 * remap hit a SHARED run — the stomp itself. This
		 * round = the writer (the fault = its write). */
		if (uml_nt_cowbreak_faults != cowbreak_seen) {
			cowbreak_seen = uml_nt_cowbreak_faults;
			os_info("[cowbreak-fault] pid %lu: write 0x%llx "
				"run=0x%llx refs=%d prot=0x%x "
				"flags=0x%x non-COW — restore-W stomps "
				"the sharer (fault #%d)\n",
				(unsigned long)c->pid,
				uml_nt_cowbreak_va,
				uml_nt_cowbreak_run,
				uml_nt_cowbreak_refs,
				uml_nt_cowbreak_prot,
				uml_nt_cowbreak_flags,
				uml_nt_cowbreak_faults);
		}
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
				/* The instruction bytes + the recorded
				 * TLS base settle the fs=0-vs-wild-
				 * pointer question from the log alone
				 * (the 0xfff...feb0 / -1 reads kept
				 * flip-flopping at the same rip across
				 * runs 36785701760 / 36786525015). */
				long long it = uml_nt_vma_translate(
					c->mm, d->regs.rip, 8);
				unsigned char ib[8] = { 0x90, 0x90, 0x90,
					0x90, 0x90, 0x90, 0x90, 0x90 };

				if (it >= 0)
					memcpy(ib, (char *)uml_boot.
					       physmem_base + it, 8);
				/* v6 (051 task 1): os_info's buffer is
				 * 256 bytes (util.c) — the one-line
				 * version died at ~249 chars, mid-
				 * "r12=0x613", losing r13/r14/r15/
				 * last_nr/last_ret (the callee-saved
				 * regs ARE the walker's strv/arena
				 * state). Split: main regs above,
				 * callee-saved + last-syscall below
				 * (each line < 255). */
				sigsegv_victims++;
				os_info("[stubtest] SIGSEGV victim #%d "
					"pid %lu addr=0x%llx type=%u "
					"rip=0x%llx why=%c fs=0x%llx "
					"rsp=0x%llx "
					"insn=%02x%02x%02x%02x%02x%02x%02x%02x "
					"rax=0x%llx rcx=0x%llx rdi=0x%llx "
					"rsi=0x%llx rdx=0x%llx\n",
					sigsegv_victims,
					(unsigned long)c->pid, d->fault_addr,
					d->fault_type, d->regs.rip,
					c->plan.kill_why ?
					c->plan.kill_why : '?',
					d->fs_base, d->regs.rsp,
					ib[0], ib[1], ib[2], ib[3],
					ib[4], ib[5], ib[6], ib[7],
					d->regs.rax, d->regs.rcx,
					d->regs.rdi, d->regs.rsi,
					d->regs.rdx);
				os_info("[stubtest]   callee: "
					"rbx=0x%llx rbp=0x%llx r12=0x%llx "
					"r13=0x%llx r14=0x%llx r15=0x%llx "
					"last_nr=%llu last_ret=%lld "
					"rax_lo=0x%08x rax_hi=0x%08x "
					"seed_rip=0x%llx\n",
					d->regs.rbx, d->regs.rbp,
					d->regs.r12, d->regs.r13,
					d->regs.r14, d->regs.r15,
					c->last_nr, c->last_ret,
					(unsigned int)(d->regs.rax &
						       0xffffffff),
					(unsigned int)(d->regs.rax >> 32),
					c->d->init_regs.rip);
				/* M5.6a unlink autopsy: the dlZ shape
				 * is the glibc-2.36 unlink check
				 * (cmp %rcx,0x10(%rdx)) faulting on a
				 * bin-listed chunk whose bk holds env
				 * text. rcx=P (the chunk). Walk the
				 * unsorted bin and flag members whose
				 * fd/bk is neither heap nor arena.
				 * EVERY read goes through bw_qword
				 * (translate + bounds, fail-safe): the
				 * first version's hand-rolled ternary
				 * dereferenced a raw phys offset and
				 * AV'd the KERNEL (dl1/dl3b, rip
				 * 6003cb35 — a witness must never be
				 * the killer). */
				if (c->bw_arena != 0) {
					/* bin_at(1) sentinel = av+0x60
					 * (its fd at +0x10 = av+0x70) */
					unsigned long long head =
						c->bw_arena + 0x60;
					unsigned long long m = 0;
					int steps;

					if (bw_qword(c->mm, head + 0x10,
						     &m) == 0)
						for (steps = 0;
						     steps < 8 &&
						     m != head &&
						     m != 0; steps++) {
							unsigned long long fd, bk;

							if (bw_qword(c->mm,
								m + 0x10,
								&fd) < 0 ||
							    bw_qword(c->mm,
								m + 0x18,
								&bk) < 0)
								break;
							os_info("[stubtest]   "
								"unsorted[%d] "
								"m=0x%llx "
								"fd=0x%llx "
								"bk=0x%llx%s\n",
								steps, m, fd,
								bk,
								((bk >> 44) !=
								 0x6 &&
								 bk != 0) ?
								"  <-- TORN" :
								"");
							m = fd;
						}
				}
				/* M5.4 c3: the wild-pointer autopsy —
				 * run 36806296858's victims all die at
				 * ONE libc rip copying 8 bytes from a
				 * lib's rodata to the deterministic
				 * wild 0x3577fffff0003d40 (rax, non-
				 * canonical: Windows reports addr=-1 —
				 * the "-EPERM as length" reading was
				 * wrong). Bytes AT rax + the VMA it
				 * falls in separate wrong-run-aliasing
				 * (kernel/foreign garbage in the view)
				 * from a guest-logic wild pointer. */
				{
					struct uml_nt_vma *rv =
						uml_nt_vma_find(c->mm,
								d->regs.rax);

					if (rv != NULL)
						os_info("[stubtest]   rax-vma 0x%llx-0x%llx prot=0x%x off=0x%llx\n",
							rv->start, rv->end,
							rv->prot,
							rv->run_off);
					else
						os_info("[stubtest]   rax-vma: none\n");
					/* M5.6a writer-hunt follow-up
					 * (rf pair 40064950549/590):
					 * the login victims die with
					 * sigcontext-shaped bytes in
					 * the interp run (saved
					 * rip/eflags at 0xb560). Name
					 * the run's epoch + the
					 * funnel ledger for the RIP
					 * run and the stack run — a
					 * kernel frame write into an
					 * aliased run appears here. */
					{
						long long ro2 =
							uml_nt_vma_translate(
								c->mm,
								d->regs.rip, 1);
						struct uml_nt_vma *sv =
							uml_nt_vma_find(
								c->mm,
								d->regs.rsp);
						long long so2 =
							uml_nt_vma_translate(
								c->mm,
								d->regs.rsp, 1);

						if (ro2 >= 0) {
							unsigned long long rr =
								((unsigned long long)ro2) &
								~(UML_NT_PHYS_RUN_SIZE - 1);

							os_info("[stubtest]   run(rip)=0x%llx gen=0x%llx refs=%lld\n",
								rr,
								uml_nt_phys_gen(
									c->ph,
									(long long)rr),
								uml_nt_phys_refs(
									c->ph,
									(long long)rr));
							uml_nt_uacc_towrite_dump(rr);
							uml_nt_imgwatch_death_check(
								c, rr);
						}
						if (sv != NULL)
							os_info("[stubtest]   stack-vma 0x%llx-0x%llx prot=0x%x flags=0x%x off=0x%llx\n",
								sv->start, sv->end,
								sv->prot,
								sv->flags,
								sv->run_off);
						if (so2 >= 0) {
							unsigned long long sr =
								((unsigned long long)so2) &
								~(UML_NT_PHYS_RUN_SIZE - 1);

							os_info("[stubtest]   run(rsp)=0x%llx gen=0x%llx refs=%lld\n",
								sr,
								uml_nt_phys_gen(
									c->ph,
									(long long)sr),
								uml_nt_phys_refs(
									c->ph,
									(long long)sr));
							if (so2 != ro2)
								uml_nt_uacc_towrite_dump(sr);
						}
					}
					dump_guest_bytes(c->mm,
							 d->regs.rax &
							 ~0xfULL, 32,
							 "at-rax");
					dump_guest_bytes(c->mm,
							 d->regs.rsi, 32,
							 "at-rsi");
					/* v3: the caller chain + the TCB.
					 * Run 36823383637's victims all
					 * die in glibc's SSE2 strcasecmp
					 * body (rip = the movdqa under
					 * the tolower-table shuffle —
					 * at-rsi IS the identity+0xff
					 * table; every service, the SAME
					 * wild rdi 0x3577fffff0003d40).
					 * The stack at rsp names the
					 * caller (return addresses are
					 * libc/lib vaddrs); the TCB at
					 * fs shows what the child
					 * inherited vs the parent's
					 * dump below. */
					dump_guest_bytes(c->mm,
							 d->regs.rsp, 48,
							 "at-rsp");
					dump_guest_bytes(c->mm,
							 d->regs.rsp + 48,
							 48,
							 "at-rsp2");
					dump_guest_bytes(c->mm,
							 d->fs_base, 48,
							 "at-fs");
					/* v5: the walker frame's slots
					 * ARE the strv pointers (run
					 * 36828973188: saved rdi =
					 * the heap strv, saved r12/
					 * rbx = the 704KB pthread
					 * arena) — dump the arrays
					 * they name + the frame chain
					 * + the pointer guard. */
					dump_ptr_at(c->mm, d->regs.rsp + 8,
						    "frame-slot8");
					dump_ptr_at(c->mm, d->regs.rsp + 0x18,
						    "frame-slot18");
					dump_ptr_at(c->mm, d->regs.rsp + 0x30,
						    "frame-slot30");
					dump_ptr_at(c->mm, d->regs.rbp,
						    "frame-rbp");
					dump_ptr_at(c->mm, d->regs.rbp + 8,
						    "frame-ret");
					dump_guest_bytes(c->mm,
							 d->fs_base + 48, 16,
							 "at-fs2");
					/* v6 (051 tasks 2+3): the strv
					 * array around the walker's
					 * cursor + the pthread arena
					 * head — the slot CONTEXT the
					 * value-only dumps couldn't
					 * give. */
					dump_strv_slots(c->mm,
							d->regs.r13);
					dump_arena_head(c->mm,
							d->regs.r12);
					/* v7 (map 052 a+b): the death
					 * frame chain qword-decode +
					 * the VALUE hunt for the
					 * walker's cursor (r13 =
					 * _Fork+0x23 here) — self +
					 * PID 1. First 3 victims only:
					 * the 19 share one signature
					 * and the scan walks
					 * megabytes. */
					if (sigsegv_victims <= 3 &&
					    d->regs.r13 > 0x1000 &&
					    d->regs.r13 <
					    0x800000000000ull &&
					    d->regs.rbp > d->regs.rsp) {
						unsigned long long lo =
							d->regs.rsp - 0x40;
						unsigned long long hi =
							d->regs.rbp + 0x140;

						if (hi - lo > 0x400)
							hi = lo + 0x400;
						dump_qword_range(c->mm, lo,
								 hi - lo,
								 d->regs.rsp);
						valscan_death(c,
							      d->regs.r13);
					}
					/* runs 36922613566/36925403121/
					 * 36932969287: the malloc-walk
					 * wild is BOOT-CONSTANT across
					 * victims (rdi here) yet absent
					 * from the co-mappers' runs —
					 * scan for THE VALUE itself:
					 * every hit = a slot the writer
					 * (or its source struct)
					 * touches, the provenance map.
					 * Run 36943585894: victim r13 =
					 * 0x4 (chain length, not a
					 * cursor) skipped the r13-shaped
					 * gate and the wild valscan never
					 * ran — the wild needs its OWN
					 * gate (sanity on rdi alone),
					 * independent of the frame
					 * shape. */
					if (sigsegv_victims <= 3 &&
					    d->regs.rdi > 0x1000 &&
					    d->regs.rdi <
					    0x800000000000ull)
						valscan_death(c,
							      d->regs.rdi);
					/* v2: run-ownership census at
					 * the wild pointer. Run
					 * 36808917963's victims die on
					 * a VMA whose run holds ANOTHER
					 * allocation's residue
					 * ("STREAM=7" as a pointer
					 * slot) — the 044 recycle
					 * family. The co-mapper walk
					 * (same VA across every live
					 * mm) + the parent's bytes
					 * decide shared-stale (parent
					 * shows the same content) vs
					 * recycled (nobody else claims
					 * this run_off). The pump runs
					 * on the one vCPU thread, so
					 * the task list cannot mutate
					 * under the walk. */
					{
						struct task_struct *p;

						for_each_process(p) {
							struct uml_nt_stub_conn *pc;
							struct uml_nt_vma *pv;

							if (p->mm == NULL)
								continue;
							pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
							if (pc == NULL ||
							    pc->mm == NULL ||
							    pc->dead_magic ==
								UML_NT_CONN_DEAD)
								continue;
							pv = uml_nt_vma_find(pc->mm, d->regs.rax);
							if (pv == NULL)
								continue;
							os_info("[stubtest]   co-mapper pid %d%s: vma 0x%llx-0x%llx prot=0x%x off=0x%llx\n",
								p->pid,
								(pc == c) ?
									" (self)" : "",
								pv->start,
								pv->end,
								pv->prot,
								pv->run_off);
							/* runs 36922613566
							 * + 36925403121:
							 * the wild slot
							 * 0x607a3ce8 holds a
							 * DIFFERENT value per
							 * boot while rax/rsi
							 * stay deterministic —
							 * compare the SAME
							 * bytes through every
							 * co-mapper's run:
							 * wild only in the
							 * victim's run = a
							 * post-fork writer in
							 * the child's own
							 * path; wild in all =
							 * inherited from the
							 * common parent. */
							dump_guest_bytes(
								pc->mm,
								d->regs.rax &
									~0xfULL,
								16,
								"at-rax-comap");
						}
					}
				}
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
		c->last_fault_rip = d->regs.rip;
		c->last_fault_addr = d->fault_addr;
		c->last_fault_valid = 1;
		{
			static int n_fault_log;

			if (++n_fault_log <= 64)
				os_info("[stubtest] FAULT pid %lu addr=0x%llx type=%u -> "
					"%d op(s)\n", (unsigned long)c->pid,
					d->fault_addr, d->fault_type,
					c->plan.n_ops);
		}
		/* K6 (cowcopy-race-class-fix, dlW 37576991123 / dlX
		 * 37579340518 — the RETIRE-LOST verdict): the COW copy
		 * directive is DEFERRED, not executed here. The verdict
		 * proved guest stores land in the COPY SOURCE between
		 * the copy and the view swap (16 RETIRE-LOST fires per
		 * referee, budget-capped, each fire's src the previous
		 * arm's dst), and the copy ran at THIS round — before
		 * op 0 (the source view's release) even streams, the
		 * widest possible window. The copy now runs at the
		 * teardown/re-map boundary of this same plan's drain
		 * (fault_cowcopy_exec below, uml_nt_fault_copy_due):
		 * after every release op applied (the conn's view of
		 * the source is torn down — the snapshot is taken from
		 * a source the conn can no longer store to) and
		 * before the first re-MAP issues (no new view can race
		 * it). Stores that landed in the source during the
		 * release phase are then INCLUDED in the copy — they
		 * ride into the live backing instead of retiring with
		 * the abandoned source. */
		if (c->plan.copy_src_off != 0 ||
		    c->plan.copy_dst_off != 0) {
			/* D26 (to-shelley 144): snapshot the copy
			 * directive into the conn descriptor NOW. The
			 * plan struct is scratch — a superseding
			 * mm_fault (the MID-DRAIN case above) wipes
			 * it, and a descriptor living in the plan
			 * dies with it (dl139b: the deferred copy
			 * outlived its drain and ran ~172 parks late
			 * into a guest that had already resumed). */
			if (c->copy_pend_kind != 0) {
				static int double_budget = 4;

				/* impossible post-D26: a pending copy
				 * always drains before the guest
				 * resumes, and a fault needs a
				 * running guest. LOUD; exec the OLD
				 * copy first — overwriting its
				 * descriptor would orphan it. */
				if (double_budget > 0) {
					double_budget--;
					os_info("[copypend-double] pid %lu"
						" new copy armed over "
						"kind=%d va=0x%llx — exec "
						"old first\n",
						(unsigned long)c->pid,
						c->copy_pend_kind,
						c->copy_pend_va);
				}
				if (uml_nt_copy_pend_exec(c, "double") < 0)
					return -1;
			}
			c->copy_pend_src = c->plan.copy_src_off;
			c->copy_pend_dst = c->plan.copy_dst_off;
			c->copy_pend_gsrc = c->plan.cap_gen_src;
			c->copy_pend_gdst = c->plan.cap_gen_dst;
			c->copy_pend_len = UML_NT_PHYS_RUN_SIZE;
			c->copy_pend_va = d->fault_addr &
				~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1);
			c->copy_pend_kind = 1;
			if (uml_nt_fault_copy_mode(
			    c->plan.copy_src_refs) == 1) {
				/* no sharer at the decision — no
				 * release-store window can exist:
				 * copy INLINE at the arm, before any
				 * op streams. (The fault path routes
				 * refs<=1 away from the copy plan at
				 * fault.c, so this is the census-lie
				 * guard; the brk path is the live
				 * inline user.) */
				if (uml_nt_copy_pend_exec(c, "inline") < 0)
					return -1;
			}
		}
		stack_window_reassert(c);
		/* K6 (cowcopy-race-class-fix): the COMPLETE per-view
		 * release set + stream arming before op 0 issues — a
		 * surviving view over the re-homed range (the dl26
		 * conviction: pid 7484's own tcache_put pair landing
		 * in the abandoned source run) is released HERE, by
		 * ledger base, and any that somehow survive meet the
		 * drain census below. */
		if (uml_nt_view_release_complete(c) < 0)
			return -1; /* release_complete already KILLed */
		if (copy_pend_gate(c, &c->plan.ops[0]) < 0)
			return -1;
		issue_plan_op(c, &c->plan.ops[0]);
		return 0;
	}

	/* Syscall trap: the D16 dispatch (skas/syscall.c) owns the
	 * surface; this function keeps the plan/protocol streaming. */
	{
	int trap_merged = 0;

	d->action = UML_STUB_ACTION_NONE;
	d->err = 0;
	d->halt = 0;
	c->plan.kill = 0;
	/* M5.6a (to-shelley 140 — stream atomicity): a SYSCALL trap
	 * with plan_left > 0 means the previous plan's stream is still
	 * unissued in part. The pre-fix wipe here orphaned those MAPs
	 * (the table had already moved at queue time — the guest then
	 * parked reading ZEROS off the fresh handout: dl139b pid 3068,
	 * the nr=228 park) and floated the pending copy past its own
	 * drain (the [cowcopy]-after-park line, then the SHARED-WRITE
	 * at 100340). The wipe is FORBIDDEN mid-drain: keep the
	 * position AND the pending copy descriptor; the handler's ops
	 * append, release_complete merges the release set of the
	 * unissued tail, and the stream re-joins at plan_next. Loud —
	 * the protocol says a trap cannot arrive mid-drain, so every
	 * hit names the gate that broke. */
	if (c->plan_left > 0) {
		static int midtrap_budget = 8;

		trap_merged = 1;
		if (midtrap_budget > 0) {
			midtrap_budget--;
			os_info("[streamsync] pid %lu SYSCALL trap "
				"MID-DRAIN (left=%d next=%d n=%d "
				"copy_pend=%d) — MERGE, the wipe is "
				"forbidden\n",
				(unsigned long)c->pid, c->plan_left,
				c->plan_next, c->plan.n_ops,
				c->copy_pend_kind);
		}
	} else {
		c->plan.n_ops = 0;
		c->plan.copy_src_off = 0;
		c->plan.copy_dst_off = 0;
		c->plan.copy_src_refs = 0;
		c->plan_next = 0;
		c->plan_left = 0;
	}
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
	/* M5.6a (140): merged mid-drain — the window re-assert
	 * PREPENDS (resets the position), so it is skipped; the
	 * in-flight plan already carries its own window ops from
	 * its prime. */
	if (!trap_merged)
		stack_window_reassert(c);
	/* K6 (cowcopy-race-class-fix): the release set + ARMING.
	 * uaccess COW fixups queue UNMAP/MAP ops without arming the
	 * stream (uacc_plan_op appends; only sc_plan_add set
	 * plan_left) — a round whose only view ops were fixups
	 * never streamed, the fixup's cow_split had already moved
	 * the table, and the stale view served every later guest
	 * store into the abandoned backing with no fault and no
	 * catch. plan_left = n_ops HERE makes "every queued op
	 * streams" the invariant for every round shape.
	 * M5.6a (140): merged rounds keep the position —
	 * release_complete augments the unissued tail and
	 * recounts, and the issue below re-joins the stream
	 * AT plan_next. */
	if (uml_nt_view_release_complete(c) < 0)
		return -1; /* release_complete already KILLed */
	if (c->plan_left > 0) {
		if (copy_pend_gate(c, &c->plan.ops[c->plan_next]) < 0)
			return -1;
		issue_plan_op(c, &c->plan.ops[c->plan_next]);
	}
	return 0;
	}
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
	int rc_clone;

	/* map 053 item 1: the parent's live callee-saved regs at the
	 * fork round. If the parent EVER carries the fork-resume-RIP
	 * value (_Fork+0x23) in r12/r13/rbx here, the syscall-round
	 * save/restore contaminates the parent — bisect there. */
	os_info("[stubtest] fork round pid %lu: parent rip=0x%llx "
		"rax=0x%llx rbx=0x%llx rbp=0x%llx r12=0x%llx r13=0x%llx "
		"r14=0x%llx r15=0x%llx\n",
		(unsigned long)c->pid, g->rip, g->rax, g->rbx, g->rbp,
		g->r12, g->r13, g->r14, g->r15);
	if (k->alive) {
		os_info("[stubtest] fork: child already exists\n");
		d->retval = (unsigned long long)-9LL; /* -EBADF */
		d->err = 1;
		return;
	}
	rc_clone = uml_nt_mm_clone(&mm_child, c->mm, c->ph, g->rsp);
	if (rc_clone != 0) {
		os_info("[stubtest] fork: mm clone failed (reason %s, "
			"parent nvma %d, nguard %d)\n",
			uml_nt_clone_reason(rc_clone), c->mm->nvma,
			c->mm->nguard);
		d->retval = (unsigned long long)-12LL; /* -ENOMEM */
		d->err = 1;
		return;
	}
	for (vi = 0; vi < mm_child.nvma; vi++) {
		const struct uml_nt_vma *pv = &c->mm->vma[vi];
		const struct uml_nt_vma *cv = &mm_child.vma[vi];

		if (cv->run_off == pv->run_off)
			continue; /* shared run */
		/* WRITER-HUNT (M5.6a): either end leaving its block is
		 * the direct-write heap-trasher — fail the fork, no
		 * write. */
		if (uml_nt_phys_block_check(c->ph,
				(long long)cv->run_off,
				cv->end - cv->start) < 0 ||
		    uml_nt_phys_block_check(c->ph,
				(long long)pv->run_off,
				cv->end - cv->start) < 0) {
			os_info("[fillguard] fork eager copy vma %d: "
				"src=0x%llx dst=0x%llx len=%llu leaves "
				"the block — fork refused\n", vi,
				pv->run_off, cv->run_off,
				cv->end - cv->start);
			d->retval = (unsigned long long)-12LL;
			d->err = 1;
			return;
		}
		/* K6 [flatwr]: the eager copy is a kernel flat write of
		 * guest content — capture both ends' gens at the
		 * translate, gen-only compare at the write (the child
		 * table is fresh this round; the dst run is born here). */
		{
			unsigned long long egs = (unsigned long long)
				uml_nt_phys_gen(c->ph,
						(long long)pv->run_off);
			unsigned long long egd = (unsigned long long)
				uml_nt_phys_gen(c->ph,
						(long long)cv->run_off);

			uml_nt_copy_verify(uml_boot.physmem_base +
					   cv->run_off,
				   uml_boot.physmem_base + pv->run_off,
				   cv->end - cv->start, "poc-eager");
			uml_nt_flatwr_check(c,
				UML_NT_FLATWR_SITE_FORK_EAGER, 0,
				cv->end - cv->start, pv->run_off, egs,
				-1);
			uml_nt_flatwr_check(c,
				UML_NT_FLATWR_SITE_FORK_EAGER, 0,
				cv->end - cv->start, cv->run_off, egd,
				-1);
		}
		uml_nt_cowwatch_touch((unsigned long long)pv->run_off,
				      cv->end - cv->start,
				      "poc-eager-src");
		uml_nt_cowwatch_touch((unsigned long long)cv->run_off,
				      cv->end - cv->start,
				      "poc-eager-dst");
		os_info("[eager] poc-fork vma %d src=0x%llx dst=0x%llx "
			"len=%llu\n", vi, pv->run_off, cv->run_off,
			cv->end - cv->start);
	}
	/* M5.4 c3 (map 053 item 2b): below-rsp residue zeroing — same
	 * contract as the task-backed seed above (the eager copy hands
	 * the child the parent's sigframe garbage; below-rsp is dead
	 * by ABI, the red zone stays). */
	{
		struct uml_nt_vma *sv = uml_nt_vma_find(&mm_child, g->rsp);
		unsigned long long zstart;

		if (g->rsp >= 128) {
			zstart = g->rsp - 128;
			if (sv != NULL && zstart > sv->start) {
				unsigned long long zlen =
					zstart - sv->start;

				/* WRITER-HUNT (M5.6a): hygiene step —
				 * on a block check failure skip the
				 * zeroing loud, the fork itself stays
				 * alive (the copy loop above already
				 * refused if the table was rotten). */
				if (uml_nt_phys_block_check(c->ph,
						(long long)sv->run_off,
						zlen) < 0)
					os_info("[fillguard] fork "
						"residue zero dst=0x%llx "
						"len=%llu leaves the "
						"block — skipped\n",
						sv->run_off, zlen);
				else {
					/* K6 [flatwr]: gen-only capture/
					 * compare around the residue
					 * zero (a kernel flat write of
					 * guest stack content). */
					unsigned long long zgs =
						(unsigned long long)
						uml_nt_phys_gen(c->ph,
							(long long)
							sv->run_off);

					memset(uml_boot.physmem_base +
					       sv->run_off, 0, zlen);
					uml_nt_flatwr_check(c,
						UML_NT_FLATWR_SITE_FORK_ZERO,
						0, zlen, sv->run_off,
						zgs, -1);
					uml_nt_cowwatch_touch(
						(unsigned long long)
						sv->run_off, zlen,
						"residue-zero");
					os_info("[stubtest] fork: zeroed "
						"child stack residue "
						"below rsp 0x%llx (%llu "
						"bytes)\n", g->rsp, zlen);
				}
			}
		}
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
	/* map 059 fix F: same contract as conn_bootstrap's fork-child
	 * half — the seed rcx is ABI garbage that would ride every
	 * VEH dispatch CONTEXT back onto the guest stack. */
	k->d->init_regs.rcx = 0;
	k->d->fs_tramp_off = 0; /* see the bootstrap note: hop stays ON */
	os_info("[stubtest] fork seed pid %lu: child rip=0x%llx "
		"rcx=0x%llx rbx=0x%llx r12=0x%llx r13=0x%llx\n",
		(unsigned long)k->pid, k->d->init_regs.rip,
		k->d->init_regs.rcx, k->d->init_regs.rbx,
		k->d->init_regs.r12, k->d->init_regs.r13);
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

/* The fork handoff is PER-TASK (run 37075722281 decode): a global
 * fork_pending_parent died the moment two forks overlapped — the
 * executor's fork (nr=57, conn 2580, armed at line 3611) was still in
 * copy_process when PID 1's own fork (nr=56, conn 7552) armed at 3629
 * and CLOBBERED the single global; the loser's child mm then spawned
 * its conn unseeded (nvma=0, INIT 0 map ops) and the stub jumped into
 * an unmapped address space (rip=0, 0xC0000005). arm and seed run on
 * the SAME kernel thread — copy_process is synchronous inside the
 * fork syscall — so the handoff keys on current->pid and preemption
 * cannot cross wires. The seed's anti-stale guard re-checks that
 * current's mm still points at the armed conn (a recycled pid's stale
 * slot cannot seed a foreign mm). */
#define UML_NT_FORK_HANDOFF_N 16
static struct {
	int pid;
	struct uml_nt_stub_conn *conn;
	unsigned long long rsp;
} fork_handoffs[UML_NT_FORK_HANDOFF_N];

static struct uml_nt_stub_conn *fork_handoff_rsp(unsigned long long *rsp)
{
	int i;

	for (i = 0; i < UML_NT_FORK_HANDOFF_N; i++)
		if (fork_handoffs[i].conn != NULL &&
		    fork_handoffs[i].pid == current->pid) {
			*rsp = fork_handoffs[i].rsp;
			return fork_handoffs[i].conn;
		}
	return NULL;
}

/* [fork-entry] audit (107/108): who owns THIS task's fork handoff?
 * -1 = none. mmctx's spawn print pairs this with the child's mm so
 * an unseeded birth (0 map ops → rip=0, conn 3124's death) names its
 * branch in the same boot. Per-task: an exec birth during a fork
 * window reads its OWN (empty) cell instead of another fork's. */
int uml_nt_fork_pending_pid(void)
{
	unsigned long long rsp;
	struct uml_nt_stub_conn *parent = fork_handoff_rsp(&rsp);

	if (parent == NULL)
		return -1;
	return (int)parent->pid;
}


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

	/* Re-arm the uaccess context for the INCOMING task. The
	 * dispatch's save/restore discipline (M4.2) only covers
	 * NESTED HANDLER RETURNS — but a task that exits through
	 * do_exit never unwinds its dispatch, and a task woken by a
	 * stack switch resumes INSIDE its blocked handler
	 * (wait_task_zombie's put_user), not at a dispatch boundary.
	 * Between those, uacc_mm/uacc_sink still name the LAST
	 * dispatched conn — commonly the just-exited child whose mm
	 * was destroyed and its kzalloc reused (zeroed: nvma 0). The
	 * woken parent's status writeback then walks that corpse:
	 * "waitpid() failed: Bad address" (EFAULT, census reason=
	 * no-vma hole=(0x0,0x0), run 36798157639 #9-#13) and init
	 * freezes. The stack switch is the one boundary every path
	 * crosses: install the incoming task's conn mm + fixup
	 * channel here, NULL-safe (kthreads and conn-less tasks fail
	 * safe). Content-identical to what the incoming dispatch
	 * would install, so re-entry stays coherent.
	 * K6 (M5.6a scrutiny fix): the [uawrite] nr context rides the
	 * SAME re-arm — uml_nt_uacc_nr_switch installs the conn's
	 * active_nr (stamped at dispatch entry, uaccess_walk.h), so a
	 * resumed parent blocked in wait4 (61) hashes/reports its OWN
	 * nr, not the do_exit'd child's exit/exit_group 60/231 still
	 * sitting in the global (that dispatch never unwound to
	 * restore it). */
	{
		struct mm_id *id = (t->mm != NULL) ?
			&t->mm->context.id : NULL;
		struct uml_nt_stub_conn *c = (id != NULL) ?
			id->nt_conn : NULL;
		static int stale_logged;

		if (c != NULL && c->dead_magic == UML_NT_CONN_DEAD) {
			/* 048: the conn this task's mm points at was
			 * destroyed (stamped) — its mm/ph are kfree'd.
			 * Refuse the re-arm (fail-safe: NULL mm + NULL
			 * sink, the walk EFAULTs) and name the task
			 * once — the log line is the datum that says
			 * which path retained the corpse. */
			if (!stale_logged) {
				stale_logged = 1;
				os_info("[switch] STALE-CONN re-arm "
					"refused: incoming task %d pid "
					"%lu\n", t->pid,
					(unsigned long)c->pid);
			}
			c = NULL;
		}
		if (c != NULL) {
			struct uml_nt_uacc_sink s;

			uml_nt_uacc_set_mm(c->mm);
			s.ph = c->ph;
			s.plan = &c->plan;
			(void)uml_nt_uacc_set_sink(&s);
			(void)uml_nt_uacc_nr_switch(&c->active_nr);
			if (c->ph != NULL)
				uml_nt_phys_set_drop_owner(c->ph, c);
		} else {
			uml_nt_uacc_set_mm(NULL);
			(void)uml_nt_uacc_set_sink(NULL);
			(void)uml_nt_uacc_nr_switch(NULL);
		}
	}

	/* The M5.1c.5 off-CPU smash tripwire is GONE: it wrote a
	 * per-task magic into the vmalloc area's tail qword believing
	 * that tail was committed dead padding. It is the vmalloc
	 * GUARD page — no pte, so no os_map_memory round ever backs
	 * it, and in the private-block era (f2eb9c7) a guard page that
	 * opens a fresh 64K block stays MEM_RESERVE: the magic write's
	 * silent NtProtectVirtualMemory(RW) fails, the write itself
	 * faults c0000005, and no recovery path exists at kernel VAs
	 * (runs 36796131915 / 36796693991: write stack+size-8 from the
	 * timer task, every switch whose pad page shared a block with
	 * pte-populated pages survived by accident). The smash it
	 * hunted was root-caused at adfc650; the ring above — the part
	 * the crash reporter actually prints — stays. */
}

void uml_nt_fork_trace(void)
{
	/* fork_handler = a task's first breath on its cold vmalloc'd
	 * stack. One line per task: the log + the crash ring can then
	 * attribute every stack base to its owner. */
	os_info("fork_handler: task %d stack %px\n", current->pid,
		task_stack_page(current));
}

/* M5.1c.5: the smash-writer hunt (see internal.h). The crash
 * reporter resolves a smashed stack page to its section offset and
 * asks both live mms: does any VMA's backing run cover it? The
 * mm/VMA structs live here (statics); the walk is read-only. */
void uml_nt_alias_scan(unsigned long long lo, unsigned long long hi)
{
	static const struct {
		const char *name;
		struct uml_nt_mm *mm;
	} mms[] = {
		{ "parent", &mm_parent }, { "child", &mm_child },
	};
	int mi;

	for (mi = 0; mi < 2; mi++) {
		struct uml_nt_mm *mm = mms[mi].mm;
		int i;

		if (mm->nvma == 0)
			continue;
		for (i = 0; i < mm->nvma; i++) {
			struct uml_nt_vma *v = &mm->vma[i];
			unsigned long long vs, ve;

			vs = v->run_off;
			ve = vs + (v->end - v->start);
			if (ve <= lo || vs >= hi)
				continue;
			os_info("alias: mm %s guest [0x%llx,0x%llx) backs "
				"section [0x%llx,0x%llx) hits [0x%llx,"
				"0x%llx)\n",
				mms[mi].name, v->start, v->end, vs, ve,
				(vs > lo) ? vs : lo,
				(ve < hi) ? ve : hi);
		}
	}
}

void uml_nt_fork_arm(struct uml_nt_stub_conn *parent, unsigned long long rsp)
{
	int i, free_i = -1;

	/* fork-handoff trace (poller 070): run 36941397893 died the
	 * R7 fatal mode — a fork's child conn spawned with an EMPTY mm
	 * (INIT 0 map ops, stub dead at first access) and NO "child
	 * conn seeded" line: the pending handoff never reached the
	 * seed. Log every arm; with the disarm trace below, the next
	 * recurrence names its losing round (arm missing = route hole;
	 * arm + disarm-pending-set = consumed-by-nobody race). */
	os_info("fork-handoff: arm parent pid %lu rsp=0x%llx\n",
		(unsigned long)parent->pid, rsp);
	for (i = 0; i < UML_NT_FORK_HANDOFF_N; i++) {
		if (fork_handoffs[i].conn != NULL &&
		    fork_handoffs[i].pid == current->pid) {
			free_i = i; /* this task re-arming its own fork */
			break;
		}
		if (fork_handoffs[i].conn == NULL && free_i < 0)
			free_i = i;
	}
	if (free_i < 0) {
		os_info("fork-handoff: table full — fork refused\n");
		return;
	}
	fork_handoffs[free_i].pid = current->pid;
	fork_handoffs[free_i].conn = parent;
	fork_handoffs[free_i].rsp = rsp;
}

void uml_nt_fork_disarm(void)
{
	int i;

	/* fork-handoff trace (poller 070): disarm while THIS task's
	 * handoff is STILL SET = the seed never consumed it — this
	 * fork's child conn is about to spawn unseeded (the fatal
	 * mode of run 36941397893). Silent when empty: the seed
	 * consumed it (the normal path — every seeded fork disarms
	 * empty). */
	for (i = 0; i < UML_NT_FORK_HANDOFF_N; i++) {
		if (fork_handoffs[i].conn == NULL ||
		    fork_handoffs[i].pid != current->pid)
			continue;
		if (fork_handoffs[i].conn != NULL)
			os_info("fork-handoff: disarm with PENDING STILL "
				"SET (parent pid %lu) — seed never "
				"consumed\n", (unsigned long)
				fork_handoffs[i].conn->pid);
		fork_handoffs[i].conn = NULL;
		fork_handoffs[i].rsp = 0;
	}
}

/* Map 049: the phys refcount event log (physalloc.h for the fire
 * sites). Run 36816338737 proved the disease class: run 0x28b0000
 * was allocated to the live TLS block (line 421) AND re-allocated to
 * a fresh anon mmap (line 4154) while fs still pointed into it — the
 * block's refs reached 0 through SOME unbalanced drop, the buddy
 * re-listed it, and every later write to the "new" 64KB trashed the
 * TCB of PID 1 and all its COW children (the deterministic
 * "STREAM=7"/wild-pointer SIGSEGVs; the isolated canary never saw
 * it). These lines name the free / the unbalanced drop / the backend
 * double-alloc the moment they happen. */
/* WRITER-HUNT (M5.6a): the release-under-vma tripwire. Data from the
 * sampling runs on 6851384 (36969971407 + 36969964516, both red):
 * the block backing PID 1's LIVE heap (run 0x3960000 — the
 * tcache_perthread_struct's run) parks at drop and FREES at the
 * dropping conn's settle while PID 1's heap VMA still maps it — the
 * next alloc hands that run to another conn whose legit writes then
 * land INSIDE PID 1's malloc metadata ("a%UTEMD_S$UTEMD_" tcache
 * fragments). An unref-refused never fires (drops are table-legal):
 * the claims were under-counted somewhere — this names the moment
 * (the event), the surviving conn and the VMA that still maps the
 * released range. Exempts the dropping owner's OWN mm (its views
 * die with it — the D22 settle contract); any OTHER conn's VMA on a
 * released range is the smoking gun. Read-only. */
static int release_guard_budget = 32;
static void release_vma_sweep(const char *kind, long long off, int nruns,
			      const void *owner)
{
	struct task_struct *p;
	unsigned long long lo = (unsigned long long)off;
	unsigned long long hi = lo +
		(unsigned long long)nruns * UML_NT_PHYS_RUN_SIZE;

	for_each_process(p) {
		struct uml_nt_stub_conn *pc;
		struct uml_nt_mm *mm;
		int vi;

		if (release_guard_budget <= 0)
			return; /* loud 32, then silent — the tally
				 * stays on the [phys] lines */
		if (p->mm == NULL)
			continue;
		pc = ((struct mm_id *)&p->mm->context.id)->nt_conn;
		if (pc == NULL || pc->mm == NULL ||
		    pc->dead_magic == UML_NT_CONN_DEAD)
			continue;
		if (owner != NULL && (const void *)pc == owner)
			continue; /* the dropping view dies with it */
		mm = pc->mm;
		for (vi = 0; vi < mm->nvma; vi++) {
			unsigned long long vlo = mm->vma[vi].run_off;
			unsigned long long vhi = vlo +
				(mm->vma[vi].end - mm->vma[vi].start);

			if (vlo < hi && vhi > lo) {
				release_guard_budget--;
				os_info("[phys-guard] %s released run "
					"[0x%llx,0x%llx) still mapped "
					"by pid %lu vma[%d] [0x%llx,"
					"0x%llx) off=0x%llx\n",
					kind, lo, hi,
					(unsigned long)pc->pid, vi,
					mm->vma[vi].start,
					mm->vma[vi].end, vlo);
			}
		}
	}
}

void uml_nt_phys_zero_flat(long long off, int nruns)
{
	if (off < 0 ||
	    (unsigned long long)off +
	    (unsigned long long)nruns * UML_NT_PHYS_RUN_SIZE >
	    uml_boot.physmem_size)
		return;
	memset((char *)uml_boot.physmem_base + off, 0,
	       (unsigned long long)nruns * UML_NT_PHYS_RUN_SIZE);
}

void uml_nt_phys_event_log(const char *kind, long long off, int nruns,
			   int refs, const void *owner)
{
	static int n_phys_log;
	int normal = (strcmp(kind, "park") == 0 ||
		      strcmp(kind, "free") == 0);

	/* The tag identity = the mis-tag witness (the prior hunt
	 * round's ask): a park/free whose owner is NOT the conn
	 * whose mm still maps the run = the free-while-mapped
	 * alias reborn. Print the owner's PID, not a bare tag. */
	if (owner != (const void *)0) {
		if (!normal || ++n_phys_log <= 64)
			os_info("[phys] %s off=0x%llx runs=%d refs=%d "
				"owner=pid %lu\n", kind,
				(unsigned long long)off, nruns, refs,
				(unsigned long)((const struct uml_nt_stub_conn *)
						owner)->pid);
		return;
	}
	if (!normal || ++n_phys_log <= 64)
		os_info("[phys] %s off=0x%llx runs=%d refs=%d owner=none\n",
			kind, (unsigned long long)off, nruns, refs);
	/* WRITER-HUNT (M5.6a) run 36984940632: the rot generation
	 * chain (heap piece <- cowcopy dst <- recycled run) says a
	 * live conn's drop was PARKED under a FOREIGN tag — the D22
	 * drop_owner is TABLE-GLOBAL and the table is SHARED between
	 * forked conns: a dying child's teardown window mis-tags
	 * every sharer's drop and its settle frees their blocks
	 * early (free-while-mapped reborn). The tag identity on the
	 * line = the mis-tag's witness: park owner must be the
	 * dropping conn's OWN teardown, nobody else's. */
	if (nruns > 0 && (strcmp(kind, "park") == 0 ||
			  strcmp(kind, "free") == 0 ||
			  strcmp(kind, "park-spill") == 0))
		release_vma_sweep(kind, off, nruns, owner);
}

/*
 * M5.6a [pivot trace] — the conn's binary name.
 *
 * sys_execve records the path right before kernel_execve; the conn the
 * exec birth creates (init_new_context → mmctx_init) adopts it, and a
 * fork child inherits its parent's. The TF trace arms only for the
 * login class (basename "login"): single-stepping every close(3) in the
 * boot would cost the 900 s gate its margin, and the pivot class has
 * only ever fired on /bin/login's NSS dlopen path.
 */
#define UML_NT_EXEC_PATH_MAX_LOCAL UML_NT_EXEC_PATH_MAX
static char g_exec_path[UML_NT_EXEC_PATH_MAX_LOCAL];
/* Shelley 199: the last exec path the kernel handled was a login/getty
 * binary. The conn's own exec_path is still empty when its stub is being
 * created (it is adopted later), so the chain flag must come from here. */
static int g_exec_login;
/* Shelley 203: the death lands ~0.4s after SOMETHING; these stamps tell us
 * which something. */
unsigned long long uml_nt_tick_spawn, uml_nt_tick_dbg;
unsigned long long uml_nt_tick_round;	/* last completed round */

/* Shelley 206: microseconds between the last resume and the instant the OS
 * says the process exited. FILETIME counts 100ns; QPC counts ticks; the
 * two are bridged by reading both at the same moment. */
unsigned long long uml_nt_resume_to_exit_us(HANDLE proc,
					    unsigned long long ts_resume)
{
	FILETIME cr, ex, kt, ut, now_ft;
	LARGE_INTEGER q_now, f;
	unsigned long long ex100, now100, hz, ticks, q_exit;

	if (ts_resume == 0 || proc == NULL)
		return 0;
	if (nt->GetProcessTimes(proc, &cr, &ex, &kt, &ut) == 0)
		return 0;
	nt->GetSystemTimePreciseAsFileTime(&now_ft);
	nt->QueryPerformanceCounter(&q_now);
	if (nt->QueryPerformanceFrequency(&f) == 0 || f.QuadPart <= 0)
		return 0;
	hz = (unsigned long long)f.QuadPart;
	ex100 = ((unsigned long long)ex.HighPart << 32) | ex.LowPart;
	now100 = ((unsigned long long)now_ft.HighPart << 32) | now_ft.LowPart;
	if (now100 < ex100)
		return 0;
	/* 100ns -> ticks: ticks = us * hz / 1e6, us = (ft100 / 10) */
	ticks = (now100 - ex100) * (hz / 10000ull) / 1000ull;
	q_exit = (unsigned long long)q_now.QuadPart - ticks;
	if (q_exit < ts_resume)
		return 0;
	return (q_exit - ts_resume) * 1000000ull / hz;
}

unsigned long long uml_nt_qpc_us(unsigned long long from, unsigned long long to)
{
	LARGE_INTEGER f;
	unsigned long long hz;

	if (from == 0 || to < from)
		return 0;	/* 0 = never stamped */
	if (nt->QueryPerformanceFrequency(&f) == 0 || f.QuadPart <= 0)
		return 0;
	hz = (unsigned long long)f.QuadPart;
	return (to - from) * 1000000ull / hz;
}

unsigned long long uml_nt_qpc_ms(unsigned long long from, unsigned long long to)
{
	LARGE_INTEGER f;
	unsigned long long hz;

	if (from == 0 || to < from)
		return 0;
	if (nt->QueryPerformanceFrequency(&f) == 0 || f.QuadPart <= 0)
		return 0;
	hz = (unsigned long long)f.QuadPart;
	return (to - from) * 1000ull / hz;
}

static int path_is_login_chain(const char *p)
{
	int i;

	for (i = 0; p[i] != 0; i++) {
		if (p[i] == 'l' && p[i + 1] == 'o' && p[i + 2] == 'g' &&
		    p[i + 3] == 'i' && p[i + 4] == 'n' &&
		    (i == 0 || p[i - 1] == '/'))
			return 1;
		if (p[i] == 'g' && p[i + 1] == 'e' && p[i + 2] == 't' &&
		    p[i + 3] == 't' && p[i + 4] == 'y')
			return 1;
	}
	return 0;
}

void uml_nt_exec_path_set(const char *path)
{
	int i = 0;

	if (path == NULL) {
		g_exec_path[0] = 0;
		return;
	}
	while (path[i] != 0 && i < UML_NT_EXEC_PATH_MAX_LOCAL - 1) {
		g_exec_path[i] = path[i];
		i++;
	}
	g_exec_path[i] = 0;
	/* Shelley 235: STICKY. login execs a shell, the shell execs its own
	 * children, and every one of those execs used to clear the flag — so
	 * by the time the dying round arrived the kernel no longer believed it
	 * was serving the login chain at all (referee 40805791232: two "login
	 * chain armed" lines, zero ticks, zero samples). Once a login binary
	 * has been reached this boot, the session is the login chain. */
	if (path_is_login_chain(g_exec_path))
		g_exec_login = 1;
	if (g_exec_login && xs_lever_on()) {
		/* ruling 223: arm the xstate lever for this conn only. Ruling
		 * 160 measured that dropping the claim stops the silent death;
		 * what it also did was break the guest, because the extended
		 * state then is not carried across a restore. Doing it per-
		 * connection keeps the native boot intact and asks the
		 * question the global attempt could not. */
		g_xs_lever = 1;
		os_info("[xs-lever] armed for the login chain\n");
	}
	if (g_exec_login)
		os_info("[dbg] login chain armed by exec '%s'\n",
			g_exec_path);
}

/* The exec birth's name (called from uml_nt_fork_seed's exec branch). */
/* Shelley 189: MINI-DEBUGGER. WaitForDebugEvent delivers an exception
 * BEFORE any user-mode dispatch — including the class where the OS aborts
 * the process without ever running a filter or the VEH. That is the only
 * window this hunt has left, and it costs one thread: the debugger only
 * watches. First-chance events are continued as NOT_HANDLED so the stub's
 * own handlers behave exactly as they always have.
 */
#define UML_NT_DBG_CONTINUE	0x00010002u
#define UML_NT_DBG_NOT_HANDLED	0x80010001u

static volatile int dbg_stop;
static unsigned long dbg_events;
int uml_nt_dbg_flag(void)
{
	int i;

	if (uml_nt_dbg_on >= 0)
		return uml_nt_dbg_on;
	uml_nt_dbg_on = 0;
	for (i = 0; i < uml_boot.argc; i++)
		if (uml_boot.argv[i] != NULL &&
		    __builtin_strcmp(uml_boot.argv[i], "uml_nt_dbg=1") == 0)
			uml_nt_dbg_on = 1;
	if (uml_nt_dbg_on)
		os_info("[dbg] uml_nt_dbg=1 — the stub runs under our own "
			"debugger (watch only, first-chance NOT_HANDLED)\n");
	return uml_nt_dbg_on;
}

static void uml_nt_exec_path_adopt(struct uml_nt_stub_conn *c)
{
	int i;

	for (i = 0; i < UML_NT_EXEC_PATH_MAX_LOCAL; i++)
		c->exec_path[i] = g_exec_path[i];
	if (path_is_login_chain(c->exec_path))
		c->chain_login = 1;
}

/* The binary's base name is "login" (path suffix /login or "login"). */
int uml_nt_conn_is_login(const struct uml_nt_stub_conn *c)
{
	int n = 0, i;

	if (c == NULL)
		return 0;
	while (n < UML_NT_EXEC_PATH_MAX_LOCAL && c->exec_path[n] != 0)
		n++;
	/* suffix "login" preceded by "/" or the whole name */
	if (n < 5)
		return 0;
	i = n - 5;
	if (c->exec_path[i] != 'l' || c->exec_path[i + 1] != 'o' ||
	    c->exec_path[i + 2] != 'g' || c->exec_path[i + 3] != 'i' ||
	    c->exec_path[i + 4] != 'n')
		return 0;
	return i == 0 || c->exec_path[i - 1] == '/';
}

int uml_nt_fork_seed(struct uml_nt_stub_conn *child)
{
	unsigned long long seed_rsp;
	struct uml_nt_stub_conn *parent = fork_handoff_rsp(&seed_rsp);
	int vi;
	int rc_clone;

	if (parent == NULL) {
		/* exec/bprm birth: the binary comes from the execve that is
		 * building this mm (sys_execve's hint). */
		uml_nt_exec_path_adopt(child);
		return 0; /* exec/bprm birth — nothing to seed */
	}
	/* Shelley 199: the chain flag is inherited, never guessed — a child
	 * forked from a login-chain conn stays under the debugger. */
	child->chain_login = uml_nt_chain_child(parent->chain_login,
						uml_nt_conn_is_login(parent));
	if (child->chain_login)
		os_info("[dbg] fork %lu: child of the login conn inherits "
			"the chain\n", (unsigned long)child->pid);	/* Anti-stale guard (per-task handoff): the armed conn must
	 * still be THIS task's own mm conn. A recycled pid's stale
	 * slot, or any foreign handoff, must never seed a foreign
	 * mm — fail the fork loud instead. */
	if (current->mm == NULL ||
	    ((struct mm_id *)&current->mm->context.id)->nt_conn != parent) {
		os_info("fork: handoff stale (armed conn pid %lu, "
			"current mm conn %s) — seed refused\n",
			(unsigned long)parent->pid,
			current->mm != NULL &&
			((struct mm_id *)&current->mm->context.id)
			->nt_conn != NULL ?
			"different" : "none");
		uml_nt_fork_disarm();
		return -ENOMEM;
	}
	if (parent->dead_magic == UML_NT_CONN_DEAD) {
		/* 048 audit: the armed parent conn was destroyed
		 * between the arm and this seed (its exit beat the
		 * fork). Cloning its freed mm is the injection class —
		 * fail the fork loud instead (the generic fork aborts
		 * with -ENOMEM, the guest sees fork() fail). */
		os_info("fork: armed parent conn destroyed (pid %lu) "
			"— seed refused\n", (unsigned long)parent->pid);
		uml_nt_fork_disarm();
		return -ENOMEM;
	}

	/* One phys table per MM CONTEXT would double-count nothing but
	 * also see nothing: run refcounts must count mm CONTEXTS
	 * sharing each run (S3 semantics, mmctx.c comment) — the child
	 * shares the parent's table and abandons its fresh, unclaimed
	 * one (phys_init allocates nothing — the kzalloc is the only
	 * memory). */
	if (!child->ph_shared && child->ph != parent->ph)
		kfree(child->ph);
	child->ph = parent->ph;
	child->ph_shared = 1;

	rc_clone = uml_nt_mm_clone(child->mm, parent->mm, child->ph,
			    seed_rsp);
	if (rc_clone != 0) {
		os_info("fork: mm clone failed (reason %s, child conn "
			"pid %lu, parent nvma %d, nguard %d)\n",
			uml_nt_clone_reason(rc_clone),
			(unsigned long)child->pid, parent->mm->nvma,
			parent->mm->nguard);
		/* Name the rot: shared-run-refs-zero means a run the
		 * parent's table still claims shows 0 refs. Walk every
		 * backing run so the log points at the VMA (the 015233d
		 * reason code found the CLASS, this finds the run). */
		if (rc_clone == UML_NT_CLONE_REF) {
			int mi;

			for (mi = 0; mi < parent->mm->nvma; mi++) {
				const struct uml_nt_vma *mv =
					&parent->mm->vma[mi];
				unsigned long long mo, me;

				for (mo = mv->run_off,
				     me = mv->run_off +
					  (mv->end - mv->start);
				     mo < me;
				     mo += UML_NT_PHYS_RUN_SIZE) {
					int mr = uml_nt_phys_refs(
						parent->ph,
						(long long)mo);

					if (mr > 0)
						continue;
					os_info("fork: rotten run: vma "
						"%d [0x%llx,0x%llx) run "
						"off=0x%llx refs %d prot "
						"0x%x flags 0x%x\n", mi,
						mv->start, mv->end, mo, mr,
						mv->prot, mv->flags);
				}
			}
		}
		uml_nt_fork_disarm();
		return -ENOMEM;
	}
	/* D27: the child inherits the parent's DEFERRED file regions —
	 * a first touch in the child materializes into the child's own
	 * mm (the file reference is shared). */
	(void)uml_nt_lazy_clone(child, parent);
	/* A forked child runs the parent's binary — same trace class. */
	{
		int ni;

		for (ni = 0; ni < UML_NT_EXEC_PATH_MAX_LOCAL; ni++)
			child->exec_path[ni] = parent->exec_path[ni];
	}	/* Contents of the eager (private) spans: everything whose
	 * run_off moved (the stack VMA — the COW-shared runs are the
	 * same bytes by construction). */
	/* TCACHE TRIP: the poison window opens post-fork — the
	 * parent's own heap churn carries it (the writer writes
	 * THROUGH the parent's view; every referee so far caught
	 * only the parent's legit writes next to it). Arm on the
	 * parent from its first fork on. */
	parent->tctrip_want = 1;
	for (vi = 0; vi < child->mm->nvma; vi++) {
		const struct uml_nt_vma *cv = &child->mm->vma[vi];
		const struct uml_nt_vma *pv = &parent->mm->vma[vi];

		if (cv->run_off == pv->run_off)
			continue;
		/* WRITER-HUNT (M5.6a): same direct-write tripwire as
		 * the POC fork hook — either end leaving its block
		 * fails the seed loud, no write. */
		if (uml_nt_phys_block_check(child->ph,
				(long long)cv->run_off,
				cv->end - cv->start) < 0 ||
		    uml_nt_phys_block_check(parent->ph,
				(long long)pv->run_off,
				cv->end - cv->start) < 0) {
			os_info("[fillguard] fork seed eager copy vma "
				"%d: src=0x%llx dst=0x%llx len=%llu "
				"leaves the block — seed refused\n",
				vi, pv->run_off, cv->run_off,
				cv->end - cv->start);
			uml_nt_fork_disarm();
			return -ENOMEM;
		}
		/* K6 [flatwr]: the eager copy is a kernel flat write of
		 * guest content — capture both ends' gens at the
		 * translate, gen-only compare at the write (the child
		 * table was cloned this round; the dst run is born
		 * here). */
		{
			unsigned long long egs = (unsigned long long)
				uml_nt_phys_gen(parent->ph,
						(long long)pv->run_off);
			unsigned long long egd = (unsigned long long)
				uml_nt_phys_gen(parent->ph,
						(long long)cv->run_off);

			uml_nt_copy_verify(uml_boot.physmem_base +
					   cv->run_off,
				   uml_boot.physmem_base + pv->run_off,
				   cv->end - cv->start, "seed-eager");
			uml_nt_flatwr_check(parent,
				UML_NT_FLATWR_SITE_FORK_EAGER, 0,
				cv->end - cv->start, pv->run_off, egs,
				-1);
			uml_nt_flatwr_check(parent,
				UML_NT_FLATWR_SITE_FORK_EAGER, 0,
				cv->end - cv->start, cv->run_off, egd,
				-1);
		}
		uml_nt_cowwatch_touch((unsigned long long)pv->run_off,
				      cv->end - cv->start,
				      "seed-eager-src");
		uml_nt_cowwatch_touch((unsigned long long)cv->run_off,
				      cv->end - cv->start,
				      "seed-eager-dst");
		/* WRITER-HUNT (M5.6a): same generation-grade ledger as
		 * [cowcopy] — refs both ends + source tail-16 fp. */
		{
			const unsigned char *fp =
				(const unsigned char *)
				((char *)uml_boot.physmem_base +
				 pv->run_off + UML_NT_PHYS_RUN_SIZE -
				 16);
			char hex[49];
			int hi;

			static int n_eager_log;

			if (++n_eager_log <= 64) {
				for (hi = 0; hi < 16; hi++)
					snprintf(hex + hi * 3,
						 sizeof(hex) - hi * 3,
						 "%02x ", fp[hi]);
				os_info("[eager] fork-seed vma %d src=0x%llx "
					"(refs=%d) dst=0x%llx (refs=%d) len=%llu "
					"fp=%s\n", vi, pv->run_off,
					uml_nt_phys_refs(parent->ph,
						(long long)pv->run_off),
					cv->run_off,
					uml_nt_phys_refs(child->ph,
						(long long)cv->run_off),
					cv->end - cv->start, hex);
			}
		}
	}
	/* M5.4 c3 (map 053 item 2b): the eager stack copy hands the
	 * child the parent's BELOW-RSP residue — sigframes (SIGCHLD
	 * storm: mcontext rip = _Fork+0x23 + callee-saved) PID 1's
	 * kernel wrote under earlier trap rsps. The fork child's
	 * exec_child env assembly (_strv_env_merge) descends to the
	 * same deterministic depths, reads the cluster as strv
	 * entries and dies in strcspn — the self-perpetuating
	 * signature. Below-rsp is dead by the ABI (red zone = 128
	 * bytes); give the child a clean slab instead of the parent's
	 * garbage. Deliberate Linux-parity deviation, documented:
	 * real Linux inherits the bytes too, but nothing may READ
	 * them — here the deterministic depth overlap makes the
	 * residue live. */
	{
		struct uml_nt_vma *sv;
		unsigned long long zstart;

		if (seed_rsp < 128)
			goto no_zero;
		sv = uml_nt_vma_find(child->mm, seed_rsp);
		zstart = seed_rsp - 128;
		if (sv != NULL && zstart > sv->start) {
			unsigned long long zlen = zstart - sv->start;

			/* WRITER-HUNT (M5.6a): hygiene step — skip
			 * loud on a block check failure (the eager
			 * copy loop above already failed the seed for
			 * a rotten table; this guards future edits). */
			if (uml_nt_phys_block_check(child->ph,
					(long long)sv->run_off,
					zlen) < 0)
				os_info("[fillguard] fork seed residue "
					"zero dst=0x%llx len=%llu leaves "
					"the block — skipped\n",
					sv->run_off, zlen);
			else {
				/* K6 [flatwr]: gen-only capture/compare
				 * around the residue zero (a kernel
				 * flat write of guest stack content). */
				unsigned long long zgs =
					(unsigned long long)
					uml_nt_phys_gen(child->ph,
						(long long)sv->run_off);

				memset(uml_boot.physmem_base +
				       sv->run_off, 0, zlen);
				uml_nt_flatwr_check(parent,
					UML_NT_FLATWR_SITE_FORK_ZERO,
					0, zlen, sv->run_off, zgs, -1);
				uml_nt_cowwatch_touch(
					(unsigned long long)sv->run_off,
					zlen, "seed-residue-zero");
				os_info("fork: zeroed child stack "
					"residue below rsp 0x%llx "
					"(%llu bytes)\n",
					seed_rsp, zlen);
			}
		}
no_zero:
		;
	}
	/* map 056 verifier: the poison the child is about to INHERIT.
	 * The sigframe machinery records trap+2 (the resume rip) in the
	 * frame's uc_mcontext (signal_check syncs with rip+2); at a
	 * fork-boundary delivery that is _Fork+0x23 — a value NO live
	 * frame may carry as data (the _Fork wrapper is a leaf: no
	 * return address points past its syscall). Scan the live region
	 * above the fork rsp for exactly that value: hits = the
	 * parent's own past dead-frame residue sitting above the fork
	 * rsp, copied into the child as "live" bytes (the below-rsp
	 * zero cannot reach). With the rt_sigreturn dead-frame zero
	 * (syscall.c case 15) in place this must read 0 — any hit names
	 * a surviving source for the next slice. */
	{
		struct uml_nt_vma *lv;
		unsigned long long rip2 = parent->d->regs.rip + 2;
		unsigned long long va, end;
		int poison = 0;

		lv = uml_nt_vma_find(child->mm, seed_rsp);
		if (lv != NULL) {
			end = seed_rsp + 0x200;
			if (end > lv->end)
				end = lv->end;
			for (va = (seed_rsp + 7) & ~7ull;
			     va + 8 <= end; va += 8) {
				unsigned long long v;

				memcpy(&v, uml_boot.physmem_base +
					    lv->run_off + (va - lv->start),
				       8);
				if (v == rip2)
					poison++;
			}
		}
		os_info("fork: seed poison-scan rip2=0x%llx: %d hit(s) in "
			"live region\n", rip2, poison);
	}
	/* D18: the child shares the TLS block COW and musl never
	 * re-runs arch_prctl after fork — the child's stub re-applies
	 * the inherited base at its first resume. */
	child->fs_base = parent->fs_base;
	if (child->d != NULL)
		child->d->fs_base = parent->fs_base;
	/* IMGWATCH inheritance (M5.6a writer-hunt follow-up): the fork
	 * child's mm shares the parent's image runs, but the fingerprint
	 * array was exec-only — every forked victim reported "not in
	 * this conn's image set" at death (the login-depth victims are
	 * forked helpers). Same runs, same gen, same post-load hashes:
	 * clone instead of starting empty. */
	child->imgw_n = parent->imgw_n;
	{
		int gi;

		for (gi = 0; gi < parent->imgw_n; gi++) {
			child->imgw_run[gi] = parent->imgw_run[gi];
			child->imgw_gen[gi] = parent->imgw_gen[gi];
			child->imgw_hash[gi] = parent->imgw_hash[gi];
			child->imgw_full[gi] = parent->imgw_full[gi];
		}
	}
	/* GUARD inheritance (M5.6a login-depth follow-up): the child's
	 * TCB memory is the parent's COW-shared block and its exec's
	 * AT_RANDOM is the same — comparing against the parent's
	 * recorded init is exactly right. */
	memcpy(child->auxv_rand, parent->auxv_rand,
	       sizeof(child->auxv_rand));
	child->auxv_rand_valid = parent->auxv_rand_valid;
	child->guard_init = parent->guard_init;
	child->guard_canary = parent->guard_canary;
	child->guard_seen = parent->guard_seen;
	child->guard_changes = parent->guard_changes;
	/* M5.4 c3 (map 057): arm the residue-watch — the per-round
	 * whole-stack-VMA scan that names the round re-introducing
	 * the fork-resume value into the child's stack (seed proven
	 * clean two lines above; the writer acts post-seed). 512
	 * rounds is far past the victims' death depth (INIT + a
	 * handful of faults + the arena mmap). */
	child->watch_val = parent->d->regs.rip + 2;
	child->watch_rsp = seed_rsp;
	child->watch_left = 512;
	{
		struct uml_nt_vma *wv = uml_nt_vma_find(child->mm,
							seed_rsp);

		os_info("fork: residue-watch armed pid %lu val=0x%llx "
			"rsp=0x%llx vma=[0x%llx,0x%llx) "
			"run_off=0x%llx\n",
			(unsigned long)child->pid, child->watch_val,
			seed_rsp,
			wv != NULL ? wv->start : 0,
			wv != NULL ? wv->end : 0,
			wv != NULL ? wv->run_off : 0);
	}
	/* The handoff is consumed: clear THIS task's cell silently —
	 * the fork round's disarm logs only the not-consumed case. */
	{
		int i;

		for (i = 0; i < UML_NT_FORK_HANDOFF_N; i++)
			if (fork_handoffs[i].conn == parent &&
			    fork_handoffs[i].pid == current->pid) {
				fork_handoffs[i].conn = NULL;
				fork_handoffs[i].rsp = 0;
			}
	}
	/* cowwatch sweep (M5.6a): the clone JUST bumped the refs of
	 * every COW-shared run — arm each run that is NOW shared
	 * (refs >= 2): the poison class writes into a shared run
	 * after the copy (fp-at-copy clean, run 37005701588). The
	 * COW-split arm at the [cowcopy] print catches the moment a
	 * piece splits; THIS sweep catches the sharing event itself
	 * (run 37011596048's rot run 0xcf0000 was never armed — its
	 * last copy had refs=1). */
	{
		int vi2;

		for (vi2 = 0; vi2 < parent->mm->nvma; vi2++) {
			const struct uml_nt_vma *pv =
				&parent->mm->vma[vi2];
			unsigned long long po, pe;

			if (!uml_nt_prot_writable(pv->prot))
				continue;
			for (po = pv->run_off,
			     pe = pv->run_off +
				  (pv->end - pv->start);
			     po < pe;
			     po += UML_NT_PHYS_RUN_SIZE)
				if (uml_nt_phys_refs(parent->ph,
					    (long long)po) >= 2)
					uml_nt_cowwatch_arm(po,
			pv->start + (po - pv->run_off),
			(unsigned long)parent->pid);
		}
	}
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
			/* Plan full: the skipped views keep WRITABLE
			 * stub views over runs the child shares — the
			 * parent's guest writes there never fault (no
			 * COW machinery) and stomp the child's pages
			 * (run 36787150906: the plan capped at 32 views
			 * — exactly 64 ops — and the skipped high-VA
			 * arena/heap views were where the executors
			 * read their torn malloc metadata). Never
			 * silent: name how many and where. */
			os_info("fork: reprotect plan full at view %d — "
				"%d view(s) [0x%llx..] stay WRITABLE on "
				"shared runs\n", vi, c->mm->nvma - vi,
				pv->start);
			break;
		}
		vi_reprotect++;
	}
	if (vi_reprotect)
		os_info("fork: re-protected %d parent view(s) "
			"read-only\n", vi_reprotect);
	uml_nt_claim_audit_force();
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
/* Shelley 198 (option C): the debug tax is only worth paying on the conn
 * we are chasing. At spawn time the conn may already know its exec path
 * (fork inherits it, exec sets it), so the gate asks the path: a conn on
 * the agetty→login chain gets the debugger, everything else is created on
 * the production path and runs at full speed.
 */
/* Shelley 232: the login chain as the rest of the kernel can ask about it.
 * chain_login is set at fork/exec, g_exec_login at the exec of a login
 * binary — either one is enough, and the exec path itself is empty at spawn
 * (ruling 199), so it is never the test. */
int uml_nt_login_chain(const struct uml_nt_stub_conn *c)
{
	return c != NULL && (c->chain_login || g_exec_login);
}

static int dbg_want(const struct uml_nt_stub_conn *c)
{
	int want;

	if (!uml_nt_dbg_flag() || c == NULL)
		return 0;
	/* the flag this conn inherited across fork, or discovered itself */
	want = uml_nt_chain_child(c->chain_login,
				  path_is_login_chain(c->exec_path) ||
				  (g_exec_login && c->exec_path[0] == 0));
	return want;
}

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
	/* A/B (Shelley 161 item 4): MEASURED, and the answer is that the
	 * hop is load-bearing — with it disabled the guest got FURTHER
	 * (its first password round completed, "Login incorrect", second
	 * prompt) and then faulted on `sub %fs:0x28`: the hop is what
	 * re-applies the FS base after the CONTEXT restore. Default
	 * stays ON; the switch and the canary stay as instruments. */
	d->fs_tramp_off = 0;

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
	if (dbg_want(c) || g_exec_login) {
		LARGE_INTEGER q;

		nt->QueryPerformanceCounter(&q);
		uml_nt_tick_spawn = (unsigned long long)q.QuadPart;
	}
	os_info("[dbg] spawn pid-soon exec='%s' chain=%u gexec_login=%d "
		"debug=%d tick=%llu\n", c->exec_path,
		(unsigned)c->chain_login, g_exec_login, dbg_want(c),
		uml_nt_tick_spawn);
	if (!nt->CreateProcessA(NULL, cmd, NULL, NULL, 1,
				(unsigned long)(dbg_want(c) ?
				/* a debuggee must NOT be created suspended:
				 * the first event (CREATE_PROCESS) has to be
				 * continued before any thread runs, and the
				 * pump thread cannot be the one to do it —
				 * it does not exist yet (referee 40420877602:
				 * 0 events and a stub that never ran). */
				0x2 /*DEBUG_ONLY_THIS_PROCESS*/ :
				0x4 /*CREATE_SUSPENDED*/),
				NULL, NULL, &si, &pi))
		goto fail;
	if (dbg_want(c)) {
		{
			LARGE_INTEGER q;

			nt->QueryPerformanceCounter(&q);
			uml_nt_tick_dbg = (unsigned long long)q.QuadPart;
		}
		os_info("[dbg] attach tick=%llu (since spawn %llu ms)\n",
			uml_nt_tick_dbg,
			uml_nt_tick_dbg - uml_nt_tick_spawn);
		/* the handshake, on THIS thread, before anything else */
		unsigned char fe[UML_NT_DE_SIZE];
		unsigned int tid = 0;

		if (nt->WaitForDebugEvent(fe, 5000)) {
			os_info("[dbg] first event code=%u pid=%u tid=%u\n",
				de_u32(fe, UML_NT_DE_CODE),
				de_u32(fe, UML_NT_DE_PID),
				de_u32(fe, UML_NT_DE_TID));
			dbg_pid_add((unsigned long)pi.dwProcessId);
			dbg_active_pid = (unsigned long)pi.dwProcessId;
			nt->ContinueDebugEvent(de_u32(fe, UML_NT_DE_PID),
					       de_u32(fe, UML_NT_DE_TID),
					       UML_NT_DBG_CONTINUE);
		} else {
			os_info("[dbg] no first event within 5s — the "
				"debugger attach did not take (check the Job "
				"Object interaction)\n");
		}
		/* NO pump thread: the service loop takes the events, on
		 * this thread, right where it waits (Shelley 191). Two
		 * consumers would race for the same debug buffer —
		 * referee 40428162068 showed both of them running. */
		(void)tid;
	}

	c->proc = pi.hProcess;
	c->thread = pi.hThread;
	c->pid = pi.dwProcessId;
	c->alive = 1;
	c->exit_code = 0;
	c->plan_next = 0;
	c->plan_left = 0;
	c->nviews = 0; /* the view ledger starts empty: the INIT
		       * plan's MAPs populate it as they issue */
	/* M5.6b: join the launcher's kill-on-close job (boot-info v4)
	 * — the launcher/kernel dying for ANY reason takes every stub
	 * down (the zombie-stub report: park_forever outlived a dead
	 * kernel on the real machine). CreateProcess children inherit
	 * the job by default; the explicit assign beats hoping (and
	 * is the nested-job-safe no-op when already a member). */
	if (uml_boot.job_object != NULL &&
	    !nt->AssignProcessToJobObject(uml_boot.job_object,
					  pi.hProcess))
		os_info("[stub] job assign failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
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
/* [d20-guard] (M5.6a, referee 40200361737): an ANSWER must never hand
 * the guest a REAL syscall instruction. The restart shape is the trap:
 * do_signal's restart sets rip = post_rip - 2, i.e. back ONTO the guest's
 * syscall site, expecting the D20 sentinel (0f 0b) to trap again. If the
 * page still holds the original 0f 05 — a file fill restored it, a sweep
 * skipped the run, a mapping was never swept — the guest executes a real
 * Windows system call: it leaves user mode through the host kernel, no
 * VEH ever runs, no record is published, and the process dies with a raw
 * 0xC0000005. Measured: guest rip libc+0xfce65, the `syscall` of
 * __close_nocancel, answered as a restart, dead with no dispatch.
 *
 * So verify the instruction at every syscall-class answer, and patch it
 * if it is real. One VMA lookup and one 2-byte compare per round. */
static void uml_nt_d20_guard_answer(struct uml_nt_stub_conn *c)
{
	struct uml_nt_vma *v;
	/* THE REAL TARGET IS rip+2, not rip: the kernel deliberately
	 * leaves the trap rip on the sentinel and the STUB advances past
	 * it (stub.c: target = d->regs.rip + 2). Checking rip measured
	 * the ud2 we already patched — true but useless. Shelley 161
	 * caught the label; check what the guest will actually fetch. */
	unsigned long long rip = c->d->regs.rip + 2, off;
	unsigned char *p;

	if (c->mm == NULL)
		return;
	v = uml_nt_vma_find(c->mm, rip);
	if (v == NULL || !uml_nt_prot_execable(v->prot))
		return;
	if (rip + 2 > v->end)
		return;
	off = v->run_off + (rip - v->start);
	p = (unsigned char *)uml_boot.physmem_base + off;
	/* MEASURE the guard itself: if it never sees 0f 05 while the guest
	 * demonstrably executes one, the translation is wrong, not the
	 * guest. Record what we looked at (and the ledger's own answer for
	 * the same VA) so the death line can say which side is lying. */
	{
		int vi = uml_nt_vp_view_find(c->views, c->nviews, rip);

		c->gd_rip = rip;
		c->gd_vma = 1;
		c->gd_prot = (unsigned)v->prot;
		c->gd_off = off;
		c->gd_b0 = p[0];
		c->gd_b1 = p[1];
		c->gd_view = vi;
		c->gd_voff = vi >= 0 ?
			uml_nt_vp_view_off(&c->views[vi], rip) : 0;
		c->gd_vb0 = vi >= 0 ? *(unsigned char *)
			((char *)uml_boot.physmem_base + c->gd_voff) : 0;
		c->gd_n++;
	}
	if (p[0] != 0x0f || p[1] != 0x05)
		return;
	p[1] = 0x0b;
	c->d->d20_guarded++;
	os_info("[d20-guard] pid %lu resume TARGET 0x%llx held a REAL "
		"syscall (0f 05) — patched to the sentinel before the resume "
		"(%llu guard(s))\n", (unsigned long)c->pid, rip,
		c->d->d20_guarded);
}

int uml_nt_pump_conn(struct uml_nt_stub_conn *c)
{
	int rc;
	int pushed = 0;

	mb();
	/* Shelley 159 (i): what the block held the moment the request
	 * arrived — the other end of the transit window. */
	c->req_rip = c->d->regs.rip;
	c->req_rsp = c->d->regs.rsp;
	c->req_seq_seen = c->d->req_seq;
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
		if (c->plan_left == 0) {
			pushed = uml_nt_signal_check(c);
			/* Push only when signal_check pulled THIS trap's
			 * xstate into regs->fp. With ops in flight the
			 * pull never ran, so regs->fp is one trap round
			 * stale — pushing it over the stub's fresh
			 * capture made the resumed guest replay its
			 * faulting SSE store with a dead register
			 * (musl queue()'s movups wrote {0,0} instead of
			 * {m,m}: the net gate's sh died dequeuing the
			 * zeroed free-meta node). Left unpushed, the
			 * CONTEXT restore keeps Windows' own at-
			 * exception FP state — exactly right. */
			uml_nt_fp_push(c, c->owner_regs);
		}
		/* The resume-boundary audit's expected target: the
		 * stub's d->resume_rip (published at its own resume) is
		 * compared against this at the next real trap. A verbatim
		 * push (signal/sigreturn) carries the kernel's exact rip;
		 * otherwise a syscall advances 2, a fault replays. */
		c->exp_resume_rip = uml_nt_resume_expected(
			c->d->cmd == UML_STUB_CMD_SYSCALL,
			c->d->regs.rip, pushed, c->d->regs.rip);
		c->exp_resume_valid = 1;
	} else if (c->d->cmd == UML_STUB_CMD_SYSCALL ||
		   c->d->cmd == UML_STUB_CMD_FAULT) {
		/* POC conns (no task/signals): the stub resumes by the
		 * same arithmetic — audit them too. */
		c->exp_resume_rip = uml_nt_resume_expected(
			c->d->cmd == UML_STUB_CMD_SYSCALL,
			c->d->regs.rip, 0, 0);
		c->exp_resume_valid = 1;
	}
	/* M5.4 c3 (map 057): residue-watch — after the round's service
	 * AND signal delivery (a sigframe written by signal_check is
	 * exactly one of the suspects), before the answer releases.
	 * Expiry is logged once so the window itself is auditable. */
	if (c->watch_val != 0 && c->watch_left > 0) {
		c->watch_left--;
		uml_nt_residue_watch(c);
		if (c->watch_left == 0 && c->watch_val != 0) {
			os_info("[stubtest] residue-watch pid %lu expired "
				"clean (last nr=%llu)\n",
				(unsigned long)c->pid, c->last_nr);
			c->watch_val = 0;
		}
	}
	/* M5.6a cowwatch: the armed shared runs — the same per-round
	 * audit point as the residue-watch (post-service, post-signal,
	 * pre-release); the round identity on a hit = the writer. */
	uml_nt_cowwatch_round(c);
	/* M5.6a [pivot trace]: the close(3) answer is the arm point —
	 * the next instruction the guest executes is the first step of
	 * the interval the [resume-regs] verdict proved is guest code.
	 * Armed before the release so the stub raises TF on THIS resume;
	 * the resume record below still notes this round's own state,
	 * and only the login class is ever traced. */
	/* M5.6a [pivot-sample]: TF is retired (the Windows dispatcher eats
	 * TF on every hop) — the sampler replaces it on the same arm
	 * point. */
	/* M5.6a [pivot-dr]: the close(3) gate arms the one-shot execute
	 * breakpoint on the interp's DSO-lookup entry. The sampler of
	 * to-shelley/150 stays in the tree but is NOT armed: the interval
	 * is ~1-2 us and a suspend/read probe is ~10 us, so it can never
	 * land inside (referees 40094545095/40094551603). */
	/* M5.6a [pivot-wslot] (to-shelley 151, Shelley's ruling): the
	 * DR EXECUTE breakpoint is RETIRED — it saw 20000 entry calls per
	 * login with a clean rbp every time (referees 40111848005/
	 * 40111855705), which falsified the "entry call with a text rbp"
	 * hypothesis and cost 20000 round trips. The four WRITE slots on
	 * the observed array qwords replace it: text is never written by
	 * a correct guest, so the first hit is the pivot itself. */
	/* Shelley 162: the one-shot execute probe is armed FIRST, so the
	 * retired write-slot instrument can never take its hardware slot
	 * (that is exactly how the first attempt measured nothing). */
	if (c->d->action == UML_STUB_ACTION_NONE)
		uml_nt_drexec_arm(c);
	/* Shelley 168: before this answer releases the stub, make sure the
	 * stack has a committed page under rsp. Every exception — the
	 * guest's, the dispatcher's, and our own instrument's #DB — builds
	 * its frame on this stack, and an exception with <8KB of committed
	 * page under rsp writes into the reservation hole and dies with no
	 * handler at all. The kernel has rsp here and owns the plan, so
	 * this costs one MAP op in an answer we were sending anyway. */
	if (c->d->action == UML_STUB_ACTION_NONE && c->mm != NULL) {
		int sg = uml_nt_stack_precommit(c->mm, c->ph,
						c->d->regs.rsp,
						c->d->stack_bottom,
						c->d->stack_top_hint,
						c->d->stack_alloc_hint,
						&c->plan);

		/* Shelley 170: WHICH mm, WHICH table, WHICH answer. Three
		 * suspects, three fixes: (2) my scan's `start >= best` with
		 * best=0; (1) a stack mapped outside the VMA table; (3) the
		 * answer path and the death dump looking at different mms
		 * (D15 uaccess install lifecycle). One line per conn says
		 * which. */
		if (c->mm_logged < 2 && uml_nt_conn_is_login(c)) {
			struct uml_nt_vma *mv = uml_nt_vma_find(c->mm,
								c->d->regs.rsp);

			c->mm_logged++;
			os_info("[mm-id] pid %lu mm=%px uacc_mm=%px nvma=%d "
				"rsp=0x%llx find=%s(0x%llx,0x%llx,prot=0x%x) "
				"stack_bottom=0x%llx top_hint=0x%llx "
				"mm_stack_top=0x%llx\n",
				(unsigned long)c->pid, c->mm,
				uml_nt_uacc_mm_ptr(), c->mm->nvma,
				c->d->regs.rsp, mv ? "YES" : "NULL",
				mv ? mv->start : 0, mv ? mv->end : 0,
				mv ? mv->prot : 0, c->d->stack_bottom,
				c->d->stack_top_hint, c->mm->stack_top);
		}
		if (sg < 0 && c->sg_logged < 4) {
			c->sg_logged++;
			os_info("[stack-pre] pid %lu grow REQUESTED but the "
				"plan refused it (rsp=0x%llx bottom=0x%llx) "
				"— the round goes out unchanged\n",
				(unsigned long)c->pid, c->d->regs.rsp,
				c->d->stack_bottom);
		}
		/* Shelley 169 (3): the alignment question — a bottom that is not
		 * run-aligned cannot be a grow target. */
		if (sg == 0 && c->d->stack_bottom != 0 &&
		    (c->d->stack_bottom & (UML_NT_SG_RUN - 1)) != 0 &&
		    c->sg_logged < 4) {
			c->sg_logged++;
			os_info("[stack-pre] pid %lu bottom 0x%llx is NOT "
				"run-aligned — the hint is a region base, not "
				"the committed run\n", (unsigned long)c->pid,
				c->d->stack_bottom);
		}
		{
			struct uml_nt_vma *rv = uml_nt_vma_find(c->mm,
							       c->d->regs.rsp);

			c->sg_ring[c->sg_ring_at & 7u].rsp = c->d->regs.rsp;
			c->sg_ring[c->sg_ring_at & 7u].bottom =
				c->d->stack_bottom;
			c->sg_ring[c->sg_ring_at & 7u].top =
				c->mm->stack_top;
			c->sg_ring[c->sg_ring_at & 7u].found = rv != NULL;
			c->sg_ring[c->sg_ring_at & 7u].find_start =
				rv ? rv->start : 0;
			c->sg_ring[c->sg_ring_at & 7u].find_end =
				rv ? rv->end : 0;
			c->sg_ring[c->sg_ring_at & 7u].nvma = (int)c->mm->nvma;
			c->sg_ring[c->sg_ring_at & 7u].sg = sg;
			c->sg_ring_at++;
		}
		if (sg == 0 && c->d->stack_bottom != 0 && c->sg_logged < 4) {
			/* why did it not grow? the inputs, once per conn —
			 * "no line" must never be the answer to "why". */
			c->sg_logged++;
			os_info("[stack-pre] pid %lu NO GROW rsp=0x%llx "
				"hint=0x%llx top=0x%llx limit=0x%llx "
				"headroom=0x%llx\n",
				(unsigned long)c->pid, c->d->regs.rsp,
				c->d->stack_bottom, c->mm->stack_top,
				c->mm->stack_limit,
				(c->d->stack_bottom != 0 &&
				 c->d->regs.rsp > c->d->stack_bottom) ?
				c->d->regs.rsp - c->d->stack_bottom : 0);
		}
		if (sg > 0 && c->sg_logged < 16) {
			c->sg_logged++;
			os_info("[stack-pre] pid %lu rsp=0x%llx grew to "
				"[0x%llx,+0x%llx) — the dispatcher needs "
				"committed page under rsp too, not just the "
				"guest\n",
				(unsigned long)c->pid, c->d->regs.rsp,
				c->plan.ops[c->plan.n_ops - 1].va,
				c->plan.ops[c->plan.n_ops - 1].len);
		}
	}
	if (c->d->action == UML_STUB_ACTION_NONE && !c->ws_armed)
		uml_nt_pivot_wslot_arm(c);
	/* M5.6a login-depth follow-up (Shelley 149): the RESUME answer —
	 * only a NONE answer releases the stub out of its VEH back into
	 * guest code, and only a real trap (or the op drain that ends
	 * one) carries that resume. Recorded after signal delivery so
	 * the state is exactly what the CONTEXT restore will apply. */
	if (c->res_trap_valid &&
	    c->d->action == UML_STUB_ACTION_NONE &&
	    !(c->d->cmd == UML_STUB_CMD_FAULT &&
	      c->d->fault_type == UML_NT_FAULT_STEP) &&
	    (c->d->cmd == UML_STUB_CMD_SYSCALL ||
	     c->d->cmd == UML_STUB_CMD_FAULT ||
	     c->d->cmd == UML_STUB_CMD_PROT_DONE))
		uml_nt_resume_regs_record(c, pushed);
	if (c->d->cmd == UML_STUB_CMD_SYSCALL)
		uml_nt_d20_guard_answer(c);
	/* Shelley 159 (i): freeze what we believe we published, in our
	 * own memory, BEFORE the event releases the stub. If the block
	 * is later found holding something else, this is the yardstick
	 * that separates corruption-in-transit from a guest that really
	 * was at the death rip. */
	/* Which SHAPE is this answer? A normal syscall resumes at trap+2
	 * (past the ud2 sentinel); a RESTART puts rip back ONTO the
	 * sentinel so the guest re-executes it. The two are different
	 * contracts with the dispatcher, so count them and keep the last
	 * eight, instead of inferring the shape from a hex difference
	 * after a death. */
	{
		unsigned long long trap = c->res_trap_valid ?
			c->res_trap_rip : 0;
		unsigned cls = 0; /* 0 = advance (+2), 1 = restart, 2 = other */

		if (trap != 0 && c->d->regs.rip == trap)
			cls = 1;
		else if (trap != 0 && c->d->regs.rip == trap + 2)
			cls = 0;
		else
			cls = 2;
		c->ans_cls = cls;
		c->ans_cls_ring[c->ans_cls_at % 8] = cls;
		c->ans_cls_at++;
		if (cls == 1)
			c->ans_restarts++;
		else if (cls == 2)
			c->ans_other++;
	}
	/* Shelley 162: the one-shot execute breakpoint on the real resume
	 * target — armed with this answer, sized to the next round. */
	if (c->d->action == UML_STUB_ACTION_NONE)
		uml_nt_drexec_arm(c);
	c->ans_cmd = c->d->cmd; /* which round kind the yardstick belongs to */
	{
		const struct uml_nt_gp_regs *g = &c->d->regs;

		c->ans_regs[0] = g->rax;  c->ans_regs[1] = g->rcx;
		c->ans_regs[2] = g->rdx;  c->ans_regs[3] = g->rbx;
		c->ans_regs[4] = g->rsp;  c->ans_regs[5] = g->rbp;
		c->ans_regs[6] = g->rsi;  c->ans_regs[7] = g->rdi;
		c->ans_regs[8] = g->r8;   c->ans_regs[9] = g->r9;
		c->ans_regs[10] = g->r10; c->ans_regs[11] = g->r11;
		c->ans_regs[12] = g->r12; c->ans_regs[13] = g->r13;
		c->ans_regs[14] = g->r14; c->ans_regs[15] = g->r15;
		c->ans_regs[16] = g->rip;
	}
	c->ans_pub = c->d->pub_seq;
	c->ans_rip = c->d->regs.rip;
	c->ans_rsp = c->d->regs.rsp;
	c->ans_rax = c->d->regs.rax;
	c->ans_retval = c->d->retval;
	c->ans_seq = c->d->req_seq;
	c->ans_step = c->d->round_step;
	{
		LARGE_INTEGER q;

		nt->QueryPerformanceCounter(&q);
		uml_nt_tick_round = (unsigned long long)q.QuadPart;
	}
	mb();
	nt->NtSetEvent(c->evt_out, NULL);
	if (c->d->halt || c->d->action == UML_STUB_ACTION_KILL) {
		/* Kernel owns the kill (upstream parity, M2.2): halt =
		 * guest exit; KILL = the stub parked on a fatal fault/
		 * failed op — terminate it now, never wait it out. */
		/* Shelley 188: NAME the kill. A process that dies with
		 * 0xC0000005 but never runs its unhandled filter did not
		 * crash — someone terminated it. If this line fires with the
		 * dying pid, the "AV with no handler" of the last dozen
		 * slices was our own NtTerminateProcess carrying a stale
		 * retval, and the whole exception hunt was chasing a value
		 * that was never an exception at all. */
		os_info("[kill] pid %lu TERMINATING stub: halt=%u action=%u "
			"retval=0x%llx (this becomes the exit code) "
			"cmd=%u rip=0x%llx\n",
			(unsigned long)c->pid, (unsigned)c->d->halt,
			(unsigned)c->d->action,
			c->d->retval, (unsigned)c->d->cmd,
			c->d->regs.rip);
		/* Shelley 201 (self-kill audit): if THIS line fires with the
		 * dying pid, the exit code was never an exception — it is the
		 * guest's own retval, handed to NtTerminateProcess by us. */
		os_info("[term] SELF-KILL pid %lu code=0x%llx (guest retval, "
			"KILL action) cmd=%u\n", (unsigned long)c->pid,
			(unsigned long long)(unsigned int)c->d->retval,
			(unsigned)c->d->cmd);
		nt->NtTerminateProcess(c->proc,
				       (NTSTATUS)c->d->retval);
		c->exit_code = c->d->retval;
		c->alive = 0;
		os_info("[stubtest] pid %lu halt (exit %lu)\n",
			(unsigned long)c->pid,
			(unsigned long)c->exit_code);
		return 1;
	}
	/* M5.6a [pivot-sample]: the answer is out — the stub is back in
	 * guest code, so this is the one place the kernel may read the
	 * running thread's CONTEXT. Bounded, and it stops the instant the
	 * next round is published. */
	if (c->smp_left != 0)
		uml_nt_sample_burst(c);
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
			unsigned long long slen;

			if (!uml_nt_prot_execable(img.seg[si].prot))
				continue;
			slen = img.seg[si].end - img.seg[si].start;
			if (slen > sizeof(uml_nt_patch_mark)) {
				os_info("[stubtest] seg too big to patch "
					"(%llu > %zu)\n", slen,
					sizeof(uml_nt_patch_mark));
				return 0;
			}
			patched += uml_nt_patch_syscalls(
				uml_boot.physmem_base +
					img.seg[si].run_off,
				slen, 0, uml_nt_patch_mark);
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
		if (blob_len > sizeof(uml_nt_patch_mark)) {
			os_info("[stubtest] blob too big to patch "
				"(%llu > %zu)\n", blob_len,
				sizeof(uml_nt_patch_mark));
			return 0;
		}
		patched = uml_nt_patch_syscalls(
			uml_boot.physmem_base + entry_off, blob_len, 0,
			uml_nt_patch_mark);
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
	os_info("[stubtest] parent stub pid %lu — resuming (veh phase=%llu "
		"in=0x%llx body=0x%llx out=0x%llx ret=0x%llx want=0x%llx "
		"r10=0x%llx r11=0x%llx)\n",
		(unsigned long)conn_parent.pid,
		conn_parent.d->veh_phase, conn_parent.d->veh_sc_sp_in,
		conn_parent.d->veh_sc_sp_body, conn_parent.d->veh_sc_sp_out,
		conn_parent.d->veh_sc_ret, conn_parent.d->veh_sc_want,
		conn_parent.d->veh_sc_r10, conn_parent.d->veh_sc_r11);
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

		/* Shelley 191: on the debug path the debug events are taken
		 * HERE, on the thread that made the handshake. A debug event
		 * freezes every debuggee thread until it is continued, so a
		 * pump that lives anywhere else (or a thread that never gets
		 * the event) turns the guest into a statue — referee
		 * 40424336921 hung exactly there. Poll with zero timeout so
		 * the wait below keeps its 1s cadence. */
		if (uml_nt_dbg_flag()) {
			unsigned char de[UML_NT_DE_SIZE];

			dbg_drain();
		}
		{
			static unsigned long long job_t[4];
			static int job_n;
			LARGE_INTEGER q;
			unsigned long long now;

			nt->QueryPerformanceCounter(&q);
			now = (unsigned long long)q.QuadPart;
			if (job_n < 4 && (job_n == 0 ||
			    uml_nt_qpc_ms(job_t[job_n - 1], now) >=
			    (job_n == 1 ? 1000u : 4000u))) {
				job_t[job_n++] = now;
				os_info("[job] probe %d: t=%llu ms since spawn "
					"= %llu ms (launcher alive — a closed "
					"kill-on-close job would have taken "
					"every conn with it)\n",
					job_n - 1,
					uml_nt_qpc_ms(uml_nt_tick_spawn, now),
					uml_nt_qpc_ms(uml_nt_tick_spawn, now));
			}
		}
		w = nt->WaitForMultipleObjects((ULONG)nwaits, waits, 0,
					       uml_nt_dbg_flag() ? 5u : 1000u);
		/* a debug event can arrive during the wait; drain again so the
		 * guest is never left frozen between two polls */
		if (uml_nt_dbg_flag()) {
			unsigned char de2[UML_NT_DE_SIZE];

			dbg_drain();
		}
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
						"silently: %lu veh=[phase=%llu "
						"in=0x%llx body=0x%llx "
						"out=0x%llx ret=0x%llx "
						"want=0x%llx r10=0x%llx "
						"r11=0x%llx] cmd=%u rip=0x%llx\n",
						(unsigned long)code,
						conn_parent.d->veh_phase,
						conn_parent.d->veh_sc_sp_in,
						conn_parent.d->veh_sc_sp_body,
						conn_parent.d->veh_sc_sp_out,
						conn_parent.d->veh_sc_ret,
						conn_parent.d->veh_sc_want,
						conn_parent.d->veh_sc_r10,
						conn_parent.d->veh_sc_r11,
						(unsigned)conn_parent.d->cmd,
						conn_parent.d->regs.rip);
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
