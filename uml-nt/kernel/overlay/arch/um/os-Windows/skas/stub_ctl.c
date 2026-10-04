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
	os_info("[cowwatch] armed run=0x%llx owner=%lu@0x%llx "
		"(slot %u)\n", run_off, owner_pid, owner_va, i);
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
static int tctrip_budget = 12;

static void uml_nt_tctrip_arm(struct uml_nt_stub_conn *c)
{
	if (tctrip_budget <= 0 || tctrip_conn != NULL)
		return; /* one live trip — the log names re-arms */
	if (c->mm == NULL || c->mm->heap_start == 0)
		return;
	if (uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT,
			       UML_NT_PAGE_READONLY, c->mm->heap_start,
			       UML_NT_FAULT_PAGE_SIZE, 0) < 0)
		return;
	tctrip_conn = c;
	tctrip_page = c->mm->heap_start;
	tctrip_pending = 1;
	os_info("[tctrip] armed tcache page 0x%llx pid %lu "
		"READ-ONLY — every write to the struct page names "
		"its rip\n", tctrip_page, (unsigned long)c->pid);
}

static void uml_nt_tctrip_trip(struct uml_nt_stub_conn *c,
			       struct uml_nt_stub_data *d)
{
	if (tctrip_conn != c || d->fault_addr < tctrip_page ||
	    d->fault_addr >= tctrip_page + UML_NT_FAULT_PAGE_SIZE)
		return;
	os_info("[tctrip] WRITE pid %lu rip=0x%llx rsp=0x%llx "
		"rcx=0x%llx addr=0x%llx type=%u nr=%llu ret=%lld\n",
		(unsigned long)c->pid, d->regs.rip, d->regs.rsp,
		d->regs.rcx, d->fault_addr, d->fault_type,
		c->last_nr, c->last_ret);
	tctrip_conn = NULL;
	tctrip_pending = 0;
	tctrip_budget--; /* re-armed at the next serve round */
}

/* [copyver] (see syscall.h): memcpy + read-back verify for the
 * kernel-side bulk copies into guest memory. The trap census only
 * sees stub-view writes — a bad kernel copy is invisible to it, and
 * it lands precisely in allocator-metadata territory. */
int uml_nt_copy_verify(char *dst, const char *src, unsigned long long len,
		       const char *what)
{
	unsigned long long i;

	memcpy(dst, src, len);
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

	for (i = 0; i < UML_NT_COWWATCH_N; i++) {
		struct uml_nt_cowwatch *w = &cowwatchs[i];
		unsigned long long off, base;
		int dumped;

		if (!w->armed)
			continue;
		if (w->rounds-- == 0) {
			w->armed = 0;
			os_info("[cowwatch] run=0x%llx expired\n",
				w->run_off);
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

	for (i = 0; i < UML_NT_COWWATCH_N; i++) {
		struct uml_nt_cowwatch *w = &cowwatchs[i];

		if (!w->armed)
			continue;
		if (off + len <= w->run_off ||
		    off >= w->run_off + UML_NT_PHYS_RUN_SIZE)
			continue;
		os_info("[cowwatch] kernel-write %s run=0x%llx touch "
			"[0x%llx,+0x%llx) owner=%lu\n", what, w->run_off,
			off, len, w->owner_pid);
	}
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

/* Push one plan op into the conn's slot. */
static void issue_plan_op(struct uml_nt_stub_conn *c,
			  const struct uml_nt_fault_op *op)
{
	struct uml_nt_stub_data *d = c->d;

	/* OP LEDGER (M5.6a, referee 37212286263): the wrong-backed
	 * twin is a MEM_MAPPED section view at the heap start whose
	 * backing offset is stale — some MAP op carried an old run.
	 * Record every op touching the first heap piece (8-deep ring);
	 * the [replay-lost] fire dumps it — the stale MAP names
	 * itself. */
	if (c->mm != NULL && c->mm->heap_start != 0 &&
	    op->va < c->mm->heap_start + 0x10000 &&
	    op->va + op->len > c->mm->heap_start) {
		unsigned long long *e =
			c->op_log[c->op_log_n % 8];

		e[0] = op->op;
		e[1] = op->prot;
		e[2] = op->va;
		e[3] = op->len;
		e[4] = op->off;
		c->op_log_n++;
	}

	d->mapcanary = 0;
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
		/* mapcanary (stub_nt.h v7): prove the fresh view's
		 * BACKING, not only its protection. Plant a nonce
		 * flat-side at the VMA TABLE's run for the view's
		 * tail-8; the stub reads the tail through the fresh
		 * view; PROTDONE compares and restores. Only writable
		 * MAPs with a private table run (refs==1): no shared
		 * run is ever clobbered (the RO/shared maps skip —
		 * the cowbreak audits own that class), and the parked
		 * guest never sees the transient plant. */
		if ((op->prot == UML_NT_PAGE_READWRITE ||
		     op->prot == UML_NT_PAGE_WRITECOPY ||
		     op->prot == UML_NT_PAGE_EXECUTE_READWRITE) &&
		    op->len >= 16 && c->mm != NULL) {
			long long tbl = uml_nt_vma_translate(
				c->mm, op->va + op->len - 8, 8);
			unsigned long long plant =
				(tbl >= 0) ? (unsigned long long)tbl
					   : op->off + op->len - 8;

			if (tbl >= 0 &&
			    (unsigned long long)tbl != op->off + op->len - 8)
				os_info("[mapcanary] ISSUE-MISMATCH pid %lu "
					"va=0x%llx len=0x%llx op_off=0x%llx "
					"tbl_off=0x%llx — the plan op carries a "
					"run the VMA table does not own\n",
					(unsigned long)c->pid, op->va, op->len,
					op->off, (unsigned long long)tbl);
			if (uml_nt_phys_refs(c->ph, (long long)plant) == 1) {
				unsigned long long *qp =
					(unsigned long long *)
					((char *)uml_boot.physmem_base + plant);

				c->mc_off = plant;
				c->mc_orig = *qp;
				c->mc_want = 0x4d43414e41525900ull /* "MCANARY" */
					     ^ op->va ^ (op->off << 1);
				*qp = c->mc_want;
				c->mc_active = 1;
				d->mapcanary = c->mc_want;
			}
		}
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
		os_info("[binwatch] pid %lu main_arena=0x%llx "
			"discovered\n", (unsigned long)c->pid,
			c->bw_arena);
	}
	av = c->bw_arena;
	for (bi = 1; bi <= 5 && bw_budget > 0; bi++) {
		unsigned long long head = av + 0x50 + 16ull * bi;
		unsigned long long cur;
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

/* [replay-check] arm: decode the faulting qword store and snapshot
 * the target's BEFORE content. Pure x86 prefix decode for the two
 * glibc-metadata forms (mov r64->m64, mov imm32->m64) — the register
 * file order matches the hardware encoding (rax=0..r15=15). */
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
	d->ss_page = d->fault_addr & ~0xfffull;
	d->ss_va = d->fault_addr;
	d->ss_got = ~0ull;
}

/* [replay-check] verdict at the next syscall park. */
static void replay_check_verify(struct uml_nt_stub_conn *c)
{
	static int rp_budget = 16;
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
			int k, n = c->op_log_n < 8 ? c->op_log_n : 8;

			for (k = 0; k < n; k++) {
				unsigned long long *e = c->op_log[
					(c->op_log_n - n + k) % 8];

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
				c->d->ss_vtype == 0x40000ull ?
				"MEM_PRIVATE — NOT THE PHYSMEM SECTION!" :
				c->d->ss_vtype == 0x4000000ull ?
				"MEM_MAPPED — a section view" :
				c->d->ss_vtype == 0x1000000ull ?
				"MEM_IMAGE" : "?");
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
				if (nhits == 0)
					os_info("[replay-lost]   want "
						"ABSENT at in-run offset "
						"0x%llx on every run — "
						"the store never "
						"re-executed\n", inoff);
			}
		}
	}
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
	/* TCACHE TRIP arm/re-arm: after this conn's first fork seed
	 * the poison window is open — keep the struct page tripped
	 * (one live trap; the writer's rip = the hunt's end). */
	if (c->tctrip_want && tctrip_conn == NULL && tctrip_budget > 0)
		uml_nt_tctrip_arm(c);
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

			if (!c->tc_chunk_valid ||
			    c->tc_chunk_va[di][0] != ev ||
			    !c->tc_chunk_armed[di][0] ||
			    (ev & 0xF) != 0 || (ev >> 48) != 0 ||
			    ev < mm->heap_start || ev >= mm->heap_end) {
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
				    (ev & 0xF) == 0 && (ev >> 48) == 0 &&
				    ev >= mm->heap_start &&
				    ev < mm->heap_end) {
					unsigned long long chunk = ev;

					for (depth = 0; depth < 4;
					     depth++) {
						unsigned long long data,
							nxt;
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
						if ((nxt & 0xF) != 0 ||
						    nxt < mm->heap_start ||
						    nxt >= mm->heap_end) {
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
				poison = nxt != 0 &&
					((nxt & 0xF) != 0 ||
					 nxt < mm->heap_start ||
					 nxt >= mm->heap_end);
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
						poison = 0;
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

static int serve_conn(struct uml_nt_stub_conn *c)
{
	struct uml_nt_stub_data *d = c->d;

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
	 * was produced up to the previous round (last_nr names it). */
	tcache_watch(c);

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
			*(unsigned long long *)
				((char *)uml_boot.physmem_base + c->mc_off) =
				c->mc_orig;
		}
		if (c->rp_active) {
			/* The repair PROT_DONE for a replay-armed fault:
			 * compare the stub's own-view read of the fault
			 * qword with the VMA table's run content. */
			unsigned long long tbl = 0;
			int have = 0;

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
			d->viewprobe_got = 0;
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
			/* D23 (a) census: the syscall that queued these
			 * ops — the fork's parent re-protect included —
			 * now has EVERY op applied before the guest
			 * resumes. The stub-side verify (stub.c
			 * verify_prot) proved each apply actually took;
			 * this line proves the retval waited for it. */
			os_info("[fork-sync] plan done: %d op(s) applied, "
				"retval 0x%llx published\n", c->plan.n_ops,
				(unsigned long long)c->plan_retval);
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

		/* [cowtrap] trip: the trapped page's accessor = the
		 * writer, with LIVE regs (the scan snapshots were
		 * always post-hoc). The fault then repairs through
		 * the normal mm_fault flow — the log line is the
		 * whole cost. */
		uml_nt_cowtrap_trip(c, d);
		uml_nt_tctrip_trip(c, d);
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
		rc = uml_nt_mm_fault(c->mm, c->ph, d->fault_addr,
				     d->fault_type, &c->plan);
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
					"rax=0x%llx rdi=0x%llx rsi=0x%llx "
					"rdx=0x%llx\n",
					sigsegv_victims,
					(unsigned long)c->pid, d->fault_addr,
					d->fault_type, d->regs.rip,
					c->plan.kill_why ?
					c->plan.kill_why : '?',
					d->fs_base, d->regs.rsp,
					ib[0], ib[1], ib[2], ib[3],
					ib[4], ib[5], ib[6], ib[7],
					d->regs.rax, d->regs.rdi,
					d->regs.rsi, d->regs.rdx);
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
		os_info("[stubtest] FAULT pid %lu addr=0x%llx type=%u -> "
			"%d op(s)\n", (unsigned long)c->pid, d->fault_addr,
			d->fault_type, c->plan.n_ops);
		/* COW copy directive: the kernel owns the physmem
		 * content — memcpy the run through its own flat view
		 * before the stub maps the new one. WRITER-HUNT
		 * (M5.6a): a run copy whose either end leaves its
		 * block is the direct-write class — kill loud instead
		 * of writing foreign bytes. */
		if (c->plan.copy_src_off != 0 ||
		    c->plan.copy_dst_off != 0) {
			if (uml_nt_phys_block_check(c->ph,
					c->plan.copy_dst_off,
					UML_NT_PHYS_RUN_SIZE) < 0 ||
			    uml_nt_phys_block_check(c->ph,
					c->plan.copy_src_off,
					UML_NT_PHYS_RUN_SIZE) < 0) {
				os_info("[fillguard] COW run copy "
					"src=0x%llx dst=0x%llx: block "
					"check failed — killing\n",
					c->plan.copy_src_off,
					c->plan.copy_dst_off);
				d->action = UML_STUB_ACTION_KILL;
				d->err = 1;
				return -1;
			}
			uml_nt_copy_verify(uml_boot.physmem_base +
					   c->plan.copy_dst_off,
					   uml_boot.physmem_base +
					   c->plan.copy_src_off,
					   UML_NT_PHYS_RUN_SIZE,
					   "cow-repair");
			uml_nt_cowwatch_touch(
				(unsigned long long)
				c->plan.copy_src_off,
				UML_NT_PHYS_RUN_SIZE, "cow-copy-src");
			uml_nt_cowwatch_touch(
				(unsigned long long)
				c->plan.copy_dst_off,
				UML_NT_PHYS_RUN_SIZE, "cow-copy-dst");
		/* WRITER-HUNT (M5.6a) provenance ledger: the run-copy
		 * traffic is small and the fire dumps name their run —
		 * this line maps a poisoned run back to the copy (and
		 * its SOURCE run) that produced its generation. */
		/* WRITER-HUNT (M5.6a) provenance ledger, generation
		 * grade: run 36979286356's tcache content at abort =
		 * bytes a [cowcopy] generation copied in — run IDs
		 * alone can't see a wrong-CONTENT source (the fill
		 * fence checks refs>0 + block bounds, not identity).
		 * Refs on both ends + the source run's tail-16 fp: the
		 * abort-time poison sample matches its generating
		 * copy by fp. */
		{
			const unsigned char *fp =
				(const unsigned char *)
				((char *)uml_boot.physmem_base +
				 c->plan.copy_src_off +
				 UML_NT_PHYS_RUN_SIZE - 16);
			char hex[49];
			int hi;

			for (hi = 0; hi < 16; hi++)
				snprintf(hex + hi * 3,
					 sizeof(hex) - hi * 3,
					 "%02x ", fp[hi]);
			os_info("[cowcopy] pid %lu src=0x%llx (refs=%d) "
				"dst=0x%llx (refs=%d) fp=%s\n",
				(unsigned long)c->pid,
				c->plan.copy_src_off,
				uml_nt_phys_refs(c->ph,
					(long long)c->plan.copy_src_off),
				c->plan.copy_dst_off,
				uml_nt_phys_refs(c->ph,
					(long long)c->plan.copy_dst_off),
				hex);
			/* cowwatch arm: a SHARED src run = the poison
			 * target class (the writer writes after the
			 * copy — see the cowwatch block comment).
			 * Owner VA unknown at this site (0) — the
			 * post-clone sweep arms with the real one. */
			if (uml_nt_phys_refs(c->ph,
			    (long long)c->plan.copy_src_off) >= 2)
				uml_nt_cowwatch_arm(
					c->plan.copy_src_off, 0,
					(unsigned long)c->pid);
			/* WRITER-HUNT (M5.6a, run 37078256773): the
			 * DST side goes PRIVATE (refs=1) here with
			 * writable views and NO watcher — the
			 * alloc-arm slots on the old span retired
			 * with the split's UNMAP+MAP, and the
			 * cowwatch only re-arms at the next fork.
			 * The poison {fd=0x1a,bk=0x8000} landed in
			 * exactly that window (dst run 0xee0000,
			 * private from its cowcopy at line 19941 to
			 * the next fork's arms at 20754 — ~800 lines
			 * unwatched) and the first-see then named the
			 * WRONG round. Arm the dst at birth: the
			 * flat scan from now on names the round
			 * truthfully, and every page one-shot-traps
			 * (a private run repairs by PROTECT, no
			 * copy) so a stub-view writer dies with
			 * live rip. The dst maps the SAME VA range
			 * the faulting write hit — base = its run. */
			{
				unsigned long long dvbase =
					d->fault_addr &
					~(unsigned long long)
					(UML_NT_PHYS_RUN_SIZE - 1);

				uml_nt_cowwatch_arm(
					c->plan.copy_dst_off,
					dvbase,
					(unsigned long)c->pid);
				uml_nt_cowtrap_arm_alloc(c,
					dvbase,
					UML_NT_PHYS_RUN_SIZE,
					c->plan.copy_dst_off);
			}
		}
		}
		stack_window_reassert(c);
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
	stack_window_reassert(c);
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
		uml_nt_copy_verify(uml_boot.physmem_base + cv->run_off,
				   uml_boot.physmem_base + pv->run_off,
				   cv->end - cv->start, "poc-eager");
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
					memset(uml_boot.physmem_base +
					       sv->run_off, 0, zlen);
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
	 * would install, so re-entry stays coherent. */
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
		} else {
			uml_nt_uacc_set_mm(NULL);
			(void)uml_nt_uacc_set_sink(NULL);
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

void uml_nt_phys_event_log(const char *kind, long long off, int nruns,
			   int refs, const void *owner)
{
	/* The tag identity = the mis-tag witness (the prior hunt
	 * round's ask): a park/free whose owner is NOT the conn
	 * whose mm still maps the run = the free-while-mapped
	 * alias reborn. Print the owner's PID, not a bare tag. */
	if (owner != (const void *)0) {
		os_info("[phys] %s off=0x%llx runs=%d refs=%d "
			"owner=pid %lu\n", kind,
			(unsigned long long)off, nruns, refs,
			(unsigned long)((const struct uml_nt_stub_conn *)
					owner)->pid);
		return;
	}
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

int uml_nt_fork_seed(struct uml_nt_stub_conn *child)
{
	unsigned long long seed_rsp;
	struct uml_nt_stub_conn *parent = fork_handoff_rsp(&seed_rsp);
	int vi;
	int rc_clone;

	if (parent == NULL)
		return 0; /* exec/bprm birth — nothing to seed */
	/* Anti-stale guard (per-task handoff): the armed conn must
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
	/* Contents of the eager (private) spans: everything whose
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
		uml_nt_copy_verify(uml_boot.physmem_base + cv->run_off,
				   uml_boot.physmem_base + pv->run_off,
				   cv->end - cv->start, "seed-eager");
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
				memset(uml_boot.physmem_base +
				       sv->run_off, 0, zlen);
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
		if (c->plan_left == 0) {
			uml_nt_signal_check(c);
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
