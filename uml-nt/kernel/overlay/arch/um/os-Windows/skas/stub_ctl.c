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
		 * before the stub maps the new one. */
		if (c->plan.copy_src_off != 0 ||
		    c->plan.copy_dst_off != 0) {
			memcpy(uml_boot.physmem_base +
				       c->plan.copy_dst_off,
			       uml_boot.physmem_base +
				       c->plan.copy_src_off,
			       UML_NT_PHYS_RUN_SIZE);
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
		memcpy(uml_boot.physmem_base + cv->run_off,
		       uml_boot.physmem_base + pv->run_off,
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

				memset(uml_boot.physmem_base +
					       sv->run_off, 0, zlen);
				os_info("[stubtest] fork: zeroed child "
					"stack residue below rsp 0x%llx "
					"(%llu bytes)\n", g->rsp, zlen);
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
	/* fork-handoff trace (poller 070): run 36941397893 died the
	 * R7 fatal mode — a fork's child conn spawned with an EMPTY mm
	 * (INIT 0 map ops, stub dead at first access) and NO "child
	 * conn seeded" line: the pending handoff never reached the
	 * seed. Log every arm; with the disarm trace below, the next
	 * recurrence names its losing round (arm missing = route hole;
	 * arm + disarm-pending-set = consumed-by-nobody race). */
	os_info("fork-handoff: arm parent pid %lu rsp=0x%llx\n",
		(unsigned long)parent->pid, rsp);
	fork_pending_parent = parent;
	fork_pending_rsp = rsp;
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
void uml_nt_phys_event_log(const char *kind, long long off, int nruns,
			   int refs)
{
	os_info("[phys] %s off=0x%llx runs=%d refs=%d\n", kind,
		(unsigned long long)off, nruns, refs);
}

void uml_nt_fork_disarm(void)
{
	/* fork-handoff trace (poller 070): disarm while the pending is
	 * STILL SET = the seed never consumed the handoff — this fork's
	 * child conn is about to spawn unseeded (the fatal mode of run
	 * 36941397893). Silent when NULL: the seed consumed it (the
	 * normal path — every seeded fork disarms empty). */
	if (fork_pending_parent != NULL)
		os_info("fork-handoff: disarm with PENDING STILL SET "
			"(parent pid %lu) — seed never consumed\n",
			(unsigned long)fork_pending_parent->pid);
	fork_pending_parent = NULL;
	fork_pending_rsp = 0;
}

int uml_nt_fork_seed(struct uml_nt_stub_conn *child)
{
	struct uml_nt_stub_conn *parent = fork_pending_parent;
	int vi;
	int rc_clone;

	if (parent == NULL)
		return 0;
	if (parent->dead_magic == UML_NT_CONN_DEAD) {
		/* 048 audit: the armed parent conn was destroyed
		 * between the arm and this seed (its exit beat the
		 * fork). Cloning its freed mm is the injection class —
		 * fail the fork loud instead (the generic fork aborts
		 * with -ENOMEM, the guest sees fork() fail). */
		os_info("fork: armed parent conn destroyed (pid %lu) "
			"— seed refused\n", (unsigned long)parent->pid);
		fork_pending_parent = NULL;
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
			    fork_pending_rsp);
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
	for (vi = 0; vi < child->mm->nvma; vi++) {
		const struct uml_nt_vma *cv = &child->mm->vma[vi];
		const struct uml_nt_vma *pv = &parent->mm->vma[vi];

		if (cv->run_off == pv->run_off)
			continue;
		memcpy(uml_boot.physmem_base + cv->run_off,
		       uml_boot.physmem_base + pv->run_off,
		       cv->end - cv->start);
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

		if (fork_pending_rsp < 128)
			goto no_zero;
		sv = uml_nt_vma_find(child->mm, fork_pending_rsp);
		zstart = fork_pending_rsp - 128;
		if (sv != NULL && zstart > sv->start) {
			unsigned long long zlen = zstart - sv->start;

			memset(uml_boot.physmem_base + sv->run_off, 0,
			       zlen);
			os_info("fork: zeroed child stack residue below "
				"rsp 0x%llx (%llu bytes)\n",
				fork_pending_rsp, zlen);
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

		lv = uml_nt_vma_find(child->mm, fork_pending_rsp);
		if (lv != NULL) {
			end = fork_pending_rsp + 0x200;
			if (end > lv->end)
				end = lv->end;
			for (va = (fork_pending_rsp + 7) & ~7ull;
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
	child->watch_rsp = fork_pending_rsp;
	child->watch_left = 512;
	{
		struct uml_nt_vma *wv = uml_nt_vma_find(child->mm,
							fork_pending_rsp);

		os_info("fork: residue-watch armed pid %lu val=0x%llx "
			"rsp=0x%llx vma=[0x%llx,0x%llx) "
			"run_off=0x%llx\n",
			(unsigned long)child->pid, child->watch_val,
			fork_pending_rsp,
			wv != NULL ? wv->start : 0,
			wv != NULL ? wv->end : 0,
			wv != NULL ? wv->run_off : 0);
	}
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
