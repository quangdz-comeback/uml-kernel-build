// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/uaccess.c — guest memory access (M3.7, D15).
 *
 * Replaces upstream arch/um/kernel/skas/uaccess.c under OS_WINDOWS
 * (kernel/skas/Makefile drops the upstream object there — patch 0014).
 * Upstream walks current->mm's page tables: on UML the guest VA space
 * IS the kernel's address space. On NT it lives in the stub process,
 * materialized as per-VMA views of the physmem section; the kernel
 * knows it as the per-conn uml_nt_mm (vma.h) — so every guest pointer
 * translates through that tree and the bytes live at physmem_base +
 * offset (the flat view).
 *
 * The served conn's mm is installed by the syscall dispatch
 * (uml_nt_syscall_handle) for exactly one handler run — the service
 * loop is single-threaded. Outside a handler uacc_mm is NULL and
 * every access faults (fail-safe, never a wild flat-view access).
 *
 * Futex atomics go through uml_nt_uacc_write_ptr (the hazard 3
 * fixup): a COW-shared uaddr gets its run made private (inline copy
 * + remap ops through the sink) before the atomic touches it — the
 * __sync ops then always run on a private page.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/futex.h>

#include <internal.h>
#include <os.h>
#include <uaccess_walk.h>

static struct uml_nt_mm *uacc_mm;

/* Returns the PREVIOUS mm: dispatches NEST on the one host thread
 * (the parent blocks inside its handler — wait4 — and the child's
 * dispatch runs on the switched stack, M4.2); the dispatch restores
 * at exit instead of clearing, or the woken parent's put_user walks
 * with mm=NULL and every writeback EFAULTs. */
struct uml_nt_mm *uml_nt_uacc_set_mm(struct uml_nt_mm *mm)
{
	struct uml_nt_mm *prev = uacc_mm;

	uacc_mm = mm;
	return prev;
}

struct uml_nt_mm *uml_nt_syscall_mm(void)
{
	return uacc_mm;
}

/* M5.4 c3 EFAULT census (043 item 2 follow-up). The one-shot trace
 * spent itself on the boot's FIRST to_user EFAULT — an early
 * fork-child site (va=0x61300c10 len=4, tasks 30/31 in runs
 * 36789783203/36791847827) — while the FATAL waitpid writeback
 * ("waitpid() failed: Bad address" → init Freezing) stayed invisible
 * ~1400 lines later. This census logs the first 16 failures, each
 * CLASSIFIED by replicating uml_nt_uacc_write_ptr's decision tree
 * READ-ONLY (no re-surgery, no retry — the dispatch state is still
 * installed on this thread): the reason names the fail mode the
 * fatal put_user hit — no-mm / no-vma (the between-VMAs hole
 * hypothesis) / vma-edge / ro-vma / cow-no-channel (the fail-safe
 * EFAULT) / cow-surgery (phys-alloc or split or plan-overflow —
 * the exhaustion hypothesis, refs + plan headroom printed). */
#define UACC_TRACE_PAGE        0x1000ull
#define UACC_TRACE_PAGE_OFF(v) ((v) & (UACC_TRACE_PAGE - 1))
#define UACC_TRACE_MAX         16

/* WRITER-HUNT (M5.6a): budget for the heap-writeback logger in
 * raw_copy_to_user — the rusage-shaped poison source hunt. */
static unsigned int uacc_heap_writes;
/* The tcache-page small-write witness (its own, tiny budget). */
static unsigned int uacc_small_writes;

/* [deadwrite] witness (M5.6a, lead 115): armed ONLY while a dying
 * task's exit/destroy path runs on this thread. The decode of both
 * referee boots puts "mmctx: destroy pid X" immediately before every
 * poison detection, and the [tctrip] negative witness proved the
 * writer is kernel-side direct phys — so the suspect set is the
 * translate-then-write primitives that run AT DESTROY: the futex
 * robust-list exit-fixup class (exit_robust_list walks a possibly
 * stale user list and cmpxchg-writes the OWNER_DIED word at chain
 * VAs — put_user-class, but riding uml_nt_uacc_write_ptr, invisible
 * to the [uawrite] funnel loggers), plus any copy_to_user/clear_user
 * the exit path issues. While armed, EVERY translate-then-write into
 * [heap_start, +0x20000) of the dying mm's heap logs with the dying
 * pid + call-site tag — one referee names the site. */
static int dw_armed;
static int dw_pid;
static const char *dw_tag;
static unsigned int dw_writes;

void uml_nt_deadwrite_arm(int pid, const char *tag)
{
	dw_armed = 1;
	dw_pid = pid;
	dw_tag = tag;
}

void uml_nt_deadwrite_disarm(void)
{
	dw_armed = 0;
	dw_pid = -1;
	dw_tag = NULL;
}

/* Shared print for both writeback witnesses: task + payload + the
 * VMA/run coordinates the walker will translate through — a
 * WRONG-run_off VMA shows up right in the line as run= pointing at
 * foreign bytes (the cow_split-base sibling class). */
static void uacc_wlog(const char *tag, unsigned int idx,
		      unsigned long long va, unsigned long n,
		      unsigned long long q0, unsigned long long q1)
{
	struct uml_nt_vma *v;
	unsigned long long page, run_start, old_run;
	int task = current ? current->pid : 0;

	page = va & ~(UACC_TRACE_PAGE - 1);
	v = uml_nt_vma_find(uacc_mm, page);
	run_start = page & ~(UML_NT_PHYS_RUN_SIZE - 1);
	old_run = v ? v->run_off + (run_start - v->start) : 0;
	os_info("%s #%u task=%d va=0x%llx len=%lu q0=0x%llx q1=0x%llx "
		"vma=[0x%llx,0x%llx) run_off=0x%llx run=0x%llx\n",
		tag, idx, task, va, n, q0, q1,
		v ? v->start : 0, v ? v->end : 0,
		v ? v->run_off : 0, old_run);
}

/* [deadwrite]: the armed-window check + print. Same VMA/run coords
 * as uacc_wlog — a stale/foreign translate shows up right in the
 * line as run= pointing at foreign bytes. */
static void dw_check(unsigned long long va, unsigned long n,
		     unsigned long long q0, unsigned long long q1)
{
	struct uml_nt_vma *v;
	unsigned long long page, run_start, old_run;

	if (!dw_armed || dw_writes >= 16)
		return;
	if (uacc_mm == NULL || uacc_mm->heap_end <= uacc_mm->heap_start)
		return;
	if (va < uacc_mm->heap_start ||
	    va + n > uacc_mm->heap_start + 0x20000)
		return;
	dw_writes++;
	page = va & ~(UACC_TRACE_PAGE - 1);
	v = uml_nt_vma_find(uacc_mm, page);
	run_start = page & ~(UML_NT_PHYS_RUN_SIZE - 1);
	old_run = v ? v->run_off + (run_start - v->start) : 0;
	os_info("[deadwrite] tag=%s dying=%d task=%d va=0x%llx len=%lu "
		"q0=0x%llx q1=0x%llx vma=[0x%llx,0x%llx) run_off=0x%llx "
		"run=0x%llx\n",
		dw_tag ? dw_tag : "?", dw_pid,
		current ? current->pid : 0, va, n, q0, q1,
		v ? v->start : 0, v ? v->end : 0,
		v ? v->run_off : 0, old_run);
}

static void uacc_trace_efault(unsigned long long va, unsigned long n)
{
	static int traced;
	struct uml_nt_mm *mm = uacc_mm;
	int task = current ? current->pid : 0;

	while (n) {
		unsigned long long chunk = UACC_TRACE_PAGE -
					   UACC_TRACE_PAGE_OFF(va);
		unsigned long long page, run_start, old_run, pe, ns;
		struct uml_nt_vma *v;
		struct uml_nt_phys *ph;
		const struct uml_nt_fault_plan *plan;
		int i;

		if (chunk > n)
			chunk = n;

		if (traced >= UACC_TRACE_MAX)
			return;
		traced++;

		if (mm == NULL) {
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=no-mm\n",
				traced, va, n, task);
			return;
		}

		page = va & ~(UACC_TRACE_PAGE - 1);
		v = uml_nt_vma_find(mm, page);
		if (v == NULL) {
			/* The between-VMAs hole: name its edges (0 =
			 * none on that side). */
			pe = 0;
			ns = 0;
			for (i = 0; i < mm->nvma; i++) {
				if (mm->vma[i].end <= page &&
				    mm->vma[i].end > pe)
					pe = mm->vma[i].end;
				if (mm->vma[i].start > page &&
				    (ns == 0 || mm->vma[i].start < ns))
					ns = mm->vma[i].start;
			}
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=no-vma "
				"hole=(0x%llx,0x%llx)\n",
				traced, va, n, task, pe, ns);
			return;
		}
		if (page < v->start || page + UACC_TRACE_PAGE > v->end) {
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=vma-edge "
				"vma=[0x%llx,0x%llx) run_off=0x%llx\n",
				traced, va, n, task, v->start, v->end,
				v->run_off);
			return;
		}
		if (!uml_nt_prot_writable(v->prot)) {
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=ro-vma "
				"vma=[0x%llx,0x%llx) prot=0x%x "
				"flags=0x%x run_off=0x%llx\n",
				traced, va, n, task, v->start, v->end,
				v->prot, v->flags, v->run_off);
			return;
		}
		if (!(v->flags & UML_NT_VMA_COW)) {
			/* Unreachable while the walker is deterministic:
			 * a writable non-COW chunk writes direct. If
			 * this fires, the walk state moved between the
			 * fail and the trace — say so honestly. */
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=direct-write "
				"vma=[0x%llx,0x%llx) run_off=0x%llx\n",
				traced, va, n, task, v->start, v->end,
				v->run_off);
			return;
		}
		if (v->run_off >= uml_nt_vma_phys_limit) {
			/* The translate refused a run_off beyond the
			 * physmem window (the 048 bound — superset of
			 * the e938b68 absolute-VA class; the window is
			 * far below the guest VA base). Print the
			 * offending VMA: the [syscall] lines around it
			 * name the creator. */
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=bad-run-off "
				"vma=[0x%llx,0x%llx) run_off=0x%llx\n",
				traced, va, n, task, v->start, v->end,
				v->run_off);
			return;
		}

		ph = uml_nt_uacc_sink_phys();
		plan = uml_nt_uacc_sink_plan();
		run_start = page & ~(UML_NT_PHYS_RUN_SIZE - 1);
		old_run = v->run_off + (run_start - v->start);
		if (ph == NULL || plan == NULL) {
			os_info("[uacc] to_user EFAULT #%d: va=0x%llx "
				"len=%lu task=%d reason=cow-no-channel "
				"ph=%d plan=%d run=0x%llx\n",
				traced, va, n, task, ph != NULL,
				plan != NULL, old_run);
			return;
		}
		os_info("[uacc] to_user EFAULT #%d: va=0x%llx len=%lu "
			"task=%d reason=cow-surgery refs=%d plan=%d/%d "
			"run=0x%llx\n",
			traced, va, n, task,
			uml_nt_phys_refs(ph, (long long)old_run),
			plan->n_ops, UML_NT_FAULT_MAX_OPS, old_run);
		return;
	}

	/* The walk failed but every chunk classifies clean — the walk
	 * state moved between fail and trace (or len was 0). One line,
	 * still bounded by the census above. */
	if (traced < UACC_TRACE_MAX) {
		traced++;
		os_info("[uacc] to_user EFAULT #%d: va=0x%llx len=%lu "
			"task=%d reason=unclassified\n",
			traced, va, n, task);
	}
}

unsigned long raw_copy_from_user(void *to, const void __user *from,
				 unsigned long n)
{
	if (uml_nt_uacc_walk(uacc_mm, uml_boot.physmem_base,
			     (unsigned long long)(unsigned long)from, n,
			     to, UML_NT_UACC_FROM_GUEST) < 0) {
		/* Same census as the write side: the READ path hit the
		 * bad-VMA class first (run 36803515813's kernel fault
		 * came out of a copy FROM a translated-garbage flat
		 * pointer) — the read side needs its failures named
		 * just as much. */
		uacc_trace_efault((unsigned long long)(uintptr_t)from, n);
		return n;
	}
	return 0;
}

unsigned long raw_copy_to_user(void __user *to, const void *from,
			       unsigned long n)
{
	/* [deadwrite]: armed = a destroy/exit path owns this thread —
	 * any writeback into the victim heap window names its site
	 * (the robust-list exit-fixup hypothesis, lead 115). Runs
	 * before the ordinary witnesses so a dying task's writeback
	 * can never be eaten by their budgets/dedup. */
	if (dw_armed) {
		unsigned long long va =
			(unsigned long long)(unsigned long)to;
		unsigned long long q0 = 0, q1 = 0;

		if (n >= 8)
			q0 = *(const unsigned long long *)from;
		else if (n >= 4)
			q0 = *(const unsigned int *)from;
		else if (n >= 1)
			q0 = *(const unsigned char *)from;
		if (n >= 16)
			q1 = ((const unsigned long long *)from)[1];
		dw_check(va, n, q0, q1);
	}

	/* WRITER-HUNT (M5.6a, referee 37082741453 decode): the first
	 * logger died of starvation — all 24 slots burned by line
	 * ~700/23306 on LEGIT bulk reads (config text into low-heap
	 * buffers), blind long before the poison. The decode also
	 * moved the crime: the rusage-shaped blob in the top chunk is
	 * chain-coherent WILDERNESS residue (a freed buffer's bytes —
	 * benign), while the abort's cause is the 16-byte ASCII blob
	 * INSIDE the tcache struct (entries[1..2] = near-"SYSTEMD_"
	 * text; malloc never hands out heap_start+0x98, so no conn
	 * may target it). v2: (a) bulk budget 24 -> 256 + exact
	 * quadruple dedup (re-reads die; value-changing writebacks
	 * survive); (b) NEW small-write witness: put_user-class
	 * (n < 24) writebacks into the TCACHE PAGE
	 * [heap_start, +0x1000) — the kernel never legitimately
	 * writes there, any hit convicts; (c) both lines add task +
	 * the VMA/run coordinates via uacc_wlog. */
	if (uacc_mm != NULL && uacc_mm->heap_end > uacc_mm->heap_start) {
		unsigned long long va =
			(unsigned long long)(unsigned long)to;
		const unsigned long long *q =
			(const unsigned long long *)from;
		unsigned long long q0, q1;
		int bulk = n >= 24;
		int small = !bulk && n >= 4 &&
			    va >= uacc_mm->heap_start &&
			    va + n <= uacc_mm->heap_start + 0x1000;

		if (!((bulk && va >= uacc_mm->heap_start &&
		       va + n <= uacc_mm->heap_end) || small))
			goto walk;
		if (n >= 8)
			q0 = q[0];
		else if (n >= 4)
			q0 = *(const unsigned int *)from;
		else
			q0 = *(const unsigned char *)from;
		q1 = (n >= 16) ? q[1] : 0;
		{
			static unsigned long long d_va, d_len, d_q0, d_q1;
			static int d_valid;

			if (d_valid && d_va == va && d_len == n &&
			    d_q0 == q0 && d_q1 == q1)
				goto walk;
			d_valid = 1;
			d_va = va;
			d_len = n;
			d_q0 = q0;
			d_q1 = q1;
		}
		if (bulk) {
			if (++uacc_heap_writes <= 256)
				uacc_wlog("[uawrite]", uacc_heap_writes,
					  va, n, q0, q1);
		} else {
			if (++uacc_small_writes <= 16)
				uacc_wlog("[uawrite-s]", uacc_small_writes,
					  va, n, q0, q1);
		}
	}
walk:
	if (uml_nt_uacc_walk(uacc_mm, uml_boot.physmem_base,
			     (unsigned long long)(unsigned long)to, n,
			     (char *)from, UML_NT_UACC_TO_GUEST) < 0) {
		uacc_trace_efault((unsigned long long)(uintptr_t)to, n);
		return n;
	}
	return 0;
}

long strncpy_from_user(char *dst, const char __user *src, long count)
{
	if (count <= 0)
		return -EFAULT;
	return uml_nt_uacc_strncpy(dst, uacc_mm, uml_boot.physmem_base,
				   (unsigned long long)(unsigned long)src,
				   (unsigned long long)count);
}

long strnlen_user(const char __user *str, long len)
{
	if (len <= 0)
		return 0;
	return uml_nt_uacc_strnlen(uacc_mm, uml_boot.physmem_base,
				   (unsigned long long)(unsigned long)str,
				   (unsigned long long)len);
}

unsigned long __clear_user(void __user *mem, unsigned long len)
{
	/* [deadwrite]: the zero path is a writer too — the exit path
	 * may memclear user buffers while armed. */
	if (dw_armed)
		dw_check((unsigned long long)(unsigned long)mem, len, 0, 0);
	if (uml_nt_uacc_walk(uacc_mm, uml_boot.physmem_base,
			     (unsigned long long)(unsigned long)mem, len,
			     NULL, UML_NT_UACC_ZERO_GUEST) < 0)
		return len;
	return 0;
}

int arch_futex_atomic_op_inuser(int op, u32 oparg, int *oval,
				u32 __user *uaddr)
{
	char *w;
	volatile u32 *p;
	u32 oldval;

	/* write_ptr = hazard 3 fix: a COW-shared uaddr gets its run
	 * made private (inline copy + remap ops through the sink)
	 * before the atomic touches it — a direct translate+write
	 * would land on the page the sharing process still reads. */
	w = uml_nt_uacc_write_ptr(uacc_mm, uml_boot.physmem_base,
				  (unsigned long long)(unsigned long)uaddr);
	if (w == NULL)
		return -EFAULT;
	p = (volatile u32 *)w;
	oldval = *p;
	switch (op) {
	case FUTEX_OP_SET:
		*p = oparg;
		break;
	case FUTEX_OP_ADD:
		__sync_add_and_fetch(p, oparg);
		break;
	case FUTEX_OP_OR:
		__sync_or_and_fetch(p, oparg);
		break;
	case FUTEX_OP_ANDN:
		__sync_and_and_fetch(p, ~oparg);
		break;
	case FUTEX_OP_XOR:
		__sync_xor_and_fetch(p, oparg);
		break;
	default:
		return -ENOSYS;
	}
	/* [deadwrite]: the futex atomics are the ONE translate-then-
	 * write family that bypasses raw_copy_to_user (write_ptr
	 * direct) — the robust-list exit-fixup writes live exactly
	 * here, so the armed witness must see them. */
	dw_check((unsigned long long)(unsigned long)uaddr, 4, *p, oldval);
	*oval = oldval;
	return 0;
}

int futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
				  u32 oldval, u32 newval)
{
	char *w;
	volatile u32 *p;
	u32 v;

	w = uml_nt_uacc_write_ptr(uacc_mm, uml_boot.physmem_base,
				  (unsigned long long)(unsigned long)uaddr);
	if (w == NULL)
		return -EFAULT;
	p = (volatile u32 *)w;
	v = __sync_val_compare_and_swap(p, oldval, newval);
	/* [deadwrite]: log only a COMMITTED exchange (v == oldval) —
	 * a lost race wrote nothing. handle_futex_death's OWNER_DIED
	 * cmpxchg rides this path at destroy. */
	if (v == oldval)
		dw_check((unsigned long long)(unsigned long)uaddr, 4,
			 newval, oldval);
	*uval = v;
	return 0;
}
