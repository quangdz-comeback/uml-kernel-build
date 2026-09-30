// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/syscall.c — guest syscall surface (M3.7, D16).
 *
 * Upstream analogue: arch/um/kernel/skas/syscall.c handle_syscall()
 * (call sys_call_table[nr](args...), return value into the trap
 * regs). The NT dispatch serves the same ABI from the D10 slot:
 * d->regs.rax = nr, d->args[6] = the guest ABI registers, d->retval
 * back; ops (mmap/munmap/mprotect) stream through the conn's plan —
 * the stub executes them in its own address space exactly like a
 * fault repair, and the syscall return value is parked in
 * c->plan_retval across those rounds (the stub's op results travel
 * through d->retval).
 *
 * Handlers that only bookkeep (identity, brk, sigprocmask...) run
 * from any kernel context; buffer-touching paths go through the D15
 * uaccess (the conn's mm installed for exactly this handler run).
 * The guest VFS syscalls (openat family, fstat, getdents64, execve,
 * blocking waits) are NOT here on purpose: their bytes live inside
 * ext4 on ubda and only the guest kernel's own VFS can read them —
 * they need real kernel tasks (M3.8). The loud ENOSYS default is the
 * M3.8 boot-failure pointer ("cứ thêm + unit test").
 */
#include <linux/kernel.h>
#include <linux/binfmts.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/string.h>

#include <asm/syscall.h>
#include <os.h>
#include <internal.h>
#include <stub-panic.h>
#include <stub_nt.h>
#include <syscall.h>
#include <bench.h>
#include <uaccess_walk.h>

#define UML_NT_SYSCALLS_BASE UML_STUB_RAM_BASE

/* The real x86-64 UML table (arch/x86/um/sys_call_table_64.c). */
extern int syscall_table_size;

/* errno — x86_64 generic (asm-generic/errno.h values, UML included). */
#define SC_ENOSYS  38
#define SC_EFAULT  14
#define SC_EBADF   9
#define SC_ENOMEM  12
#define SC_EINVAL  22
#define SC_EAGAIN  11
#define SC_ECHILD  10
#define SC_ENOTTY  25

#define SC_RET(e) ((unsigned long long)-(long long)(e))

/* mmap(2) flags/values (asm-generic/mman.h). */
#define SC_PROT_READ  0x1u
#define SC_PROT_WRITE 0x2u
#define SC_PROT_EXEC  0x4u
#define SC_MAP_PRIVATE 0x02u
#define SC_MAP_FIXED   0x10u
#define SC_MAP_ANONYMOUS 0x20u

/* clone(2) flags we must refuse (threads share the address space —
 * the per-stub-process model is M5). */
#define SC_CLONE_VM     0x00000100ull
#define SC_CLONE_THREAD 0x00010000ull

/* The fixup counter's last logged value (the dispatch-tail gate line
 * prints the delta — hazard-3 native evidence). */
static unsigned long uacc_fixups_seen;

/* Queue one op for the syscall answer (the stub executes ops one
 * round-trip each). The dispatch resets the plan at entry, so ops
 * APPEND: the handler's own op (mmap/munmap/mprotect), any uaccess
 * write-fixup ops (hazard 3 — COW runs made private mid-handler)
 * and the fork hook's parent re-protect ops accumulate in order.
 * Never reset here — that would drop the fixups an earlier step in
 * the same answer already queued. Shared with stub_ctl.c (the fork
 * hook re-protects the parent's views). */
int uml_nt_sc_plan_add(struct uml_nt_stub_conn *c, unsigned op, unsigned prot,
		       unsigned long long va, unsigned long long len,
		       unsigned long long off)
{
	if (c->plan.n_ops >= UML_NT_FAULT_MAX_OPS)
		return -1;
	c->plan.ops[c->plan.n_ops].op = op;
	c->plan.ops[c->plan.n_ops].prot = prot;
	c->plan.ops[c->plan.n_ops].va = va;
	c->plan.ops[c->plan.n_ops].len = len;
	c->plan.ops[c->plan.n_ops].off = off;
	c->plan.n_ops++;
	c->plan_next = 0;
	c->plan_left = c->plan.n_ops;
	return 0;
}

/* Route one VFS-backed syscall through the REAL kernel table —
 * upstream handle_syscall parity (sys_call_table[nr](args...)). This
 * is the M3.8 answer to "bytes nằm trong ext4": getname()'s
 * strncpy_from_user, read()'s copy_to_user, uname's fill — they all
 * land on the D15 walker (patch 0014), which translates guest VAs
 * through the conn's VMA tree onto the flat physmem view. The
 * hand-rolled handlers above stay os-specific: they drive stub ops
 * and conn state, not the VFS. */
static unsigned long long sys_vfs(unsigned long long nr,
				  const unsigned long long *a)
{
	if (nr >= (unsigned long long)syscall_table_size /
			  sizeof(sys_call_ptr_t))
		return SC_RET(SC_ENOSYS);
	return (unsigned long long)sys_call_table[nr](a[0], a[1], a[2],
						      a[3], a[4], a[5]);
}

static unsigned linux_prot_to_nt(u32 lprot)
{
	if (lprot & SC_PROT_WRITE)
		return (lprot & SC_PROT_EXEC) ?
			UML_NT_PAGE_EXECUTE_READWRITE :
			UML_NT_PAGE_READWRITE;
	if (lprot & SC_PROT_READ)
		return (lprot & SC_PROT_EXEC) ?
			UML_NT_PAGE_EXECUTE_READ :
			UML_NT_PAGE_READONLY;
	if (lprot & SC_PROT_EXEC)
		return UML_NT_PAGE_EXECUTE;
	return UML_NT_PAGE_NOACCESS;
}

/* write(2): fds 0/1/2 are the console (the guest VFS owns its own
 * fds once real tasks exist — M3.8). Buffer translated single-VMA
 * (M3.4 contract): the console write reads straight out of the flat
 * view, no bounce buffer. */
static unsigned long long sys_write(struct uml_nt_stub_conn *c,
				    const unsigned long long *a)
{
	long long off;

	if (a[0] != 1 && a[0] != 2 && a[0] != 0)
		return SC_RET(SC_EBADF);
	if (a[2] > 0x40000000ull)
		return SC_RET(SC_EFAULT);
	off = uml_nt_vma_translate(c->mm, a[1], a[2]);
	if (off < 0)
		return SC_RET(SC_EFAULT);
	nt_console_write((char *)uml_boot.physmem_base + off,
			 (unsigned int)a[2]);
	/* M4.1: the bench markers ride the console path — exact-match
	 * (length-gated) so ordinary writes never pay a memcmp. */
	uml_nt_bench_write_marker((const char *)uml_boot.physmem_base + off,
				  a[2]);
	return a[2];
}

/* brk(2): the mm owns a pre-reserved, pre-mapped heap run (set up by
 * the exec path — heap_start..heap_end). Multi-run growth (M4 slice
 * 4): a request past the reservation re-homes the heap in a fresh
 * CONTIGUOUS span of the new total size — one MapViewOfFileEx must
 * cover the whole VMA (vma.h geometry), and the buddy owes no
 * adjacency, so in-place extension is only luck. The old contents
 * ride across through the flat view (kernel-side memcpy — the stub's
 * views are only mutated later, when the queued UNMAP old / MAP new
 * ops stream), the fresh growth area arrives zeroed (__GFP_ZERO
 * backend, the mmap path's guarantee), and the old span dies by
 * refcount. Fork-shared heaps grow correctly per-mm: the copy reads
 * the shared run's live content, the unref only drops THIS mm's
 * reference, the sibling keeps its own. Linux returns the CURRENT
 * brk (not an errno) on failure — every failure path here does
 * exactly that. Shrink: brk moves down, the reservation stays (no
 * unmap/relloc — Linux would release the pages; nothing we run
 * reclaims from it, and a regrow then needs no copy). */
static unsigned long long sys_brk(struct uml_nt_stub_conn *c,
				  const unsigned long long *a)
{
	struct uml_nt_mm *mm = c->mm;

	if (mm->heap_end == 0) {
		os_info("[syscall] brk: no heap reserved — ENOMEM\n");
		return mm->brk;
	}
	if (a[0] == 0)
		return mm->brk;
	if (a[0] < mm->heap_start) {
		os_info("[syscall] brk 0x%llx below heap start 0x%llx "
			"— kept 0x%llx\n",
			a[0], mm->heap_start, mm->brk);
		return mm->brk;
	}
	if (a[0] > mm->heap_end) {
		struct uml_nt_vma *hv = uml_nt_vma_find(mm, mm->heap_start);
		unsigned long long old_end = mm->heap_end;
		unsigned long long old_off, old_len, new_off, new_end;
		long long nruns, i;

		if (hv == NULL || hv->start != mm->heap_start ||
		    hv->end != old_end) {
			os_info("[syscall] brk: heap VMA [0x%llx,0x%llx) "
				"missing/mismatched — kept 0x%llx\n",
				mm->heap_start, old_end, mm->brk);
			return mm->brk;
		}
		nruns = ((a[0] - mm->heap_start) +
			 UML_NT_PHYS_RUN_SIZE - 1) / UML_NT_PHYS_RUN_SIZE;
		new_end = mm->heap_start +
			(unsigned long long)nruns * UML_NT_PHYS_RUN_SIZE;
		old_off = hv->run_off;
		old_len = old_end - mm->heap_start;

		new_off = (unsigned long long)
			uml_nt_phys_alloc_span(c->ph, (int)nruns);
		if ((long long)new_off < 0) {
			os_info("[syscall] brk: span of %lld run(s) "
				"exhausted — kept 0x%llx\n",
				nruns, mm->brk);
			return mm->brk;
		}
		memcpy((char *)uml_boot.physmem_base + new_off,
		       (char *)uml_boot.physmem_base + old_off, old_len);

		if (uml_nt_vma_del(mm, mm->heap_start, old_end) < 0 ||
		    uml_nt_vma_add(mm, mm->heap_start, new_end, new_off,
				   UML_NT_PAGE_READWRITE, 0) < 0) {
			/* Roll the old VMA back (the del succeeded if
			 * we got here); the fresh span dies young. */
			uml_nt_vma_add(mm, mm->heap_start, old_end,
				       old_off, UML_NT_PAGE_READWRITE, 0);
			for (i = 0; i < nruns; i++)
				uml_nt_phys_unref(c->ph,
						  (long long)new_off +
						  i * UML_NT_PHYS_RUN_SIZE);
			os_info("[syscall] brk: VMA resize failed — "
				"kept 0x%llx\n", mm->brk);
			return mm->brk;
		}
		for (i = 0; i < (long long)(old_len / UML_NT_PHYS_RUN_SIZE);
		     i++)
			uml_nt_phys_unref(c->ph,
					  (long long)old_off +
					  i * UML_NT_PHYS_RUN_SIZE);

		/* Stub view swap, in this op order: the whole old view
		 * (base = heap_start) goes, the bigger one arrives, and
		 * any guards inside come back NOACCESS (the fresh MAP
		 * covers them writable — the guard state is the fault
		 * truth, the view must match it: vma.h note). */
		uml_nt_sc_plan_add(c, UML_NT_FOP_UNMAP, 0, mm->heap_start,
				   old_len, old_off);
		uml_nt_sc_plan_add(c, UML_NT_FOP_MAP, UML_NT_PAGE_READWRITE,
				   mm->heap_start,
				   new_end - mm->heap_start, new_off);
		{
			int gi;

			for (gi = 0; gi < mm->nguard; gi++) {
				if (mm->guard[gi].start >= new_end ||
				    mm->guard[gi].end <= mm->heap_start)
					continue;
				uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT,
					UML_NT_PAGE_NOACCESS,
					mm->guard[gi].start,
					mm->guard[gi].end -
					mm->guard[gi].start, 0);
			}
		}
		os_info("[syscall] brk grow: heap [0x%llx,0x%llx) -> "
			"[0x%llx,0x%llx) span off=0x%llx (contents "
			"kept)\n", mm->heap_start, old_end,
			mm->heap_start, new_end, new_off);
		mm->heap_end = new_end;
	}
	mm->brk = a[0];
	return a[0];
}

/* mmap(2), anonymous|private only: fresh runs (zeroed by the D11
 * backend) + a VMA + a MAP op for the stub's address space. MAP_FIXED
 * must land on a FREE range — silently replacing VMAs would need
 * stub-side view surgery (UnmapViewOfFile is whole-view); MAP_FIXED
 * over anything = -ENOMEM loud for now. */
static unsigned long long sys_mmap(struct uml_nt_stub_conn *c,
				   const unsigned long long *a)
{
	unsigned long long addr = a[0], len = a[1], va;
	unsigned prot, nruns, i;
	long long sp;
	u32 lprot = (u32)a[2];
	u32 flags = (u32)a[3];
	long long fd = (long long)a[4];

	if (len == 0)
		return SC_RET(SC_EINVAL);
	if (!(flags & SC_MAP_ANONYMOUS) || fd != -1 || a[5] != 0) {
		os_info("[syscall] mmap: only anon|private for now "
			"(flags=0x%x fd=%lld off=%llu)\n", flags, fd, a[5]);
		return SC_RET(SC_ENOSYS);
	}
	len = (len + UML_NT_PHYS_RUN_SIZE - 1) &
	      ~(UML_NT_PHYS_RUN_SIZE - 1);
	prot = linux_prot_to_nt(lprot);

	if (flags & SC_MAP_FIXED) {
		unsigned long long runs[UML_NT_VMA_MAX];
		unsigned long long req_len = a[1];
		int nfree, i;

		va = addr;
		if (va & (UML_NT_PHYS_RUN_SIZE - 1)) {
			os_info("[syscall] mmap MAP_FIXED 0x%llx: not "
				"run-aligned\n", va);
			return SC_RET(SC_EINVAL);
		}
		/* Sub-run MAP_FIXED (page-aligned, inside ONE VMA backed
		 * by a private run): MATERIALIZED since M4 slice 5 —
		 * the musl mallocng brk guard
		 * mmap(brk_base, 4096, PROT_NONE, MAP_FIXED) gets real
		 * NOACCESS pages in the stub view + kernel guard state
		 * (a fault inside one is a real SIGSEGV, never
		 * auto-repaired — vma.h note). A non-NONE sub-run
		 * mapping (the view is already at the VMA prot) kills
		 * the guards under it: Linux lets the new mapping win. */
		if (req_len < UML_NT_PHYS_RUN_SIZE) {
			struct uml_nt_vma *gv = uml_nt_vma_find(c->mm, va);

			if (gv && va + req_len <= gv->end &&
			    !(va & (UML_NT_FAULT_PAGE_SIZE - 1)) &&
			    !((va + req_len) &
			      (UML_NT_FAULT_PAGE_SIZE - 1)) &&
			    uml_nt_phys_refs(c->ph,
					     (long long)(gv->run_off +
							 (va - gv->start))) <= 1) {
				int killed = uml_nt_guard_del_range(c->mm,
								 va,
								 va + req_len);

				if (prot == UML_NT_PAGE_NOACCESS) {
					if (uml_nt_guard_add(c->mm, va,
							     va + req_len) < 0)
						os_info("[syscall] mmap "
							"MAP_FIXED 0x%llx: "
							"guard table full — "
							"unmaterialized\n",
							va);
					else
						uml_nt_sc_plan_add(c,
							UML_NT_FOP_PROTECT,
							UML_NT_PAGE_NOACCESS,
							va, req_len, 0);
				}
				os_info("[syscall] mmap MAP_FIXED 0x%llx+%llu "
					"prot=0x%x: sub-run %s (%d guard(s) "
					"cleared)\n", va, req_len, lprot,
					(prot == UML_NT_PAGE_NOACCESS) ?
					"guard placed" : "mapping", killed);
				return va;
			}
		}
		/* Upstream MAP_FIXED REPLACES what is there (unmap the
		 * range, then create). The stub unmaps one whole view
		 * per op, so the replace is only expressible when
		 * every intersecting VMA lies fully inside the range:
		 * queue one UNMAP per removed VMA (the op's map_va
		 * must BE the view base), drop the runs, then map
		 * fresh. A flank overlap = -ENOMEM loud. */
		if (uml_nt_vma_span_fits(c->mm, va, va + len) < 0) {
			os_info("[syscall] mmap MAP_FIXED 0x%llx+%llu: "
				"partial VMA overlap — unsupported\n",
				va, len);
			return SC_RET(SC_ENOMEM);
		}
		nfree = uml_nt_vma_span_runs(c->mm, va, va + len, runs,
					     UML_NT_VMA_MAX);
		if (nfree < 0)
			return SC_RET(SC_ENOMEM);
		if (nfree > 0) {
			for (i = 0; i < c->mm->nvma; i++) {
				unsigned long long s = c->mm->vma[i].start;
				unsigned long long e = c->mm->vma[i].end;

				if (s >= va + len || e <= va)
					continue;
				uml_nt_sc_plan_add(c, UML_NT_FOP_UNMAP, 0,
						   s, e - s, 0);
			}
			uml_nt_vma_del(c->mm, va, va + len);
			for (i = 0; i < nfree; i++)
				uml_nt_phys_unref(c->ph,
						  (long long)runs[i]);
		}
	} else {
		va = uml_nt_vma_find_free(c->mm, len, UML_NT_SYSCALLS_BASE,
					  UML_NT_SYSCALLS_BASE +
					  uml_boot.physmem_size);
		if (va == 0)
			return SC_RET(SC_ENOMEM);
	}
	nruns = (unsigned)(len / UML_NT_PHYS_RUN_SIZE);
	sp = uml_nt_phys_alloc_span(c->ph, (int)nruns);
	if (sp < 0)
		return SC_RET(SC_ENOMEM);
	if (uml_nt_vma_add(c->mm, va, va + len, (unsigned long long)sp,
			   prot, 0) < 0) {
		for (i = 0; i < nruns; i++)
			uml_nt_phys_unref(c->ph, sp +
					  (long long)i *
					  UML_NT_PHYS_RUN_SIZE);
		return SC_RET(SC_ENOMEM);
	}
	os_info("[syscall] mmap 0x%llx+%llu prot=0x%x flags=0x%x "
		"-> off=0x%llx%s\n", va, len, lprot, flags,
		(unsigned long long)sp,
		(flags & SC_MAP_FIXED) ? " FIXED" : "");
	uml_nt_sc_plan_add(c, UML_NT_FOP_MAP, prot, va, len, (unsigned long long)sp);
	return va;
}

/* munmap(2), POC: whole VMAs only — the stub's ACTION_UNMAP is
 * UnmapViewOfFile (whole view), so a partial-range unmap would leave
 * flank VMAs pointing at a dead view. Ranges that don't align with
 * the VMA edges fail loudly (Linux short mappings are the M3.8+).
 * Unmapping nothing succeeds (Linux: munmap doesn't validate). */
static unsigned long long sys_munmap(struct uml_nt_stub_conn *c,
				     const unsigned long long *a)
{
	unsigned long long addr = a[0], len = a[1];
	struct uml_nt_mm *mm = c->mm;
	unsigned long long runs[UML_NT_VMA_MAX]; /* section offsets */
	int i, nruns;

	if (addr & (UML_NT_PHYS_RUN_SIZE - 1) || len == 0)
		return SC_RET(SC_EINVAL);
	len = (len + UML_NT_PHYS_RUN_SIZE - 1) &
	      ~(UML_NT_PHYS_RUN_SIZE - 1);
	for (i = 0; i < mm->nvma; i++) {
		unsigned long long s = mm->vma[i].start;
		unsigned long long e = mm->vma[i].end;

		if (s >= addr + len || e <= addr)
			continue;
		if (s < addr || e > addr + len) {
			os_info("[syscall] munmap 0x%llx+%llu: partial "
				"VMA [0x%llx, 0x%llx) — unsupported "
				"(whole views only)\n", addr, len, s, e);
			return SC_RET(SC_EINVAL);
		}
	}
	/* The unref set: each selected VMA contributes ITS OWN backing
	 * span, deduped per physical run (review M3.8: looping
	 * len/RUN from every VMA's run_off unrefs unrelated backing —
	 * underflows refcounts → premature frees). */
	nruns = uml_nt_vma_span_runs(mm, addr, addr + len, runs,
				     UML_NT_VMA_MAX);
	if (nruns < 0) {
		os_info("[syscall] munmap 0x%llx+%llu: unref set overflow\n",
			addr, len);
		return SC_RET(SC_ENOMEM);
	}
	if (nruns == 0)
		return 0; /* unmapped range: Linux succeeds */
	if (uml_nt_vma_del(mm, addr, addr + len) < 0)
		return SC_RET(SC_ENOMEM);
	for (i = 0; i < nruns; i++)
		uml_nt_phys_unref(c->ph, (long long)runs[i]);
	uml_nt_guard_del_range(mm, addr, addr + len); /* guards die too */
	uml_nt_sc_plan_add(c, UML_NT_FOP_UNMAP, 0, addr, len, 0);
	return 0;
}

/* mprotect(2): whole-VMA changes keep the wholesale VMA prot (the
 * fault repair maps back at it). Sub-run changes (page-aligned,
 * inside ONE VMA) are page-precise: the VMA keeps its base prot,
 * PROT_NONE arms a guard (kernel state + NOACCESS view op — the
 * musl mallocng meta-area pattern), any other prot kills the guards
 * under the range (Linux: the change wins). A real mprotect(RW) on a
 * COW VMA still forces a private copy first — unsupported (M4). */
static unsigned long long sys_mprotect(struct uml_nt_stub_conn *c,
				       const unsigned long long *a)
{
	unsigned long long addr = a[0], len = a[1];
	unsigned prot = linux_prot_to_nt((u32)a[2]);
	struct uml_nt_vma *v;

	if ((addr | len) & (UML_NT_FAULT_PAGE_SIZE - 1) || len == 0)
		return SC_RET(SC_EINVAL);
	v = uml_nt_vma_find(c->mm, addr);
	if (v == NULL || v->end < addr + len) {
		os_info("[syscall] mprotect 0x%llx+%llu: not inside one "
			"VMA\n", addr, len);
		return SC_RET(SC_ENOMEM);
	}
	if (v->flags & UML_NT_VMA_COW) {
		os_info("[syscall] mprotect on COW VMA — unsupported "
			"(M4)\n");
		return SC_RET(SC_ENOSYS);
	}
	if (addr == v->start && addr + len == v->end) {
		int killed = uml_nt_guard_del_range(c->mm, addr,
						    addr + len);

		if (uml_nt_vma_chg(c->mm, addr, addr + len, prot) < 0)
			return SC_RET(SC_ENOMEM);
		os_info("[syscall] mprotect 0x%llx+%llu -> 0x%x "
			"(whole VMA, was lprot 0x%llx, %d guard(s) "
			"cleared)\n", addr, len, prot, a[2], killed);
	} else {
		int killed = uml_nt_guard_del_range(c->mm, addr,
						    addr + len);

		if (prot == UML_NT_PAGE_NOACCESS) {
			if (uml_nt_guard_add(c->mm, addr, addr + len) < 0)
				return SC_RET(SC_ENOMEM);
		}
		os_info("[syscall] mprotect 0x%llx+%llu -> 0x%x "
			"(sub-run, was lprot 0x%llx, %d guard(s) %s)\n",
			addr, len, prot, a[2], killed,
			(prot == UML_NT_PAGE_NOACCESS) ? "armed" :
			"cleared");
	}
	uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT, prot, addr,
		 len, 0);
	return 0;
}

/* clock_gettime(2): ns-since-boot (os_nsecs, QPC) split into the
 * timespec the guest asked for. CLOCK_MONOTONIC (1) and CLOCK_REALTIME
 * (0) both map to it — the kernel owns no wall-clock offset (the
 * sysbench gate times a monotonic window). */
static unsigned long long sys_clock_gettime(struct uml_nt_stub_conn *c,
					    const unsigned long long *a)
{
	long long nsecs;
	unsigned long long buf[2];

	if (a[0] != 0 /* CLOCK_REALTIME */ &&
	    a[0] != 1 /* CLOCK_MONOTONIC */)
		return SC_RET(SC_EINVAL);
	if (a[1] == 0)
		return SC_RET(SC_EFAULT);
	nsecs = os_nsecs();
	buf[0] = (unsigned long long)(nsecs / 1000000000LL);
	buf[1] = (unsigned long long)(nsecs % 1000000000LL);
	if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a[1], 16,
			     (char *)buf, UML_NT_UACC_TO_GUEST) < 0)
		return SC_RET(SC_EFAULT);
	return 0;
}

/* rt_sigprocmask(2): signals are M4; the POC answers "mask was
 * empty" (zero the oldset the caller asked back) and succeeds. */static unsigned long long sys_sigprocmask(struct uml_nt_stub_conn *c,
					  const unsigned long long *a)
{
	if (a[2] != 0 && a[3] >= 8) {
		if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
				     a[2], 8, NULL,
				     UML_NT_UACC_ZERO_GUEST) < 0)
			return SC_RET(SC_EFAULT);
	}
	return 0;
}

/* M4.2: the REAL fork — the generic copy_process machinery through
 * the sys_call_table (upstream handle_syscall parity). The conn seed
 * hands the child conn its address space at birth (init_new_context
 * runs inside dup_mm); copy_thread gives the child a cold stack at
 * fork_handler whose userspace() loop serves its own conn; blocking
 * waits ride schedule(). The parent re-protect ops stream with the
 * fork answer (retval parked while plan_left > 0). */
static unsigned long long sys_fork_real(struct uml_nt_stub_conn *c,
					struct uml_nt_stub_data *d,
					const unsigned long long *a,
					unsigned long long nr)
{
	unsigned long long ret;

	uml_nt_sync_trap_regs(&current_pt_regs()->regs, d);
	uml_nt_fork_arm(c, d->regs.rsp);
	ret = sys_vfs(nr, a); /* generic fork/clone → copy_process */
	uml_nt_fork_disarm();
	if ((long long)ret >= 0) {
		uml_nt_fork_reprotect_parent(c);
	} else {
		os_info("[syscall] fork nr=%llu failed: %lld\n", nr,
			(long long)ret);
	}
	return ret;
}

/* execve (below) destroys the conn MID-DISPATCH on success: exec_mmap
 * drops the old mm (destroy_context → mmctx_destroy frees the conn and
 * unmaps d) and binfmt_umlnt loads the new image into a NEW conn —
 * start_thread wrote its entry into current_pt_regs. The handler must
 * not touch c or d afterwards; serve_conn consumes this flag (and
 * bails the protocol round — the dead stub gets no evt_out) and the
 * userspace() loop restarts on the new conn. */
static int exec_pending;

int uml_nt_syscall_consume_exec(void)
{
	int p = exec_pending;

	exec_pending = 0;
	return p;
}

/* execve(2): kernel_execve in THIS task's context (the pump thread —
 * upstream parity: the syscall runs in the guest task's kernel
 * thread; init is a user_mode_thread, so no PF_KTHREAD refusal).
 * Strings walk guest memory through the D15 uacc — argv/envp are
 * guest pointer arrays. Success never returns to the guest caller. */
static unsigned long long sys_execve(struct uml_nt_stub_conn *c,
				     const unsigned long long *a)
{
	/* argv + envp strings in one flat slab (64 × 513 ≈ 33 KB —
	 * kvmalloc, not the 16 KB task stack). */
#define UML_NT_EXEC_MAX_STR 32u
#define UML_NT_EXEC_STRLEN  512u
	char path[UML_NT_EXEC_STRLEN + 1];
	char (*strs)[UML_NT_EXEC_STRLEN + 1];
	const char **kargv, **kenvp;
	unsigned long long i, nav = 0, nev = 0;
	int rc;

	if (a[0] == 0) {
		os_info("[syscall] execve: NULL path (argv 0x%llx)\n",
			a[1]);
		return SC_RET(SC_EFAULT);
	}
	if (uml_nt_uacc_strncpy(path, c->mm, uml_boot.physmem_base, a[0],
				UML_NT_EXEC_STRLEN) < 0) {
		os_info("[syscall] execve: path 0x%llx unmapped\n", a[0]);
		return SC_RET(SC_EFAULT);
	}

	strs = kvmalloc((UML_NT_EXEC_MAX_STR * 2) * sizeof(*strs),
			GFP_KERNEL);
	kargv = kvmalloc((UML_NT_EXEC_MAX_STR + 1) * sizeof(*kargv),
			 GFP_KERNEL);
	kenvp = kvmalloc((UML_NT_EXEC_MAX_STR + 1) * sizeof(*kenvp),
			 GFP_KERNEL);
	if (strs == NULL || kargv == NULL || kenvp == NULL) {
		kvfree(strs);
		kvfree(kargv);
		kvfree(kenvp);
		os_info("[syscall] execve(%s): kvmalloc failed\n", path);
		return SC_RET(SC_ENOMEM);
	}

	if (a[1] != 0) {
		for (i = 0; i < UML_NT_EXEC_MAX_STR; i++) {
			unsigned long long p;

			if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
					     a[1] + i * 8, 8, (char *)&p,
					     UML_NT_UACC_FROM_GUEST) < 0)
				goto efault;
			if (p == 0)
				break;
			if (uml_nt_uacc_strncpy(strs[nav], c->mm,
						uml_boot.physmem_base, p,
						UML_NT_EXEC_STRLEN) < 0)
				goto efault;
			kargv[nav] = strs[nav];
			nav++;
		}
	}
	if (a[2] != 0) {
		for (i = 0; i < UML_NT_EXEC_MAX_STR; i++) {
			unsigned long long p;

			if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base,
					     a[2] + i * 8, 8, (char *)&p,
					     UML_NT_UACC_FROM_GUEST) < 0)
				goto efault;
			if (p == 0)
				break;
			if (uml_nt_uacc_strncpy(
				    strs[UML_NT_EXEC_MAX_STR + nev], c->mm,
				    uml_boot.physmem_base, p,
				    UML_NT_EXEC_STRLEN) < 0)
				goto efault;
			kenvp[nev] = strs[UML_NT_EXEC_MAX_STR + nev];
			nev++;
		}
	}
	kargv[nav] = NULL;
	kenvp[nev] = NULL;
	os_info("[syscall] execve(%s): %llu argv, %llu envp — calling "
		"kernel_execve\n", path, nav, nev);

	rc = kernel_execve(path, kargv, kenvp);
	kvfree(kargv);
	kvfree(kenvp);
	kvfree(strs);
	if (rc == 0) {
		exec_pending = 1;
		return 0; /* the guest caller no longer exists */
	}
	os_info("[syscall] execve(%s): failed rc=%d\n", path, rc);
	return (unsigned long long)(long long)rc;

efault:
	kvfree(kargv);
	kvfree(kenvp);
	kvfree(strs);
	os_info("[syscall] execve(%s): argv/envp walk faulted at "
		"[%llu argv, %llu envp]\n", path, nav, nev);
	return SC_RET(SC_EFAULT);
}

/* arch_prctl — musl TLS (S4c2). ARCH_SET_FS records the guest TLS
 * pointer in the conn and publishes it to the stub (d->fs_base); the
 * stub re-applies it at every resume into guest code (D18 — Windows
 * scheduling does not preserve a user FS base, probes/fsgsbase S4c
 * evidence; upstream keeps the base in the task regs, Linux-side).
 * The pointer must be guest-mapped: validated through the same
 * uaccess walk every other handler uses. ARCH_GET_FS returns it —
 * the *addr writeback is deferred until a caller needs it (musl
 * never queries). */
#define UML_NT_ARCH_SET_FS 0x1002ull
#define UML_NT_ARCH_GET_FS 0x1003ull

static unsigned long long sys_arch_prctl(struct uml_nt_stub_conn *c,
					 struct uml_nt_stub_data *d,
					 const unsigned long long *a)
{
	switch (a[0]) {
	case UML_NT_ARCH_SET_FS:
		/* The TLS pointer is a plain pointer, NOT a string —
		 * validate by VMA containment (the same lookup the
		 * walker translates through). A strncpy here "faults"
		 * on any tp whose first byte is not NUL. */
		if (a[1] == 0 ||
		    uml_nt_vma_translate(c->mm, a[1], 1) < 0) {
			os_info("[syscall] arch_prctl(SET_FS, 0x%llx): "
				"tp unmapped\n", a[1]);
			return SC_RET(SC_EFAULT);
		}
		c->fs_base = a[1];
		d->fs_base = a[1];
		os_info("[syscall] arch_prctl(SET_FS, 0x%llx): recorded\n",
			a[1]);
		return 0;
	case UML_NT_ARCH_GET_FS:
		return c->fs_base;
	default:
		os_info("[syscall] arch_prctl(cmd=0x%llx): unsupported\n",
			a[0]);
		return SC_RET(SC_EINVAL);
	}
}

void uml_nt_syscall_handle(struct uml_nt_stub_conn *c,
			   struct uml_nt_stub_data *d)
{
	const unsigned long long *a = d->args;
	unsigned long long nr = d->regs.rax;
	unsigned long long ret;
	struct uml_nt_uacc_sink sink;
	/* Nesting save (M4.2): a handler may BLOCK (wait4 → schedule)
	 * and a nested dispatch runs on the switched stack — it saves
	 * ours and we restore theirs at exit; clearing here would
	 * EFAULT the woken outer dispatch's writebacks. */
	struct uml_nt_mm *uacc_prev_mm;
	struct uml_nt_uacc_sink uacc_prev_sink;

	uacc_prev_mm = uml_nt_uacc_set_mm(c->mm);
	/* The write-fixup channel (hazard 3): the handler's to_user/
	 * clear_user/futex writes force COW-shared runs private and
	 * queue their remap ops into THIS plan — streamed after the
	 * handler, retval parked (below). */
	sink.ph = c->ph;
	sink.plan = &c->plan;
	uacc_prev_sink = uml_nt_uacc_set_sink(&sink);
	d->err = 0;
	d->halt = 0;
	c->plan.kill = 0;
	c->plan.n_ops = 0;
	c->plan.copy_src_off = 0;
	c->plan.copy_dst_off = 0;
	c->plan_next = 0;
	c->plan_left = 0;
	c->plan_has_retval = 0;

	switch (nr) {
	case 60: /* exit */
	case 231: /* exit_group — POC: same halt; child teardown is the
		   * M4 signal/exit work (upstream: zap every task) */
		d->retval = a[0];
		d->halt = 1;
		goto out;
	case 0: /* read — guest fds (init: 0/1/2 = /dev/console via
		 * console_on_rootfs; script/file fds from openat) */
	case 2: /* open — musl still issues plain open(2) */
	case 3: /* close */
	case 63: /* uname — busybox sh queries at startup */
	case 72: /* fcntl — ash dups the script fd high (F_DUPFD*) */
	case 257: /* openat */
	case 4: /* stat — musl path resolution (sh /hi.sh) */
	case 5: /* fstat — musl stdio sizing/ash script fd */
	case 8: /* lseek — ash reads the script by chunks */
	case 79: /* getcwd — ash prompt/pwd */
	case 217: /* getdents64 — ash PATH search, glob */
	case 20: /* writev — musl __stdio_write IS writev: every byte
		  * busybox prints goes through here (fd 1/2 = the
		  * real console files of the exec'd task) */
		ret = sys_vfs(nr, a);
		break;
	case 1: /* write */
		ret = sys_write(c, a);
		break;
	case 9: /* mmap */
		ret = sys_mmap(c, a);
		break;
	case 10: /* mprotect */
		ret = sys_mprotect(c, a);
		break;
	case 11: /* munmap */
		ret = sys_munmap(c, a);
		break;
	case 12: /* brk */
		ret = sys_brk(c, a);
		break;
	case 13: /* rt_sigaction — REAL on task-backed conns: the
		  * generic sys_rt_sigaction records the handler +
		  * SA_RESTORER; delivery runs in the pump's
		  * signal_check (interrupt_end → do_signal). POC
		  * conns keep the ack-only answer. */
		if (c->task_backed) {
			ret = sys_vfs(nr, a);
			break;
		}
		ret = 0;
		break;
	case 14: /* rt_sigprocmask */
		ret = sys_sigprocmask(c, a);
		break;
	case 15: /* rt_sigreturn — the frame is read from the TRAP's
		  * rsp: sync the trap state into current->thread.regs
		  * first (the dispatch runs one round stale — the
		  * M4.2 fork lesson), then the generic
		  * sys_rt_sigreturn restores GP + FP from the frame's
		  * sigcontext/fpstate into thread.regs. The pump's
		  * signal_check pushes the restored state VERBATIM
		  * (no rip+2/rax=retval syscall resume over it). */
		if (c->task_backed) {
			uml_nt_sync_trap_regs(&current_pt_regs()->regs, d);
			ret = sys_vfs(nr, a);
			c->sig_regs_current = 1;
			c->push_verbatim = 1;
			break;
		}
		ret = SC_RET(SC_ENOSYS);
		break;
	case 16: /* ioctl — console is non-tty-interative for now */
		ret = SC_RET(SC_ENOTTY);
		break;
	case 39: /* getpid */
	case 186: /* gettid */
		ret = c->pid;
		break;
	case 110: /* getppid */
		ret = c->ppid;
		break;
	case 102: /* getuid */
	case 104: /* getgid */
	case 107: /* geteuid */
	case 108: /* getegid */
		ret = 0;
		break;
	case 56: /* clone */
		if (a[0] & (SC_CLONE_VM | SC_CLONE_THREAD)) {
			os_info("[syscall] clone(flags=0x%llx): threads "
				"unsupported (M5) → ENOSYS\n", a[0]);
			ret = SC_RET(SC_ENOSYS);
			break;
		}
		if (c->task_backed) {
			/* !CLONE_VM clone ≈ fork with flags: the generic
			 * path (M4.2) owns it end to end. */
			ret = sys_fork_real(c, d, a, nr);
			break;
		}
		uml_nt_sys_fork(c, d); /* fork semantics (POC) */
		ret = d->retval;
		break;
	case 57: /* fork */
		if (c->task_backed) {
			ret = sys_fork_real(c, d, a, nr);
			break;
		}
		uml_nt_sys_fork(c, d);
		ret = d->retval;
		break;
	case 59: /* execve — conn switch (see exec_pending above) */
		ret = sys_execve(c, a);
		break;
	case 61: /* wait4 */
		if (c->task_backed) {
			/* The REAL wait: do_wait blocks the task (TASK_
			 * INTERRUPTIBLE → schedule()) until the child's
			 * do_exit wakes it — the scheduler runs the
			 * child's stack (its userspace() loop serves its
			 * conn) while the parent waits. The POC hook
			 * below only serves the probe conns (no task). */
			ret = sys_vfs(nr, a);
			break;
		}
		uml_nt_sys_wait4(c, d, a);
		ret = d->retval;
		break;
	case 218: /* set_tid_address */
		c->clear_tid_va = a[0];
		ret = c->pid;
		break;
	case 158: /* arch_prctl — musl TLS (ARCH_SET_FS → D18) */
		ret = sys_arch_prctl(c, d, a);
		break;
	case 228: /* clock_gettime — the guest's time source (M4 sysbench):
		   * CLOCK_MONOTONIC/REALTIME both read os_nsecs() (QPC,
		   * D6) — the boot-relative ns clock the whole kernel
		   * already runs on. timespec walks the D15 walker
		   * (guest pointer). */
		ret = sys_clock_gettime(c, a);
		break;
	default:
		os_info("[syscall] nr=%llu not implemented → ENOSYS "
			"(add it: STATUS M3.7 order)\n", nr);
		ret = SC_RET(SC_ENOSYS);
		break;
	}

	if (exec_pending) {
		/* The exec destroyed this conn (and d): touch neither.
		 * The out: teardown below only clears the globals. */
		goto out;
	}
	d->retval = ret;
	d->err = ((long long)ret < 0 && (long long)ret > -512) ? 1 : 0;
	if (c->plan_left > 0) {
		/* The syscall carries stub ops: park the return value —
		 * the op results travel through d->retval and the plan
		 * re-publishes ours on the final NONE. */
		c->plan_has_retval = 1;
		c->plan_retval = ret;
	}
	if (uml_nt_uacc_fixups != uacc_fixups_seen) {
		/* Hazard-3 gate evidence: a handler's to_user/clear/
		 * futex write hit a COW-shared run and the walker copied
		 * it private (the native CI gate greps this line). */
		uacc_fixups_seen = uml_nt_uacc_fixups;
		os_info("[stubtest] uacc COW fixup: run(s) copied private "
			"(total %lu)\n", uacc_fixups_seen);
	}
out:
	uml_nt_uacc_set_mm(uacc_prev_mm);
	uml_nt_uacc_set_sink(&uacc_prev_sink);
}
