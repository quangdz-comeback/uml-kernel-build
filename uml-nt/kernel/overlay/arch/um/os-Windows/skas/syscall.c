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
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/string.h>

#include <asm/syscall.h>
#include <os.h>
#include <internal.h>
#include <physalloc.h>
#include <stub-panic.h>
#include <stub_nt.h>
#include <syscall.h>
#include <bench.h>
#include <uaccess_walk.h>
#include <lazyfile_model.h>
#include <d20sweep_model.h>

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
#define SC_EACCES  13

#define SC_RET(e) ((unsigned long long)-(long long)(e))

/* mmap(2) flags/values (asm-generic/mman.h). */
#define SC_PROT_READ  0x1u
#define SC_PROT_WRITE 0x2u
#define SC_PROT_EXEC  0x4u
#define SC_MAP_SHARED  0x01u
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
	/* M5.6a (to-shelley 140 — stream atomicity): mid-drain the
	 * position is SACRED — the append rides behind the unissued
	 * tail and the prime (uml_nt_view_release_complete) recounts
	 * it (the 7496f70 drain-position restore keeps the PROT_DONE
	 * context's own accounting). The reset-at-0 below is the
	 * drained-plan, decision-time semantic every queued-op caller
	 * relies on. */
	if (c->plan_left == 0) {
		c->plan_next = 0;
		c->plan_left = c->plan.n_ops;
	}
	return 0;
}

/* M5.6a root-cause fix: the all-or-nothing capacity check for the
 * table<->view swap (see syscall.h). Pure delegation to the fault
 * core's host-tested helper. */
int uml_nt_sc_plan_reserve(struct uml_nt_stub_conn *c, int need)
{
	return uml_nt_fault_plan_reserve(&c->plan, need);
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
	/* Map 049 item 2: a console write whose backing run nobody
	 * refs is a stolen run (the run 0x28b0000 class) — EFAULT, and
	 * the [phys] lines name the thief. */
	if (uml_nt_phys_refs(c->ph,
			     off & ~(long long)(UML_NT_PHYS_RUN_SIZE - 1)) ==
	    0) {
		os_info("[syscall] write 0x%llx: run off=0x%llx unowned "
			"(stolen VMA)\n", a[1], (unsigned long long)off);
		return SC_RET(SC_EFAULT);
	}
	nt_console_write((char *)uml_boot.physmem_base + off,
			 (unsigned int)a[2]);
	/* M4.1: the bench markers ride the console path — exact-match
	 * (length-gated) so ordinary writes never pay a memcmp. */
	uml_nt_bench_write_marker((const char *)uml_boot.physmem_base + off,
				  a[2]);
	return a[2];
}

#define UML_NT_MMAP_SPAN_RUNS 64

/* brk(2): the mm owns a pre-reserved, pre-mapped heap run (set up by
 * the exec path — heap_start..heap_end). Multi-run growth: a request
 * past the reservation appends delta run spans covering [old_end,
 * new_end) rather than re-homing the entire [heap_start, new_end)
 * heap. Appending delta runs preserves existing heap views across
 * COW splits (which subdivide [heap_start, old_end) into per-run VMAs)
 * and avoids double-allocating + copying the existing heap on every
 * growth step. */
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
		unsigned long long old_end = mm->heap_end;
		unsigned long long new_end, cur, clen = 0, chk;
		long long delta_runs;
		int plan_base, plan_left_base, plan_next_base;

		if (uml_nt_vma_find(mm, mm->heap_start) == NULL ||
		    uml_nt_vma_find(mm, old_end - 1) == NULL) {
			os_info("[syscall] brk: heap VMA [0x%llx,0x%llx) "
				"missing — kept 0x%llx\n",
				mm->heap_start, old_end, mm->brk);
			return mm->brk;
		}
		delta_runs = ((a[0] - old_end) +
			      UML_NT_PHYS_RUN_SIZE - 1) / UML_NT_PHYS_RUN_SIZE;
		new_end = old_end +
			(unsigned long long)delta_runs * UML_NT_PHYS_RUN_SIZE;
		for (chk = old_end; chk < new_end;
		     chk += UML_NT_PHYS_RUN_SIZE) {
			if (uml_nt_vma_find(mm, chk) != NULL) {
				os_info("[syscall] brk: [0x%llx,0x%llx) "
					"collides at 0x%llx — kept 0x%llx\n",
					old_end, new_end, chk, mm->brk);
				return mm->brk;
			}
		}

		plan_base = c->plan.n_ops;
		plan_left_base = c->plan_left;
		plan_next_base = c->plan_next;
		for (cur = old_end; cur < new_end; cur += clen) {
			unsigned long long rem_runs =
				(new_end - cur) / UML_NT_PHYS_RUN_SIZE;
			unsigned int want =
				(rem_runs > UML_NT_MMAP_SPAN_RUNS) ?
				UML_NT_MMAP_SPAN_RUNS :
				(unsigned int)rem_runs;
			unsigned long long sp = (unsigned long long)-1LL;

			while (want >= 1) {
				sp = (unsigned long long)
					uml_nt_phys_alloc_span(c->ph,
							       (int)want);
				if ((long long)sp >= 0)
					break;
				if (want == 1)
					break;
				{
					unsigned int p2 = 1;

					while ((p2 << 1) < want)
						p2 <<= 1;
					want = p2;
				}
			}
			if ((long long)sp < 0) {
				os_info("[syscall] brk: span of %llu run(s) "
					"at 0x%llx exhausted — kept 0x%llx\n",
					rem_runs, cur, mm->brk);
				goto rollback_brk;
			}
			clen = (unsigned long long)want *
			       UML_NT_PHYS_RUN_SIZE;
			if (uml_nt_sc_plan_reserve(c, 1) < 0) {
				unsigned long long roff;

				os_info("[syscall] brk: view-swap plan full "
					"at 0x%llx — kept 0x%llx\n",
					cur, mm->brk);
				for (roff = sp; roff < sp + clen;
				     roff += UML_NT_PHYS_RUN_SIZE)
					uml_nt_phys_unref_for(c->ph,
							      (long long)roff,
							      (const void *)0);
				goto rollback_brk;
			}
			if (uml_nt_vma_add_gen(mm, cur, cur + clen, sp,
					       UML_NT_PAGE_READWRITE, 0,
					       (unsigned long long)
					       uml_nt_phys_gen(
						       c->ph,
						       (long long)sp)) < 0) {
				unsigned long long roff;

				os_info("[syscall] brk: VMA add failed at "
					"0x%llx — kept 0x%llx\n",
					cur, mm->brk);
				for (roff = sp; roff < sp + clen;
				     roff += UML_NT_PHYS_RUN_SIZE)
					uml_nt_phys_unref_for(c->ph,
							      (long long)roff,
							      (const void *)0);
				goto rollback_brk;
			}
			uml_nt_sc_plan_add(c, UML_NT_FOP_MAP,
					   UML_NT_PAGE_READWRITE,
					   cur, clen, sp);
		}
		if (0) {
			unsigned long long rb;
rollback_brk:
			for (rb = old_end; rb < cur; ) {
				const struct uml_nt_vma *rv =
					uml_nt_vma_find(mm, rb);
				unsigned long long rlen, roff, roff_end;

				if (rv == NULL || rv->start != rb)
					break;
				rlen = rv->end - rv->start;
				roff = rv->run_off;
				roff_end = roff + rlen;
				uml_nt_vma_del(mm, rb, rb + rlen);
				for (; roff < roff_end;
				     roff += UML_NT_PHYS_RUN_SIZE)
					uml_nt_phys_unref_for(c->ph,
							      (long long)roff,
							      (const void *)0);
				rb += rlen;
			}
			c->plan.n_ops = plan_base;
			c->plan_left = plan_left_base;
			c->plan_next = plan_next_base;
			return mm->brk;
		}
		os_info("[syscall] brk grow: heap [0x%llx,0x%llx) -> "
			"[0x%llx,0x%llx) (+%lld run(s))\n",
			mm->heap_start, old_end, mm->heap_start,
			new_end, delta_runs);
		mm->heap_end = new_end;
	}
	mm->brk = a[0];
	return a[0];
}

/* The c2 file-backed helpers below; sys_mmap's MAP_FIXED branch
 * delegates the inside-a-file-VMA refill to them. */
static int uml_nt_mmap_fill(struct uml_nt_stub_conn *c,
			    unsigned long long map_start,
			    unsigned long long len, struct file *f,
			    unsigned long long off,
			    unsigned long long fsize, int zero);
static long long uml_nt_mmap_sweep(struct uml_nt_stub_conn *c,
				   unsigned long long map_start,
				   unsigned long long len);

/* c3: is [start, end) fully covered by FILE VMAs (fresh chunking
 * makes refills cross chunk boundaries)? *nchunks counts the VMAs
 * hit (a hole or a non-FILE VMA fails it). */
static int uml_nt_mmap_refill_ok(struct uml_nt_mm *mm,
				 unsigned long long start,
				 unsigned long long end, int *nchunks)
{
	unsigned long long cur = start;
	struct uml_nt_vma *v;
	int n = 0;

	while (cur < end) {
		v = uml_nt_vma_find(mm, cur);

		if (v == NULL || v->end <= cur ||
		    !(v->flags & UML_NT_VMA_FILE))
			return 0;
		cur = (end < v->end) ? end : v->end;
		n++;
	}
	*nchunks = n;
	return 1;
}

/* mmap(2), anonymous|private only: fresh runs (zeroed by the D11
 * backend) + a VMA + a MAP op for the stub's address space. MAP_FIXED
 * must land on a FREE range — silently replacing VMAs would need
 * stub-side view surgery (UnmapViewOfFile is whole-view); MAP_FIXED
 * over anything = -ENOMEM loud for now. */
static int lazy_unmap(struct uml_nt_stub_conn *c, unsigned long long start,
		      unsigned long long end);
static unsigned long long lazy_find_free(struct uml_nt_stub_conn *c,
					 unsigned long long len,
					 unsigned long long base,
					 unsigned long long limit);

static unsigned long long sys_mmap(struct uml_nt_stub_conn *c,
				   const unsigned long long *a)
{
	unsigned long long addr = a[0], len = a[1], va;
	unsigned prot, nruns, i;
	long long sp;
	u32 lprot = (u32)a[2];
	u32 flags = (u32)a[3];
	/* fd is an int in the mmap ABI: glibc's -1 arrives as the
	 * zero-extended 0xFFFFFFFF (mov r8d, -1) — Linux reads only
	 * the low 32 bits. */
	long long fd = (long long)(int)(unsigned)a[4];

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

	/* D28: an explicit MAP_FIXED replace over a deferred file region
	 * drops (full cover) or materializes (partial) it first — the
	 * region is invisible to the VMA replace below. */
	if ((flags & SC_MAP_FIXED) && addr != 0 && len != 0 &&
	    uml_nt_lazy_overlap(c, addr, addr + len)) {
		if (lazy_unmap(c, addr, addr + len) < 0)
			return SC_RET(SC_ENOMEM);
	}

	if (flags & SC_MAP_FIXED) {
		static unsigned long long runs[UML_NT_PHYS_MAX_RUNS];
		unsigned long long req_len = a[1];
		int nfree, i;

		va = addr;
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
					/* M5.6a root-cause fix: the guard's
					 * NOACCESS view op is reserved
					 * BEFORE the guard state moves —
					 * a dropped op would leave a guard
					 * the guest writes straight
					 * through (fault truth and view
					 * silently diverged). All or
					 * nothing: no op, no guard. */
					if (uml_nt_sc_plan_reserve(c, 1) <
					    0) {
						os_info("[syscall] mmap "
							"MAP_FIXED 0x%llx: "
							"view-swap plan "
							"full — guard "
							"unmaterialized\n",
							va);
					} else if (uml_nt_guard_add(
							c->mm, va,
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
		 * fresh. A flank overlap = -ENOMEM loud.
		 *
		 * EXCEPTION (M5.4 c2, before the replace machinery):
		 * a MAP_FIXED range fully INSIDE one FILE VMA refills
		 * bytes instead — the loader's per-segment mappings
		 * (and the anon .bss tail: fd == -1 + MAP_ANONYMOUS
		 * arrives here as a ZERO refill) all sit mid-run,
		 * 4K-aligned, where a run cannot be split for a view.
		 * c3: big file mappings are CHUNKED (sys_mmap_file,
		 * span order cap), so the refill may cross several
		 * chunk VMAs — every intersecting VMA must be
		 * file-backed (the chunks tile the span, no holes),
		 * then the fill/sweep walk does the rest per-VMA.
		 * Non-NONE anon sub-run mappings on ANON VMAs keep the
		 * old semantics below (no refill — nothing maps there
		 * twice). */
		{
			int nfile = 0;

			/* The byte range, NOT the run-rounded len — a
			 * round-raised end would stick out of the file
			 * span and fail the walk (glibc's bss tail
			 * rides just under mapend). */
			if (uml_nt_mmap_refill_ok(c->mm, addr,
						  addr + req_len, &nfile)) {
				int killed = uml_nt_guard_del_range(c->mm,
								addr,
								addr +
								req_len);

				if (uml_nt_mmap_fill(c, addr, req_len, NULL,
						     0, 0, 1) < 0)
					return SC_RET(SC_EFAULT);
				if (lprot & SC_PROT_EXEC) {
					long long p = uml_nt_mmap_sweep(c,
							addr, req_len);

					if (p < 0)
						return SC_RET(SC_EFAULT);
				}
				os_info("[syscall] mmap MAP_FIXED 0x%llx+"
					"%llu prot=0x%x: file-VMA refill "
					"(%d chunk(s), %d guard(s) "
					"cleared)\n", addr, req_len, lprot,
					nfile, killed);
				return addr;
			}
		}
		/* Fresh/replace territory — run-aligned only (the VMA
		 * geometry contract). The refill paths above are
		 * byte-ranged and take any 4K-aligned address. */
		if (va & (UML_NT_PHYS_RUN_SIZE - 1)) {
			os_info("[syscall] mmap MAP_FIXED 0x%llx: not "
				"run-aligned\n", va);
			return SC_RET(SC_EINVAL);
		}
		if (uml_nt_vma_span_fits(c->mm, va, va + len) < 0) {
			os_info("[syscall] mmap MAP_FIXED 0x%llx+%llu: "
				"partial VMA overlap — unsupported\n",
				va, len);
			return SC_RET(SC_ENOMEM);
		}
		nfree = uml_nt_vma_span_runs(c->mm, va, va + len, runs,
					     UML_NT_PHYS_MAX_RUNS);
		if (nfree < 0)
			return SC_RET(SC_ENOMEM);
		if (nfree > 0) {
			/* M5.6a root-cause fix: all-or-nothing — the
			 * replace's whole op set (one UNMAP per removed
			 * VMA + the fresh MAP below) is reserved BEFORE
			 * the table moves. A dropped op here strands the
			 * stub's view on a dropped, recycled run (the
			 * K3 uaccess-fixup precedent, 37137513174).
			 * Refusal is Linux-shaped (-ENOMEM, loud). */
			int nvict = 0;

			for (i = 0; i < c->mm->nvma; i++) {
				unsigned long long s =
					c->mm->vma[i].start;
				unsigned long long e = c->mm->vma[i].end;

				if (s < va + len && e > va)
					nvict++;
			}
			if (uml_nt_sc_plan_reserve(c, nvict + 1) < 0) {
				os_info("[syscall] mmap MAP_FIXED "
					"0x%llx+%llu: view-swap plan "
					"full (%d op(s) needed) — "
					"ENOMEM\n", va, len, nvict + 1);
				return SC_RET(SC_ENOMEM);
			}
			for (i = 0; i < c->mm->nvma; i++) {
				unsigned long long s = c->mm->vma[i].start;
				unsigned long long e = c->mm->vma[i].end;

				if (s >= va + len || e <= va)
					continue;
				if (uml_nt_sc_plan_add(c, UML_NT_FOP_UNMAP,
						       0, s, e - s, 0) < 0) {
					/* Cannot happen (reserved above):
					 * the invariant is the fix's
					 * core — never silent. */
					os_info("[viewswap] replace UNMAP "
						"dropped post-reserve — "
						"INVARIANT BROKEN (pid "
						"%lu)\n",
						(unsigned long)c->pid);
					break;
				}
			}
			uml_nt_vma_del(c->mm, va, va + len);
			for (i = 0; i < nfree; i++)
				uml_nt_phys_unref_for(c->ph,
						      (long long)runs[i], c);
		}
	} else {
		va = lazy_find_free(c, len, UML_NT_SYSCALLS_BASE,
				    UML_NT_SYSCALLS_BASE +
				    uml_boot.physmem_size);
		if (va == 0)
			return SC_RET(SC_ENOMEM);
	}
	nruns = (unsigned)(len / UML_NT_PHYS_RUN_SIZE);
	if (nruns > UML_NT_MMAP_SPAN_RUNS) {
		os_info("[syscall] mmap 0x%llx+%llu: span of %u run(s) "
			"failed\n", va, len, nruns);
		return SC_RET(SC_ENOMEM);
	}
	{
		unsigned long long cur, clen = 0, first_sp = 0, first_clen = 0;
		int plan_base = c->plan.n_ops;
		int plan_left_base = c->plan_left;
		int plan_next_base = c->plan_next;

		for (cur = va; cur < va + len; cur += clen) {
			unsigned long long rem_runs =
				(va + len - cur) / UML_NT_PHYS_RUN_SIZE;
			unsigned int want = (unsigned int)rem_runs;

			sp = -1;
			while (want >= 1) {
				sp = uml_nt_phys_alloc_span(c->ph, (int)want);
				if (sp >= 0)
					break;
				if (want == 1)
					break;
				{
					unsigned int p2 = 1;

					while ((p2 << 1) < want)
						p2 <<= 1;
					want = p2;
				}
			}
			if (sp < 0) {
				os_info("[syscall] mmap 0x%llx+%llu: span of "
					"%llu run(s) at 0x%llx failed\n",
					va, len, rem_runs, cur);
				goto rollback_anon;
			}
			clen = (unsigned long long)want *
			       UML_NT_PHYS_RUN_SIZE;
			if (cur == va) {
				first_sp = (unsigned long long)sp;
				first_clen = clen;
			}
			if (uml_nt_sc_plan_reserve(c, 1) < 0) {
				os_info("[syscall] mmap 0x%llx+%llu: "
					"view-swap plan full — ENOMEM\n",
					va, len);
				for (i = 0; i < want; i++)
					uml_nt_phys_unref_for(c->ph, sp +
							      (long long)i *
							      UML_NT_PHYS_RUN_SIZE,
							      (const void *)0);
				goto rollback_anon;
			}
			if (uml_nt_vma_add_gen(c->mm, cur, cur + clen,
					       (unsigned long long)sp,
					       prot, 0,
					       (unsigned long long)
					       uml_nt_phys_gen(
						       c->ph,
						       (long long)sp)) < 0) {
				for (i = 0; i < want; i++)
					uml_nt_phys_unref_for(c->ph, sp +
							      (long long)i *
							      UML_NT_PHYS_RUN_SIZE,
							      (const void *)0);
				goto rollback_anon;
			}
			uml_nt_sc_plan_add(c, UML_NT_FOP_MAP, prot, cur, clen,
					   (unsigned long long)sp);
		}
		if (0) {
			unsigned long long rb;
rollback_anon:
			for (rb = va; rb < cur; ) {
				const struct uml_nt_vma *rv =
					uml_nt_vma_find(c->mm, rb);
				unsigned long long rlen, roff, roff_end;

				if (rv == NULL || rv->start != rb)
					break;
				rlen = rv->end - rv->start;
				roff = rv->run_off;
				roff_end = roff + rlen;
				uml_nt_vma_del(c->mm, rb, rb + rlen);
				for (; roff < roff_end;
				     roff += UML_NT_PHYS_RUN_SIZE)
					uml_nt_phys_unref_for(c->ph,
							      (long long)roff,
							      (const void *)0);
				rb += rlen;
			}
			c->plan.n_ops = plan_base;
			c->plan_left = plan_left_base;
			c->plan_next = plan_next_base;
			return SC_RET(SC_ENOMEM);
		}
		os_info("[syscall] mmap 0x%llx+%llu prot=0x%x flags=0x%x "
			"-> off=0x%llx%s\n", va, len, lprot, flags,
			first_sp,
			(flags & SC_MAP_FIXED) ? " FIXED" : "");
		/* [cowtrap] alloc-side arm: the first WRITE into a multi-run
		 * anon span names the poison-writer (report 106). */
		if (first_clen >= 2 * UML_NT_PHYS_RUN_SIZE)
			uml_nt_cowtrap_arm_alloc(c, va, first_clen, first_sp);
	}
	return va;
}

/* ---- M5.4 c2 (D20): file-backed mmap — the dynamic-loader path ----
 *
/* D21 span-cap (archive 066): alloc_pages refuses order >
 * MAX_PAGE_ORDER (10 -> 4MB = 64 runs). Max runs one fresh chunk may
 * span is 64 (4 MiB, order 10); sys_mmap_file always picks the largest
 * power-of-2 run count <= rem_runs (so runs_order never over-allocates
 * tail runs) and steps down (want >>= 1 down to 1 run) if high-order
 * buddy blocks are fragmented. */

/* ld.so maps every shared library through here: ONE span mapping
 * (first segment's prot, no MAP_FIXED — the kernel picks the base),
 * then one MAP_FIXED mapping per remaining segment (4K-aligned,
 * mid-run), then anon MAP_FIXED for the .bss tail. Model (vma.h
 * UML_NT_VMA_FILE note): the run is the backing unit (one view per
 * VMA), CONTENT is byte-ranged — each mapping refills exactly the VA
 * bytes it owns (file bytes, EOF-clamped, zeros beyond; the anon bss
 * mapping zeroes). File VMAs carry the view prot RWX (union-
 * privileged — segments arrive one per PT_LOAD and per-run prot
 * state buys nothing boot-critical). MAP_FIXED over a file VMA
 * REFILLS bytes instead of replacing VMAs (a run cannot be split
 * for view surgery).
 *
 * Every mapping whose prot carries EXEC sweeps its syscalls to ud2
 * at FIRST map (D20 (a) — the mmap twin of binfmt.c's load-time
 * uml_nt_patch_image): an unpatched guest `syscall` would be a REAL
 * host syscall inside the stub. Re-sweeps are idempotent (0F 05 is
 * gone after the first pass).
 *
 * COW scope note: the refill writes physmem directly — correct for
 * the loader (fresh runs, refs == 1, pre-fork). dlopen-after-fork
 * would need the uaccess-style COW surgery first (loud log, later
 * slice). */

/* scan_patch.c (binfmt.c re-declares the same way — no shared header
 * yet); the mark scratch must be >= len bytes. */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off, void *mark);

/* Shared read-only / executable file-run cache (M5.6a):
 * Dynamic libraries (libc, libsystemd-shared, libcrypto, libgcrypt, ...)
 * and read-only data files (LC_COLLATE, hwdb.bin, ld.so.cache) are
 * mapped MAP_PRIVATE by every daemon and generator. For ELF shared
 * libraries, all 64 KiB runs strictly before the first PF_W PT_LOAD
 * segment (.data.rel.ro / .got / .data / .bss) are 100% read-only or
 * executable; for non-ELF PROT_READ mappings at offset 0, all runs are
 * read-only. Caching those read-only prefix runs across processes and
 * mapping them as UML_NT_PAGE_EXECUTE_READ (non-writable) avoids
 * duplicating ~18 MiB of physical runs per process while keeping the
 * writable .data/.bss tail runs private per process. */
#define UML_NT_FCACHE_MAX    64
#define UML_NT_FCACHE_CHUNKS 32
/* M5.6a: bounded-cache policy — the fcache exists to dedup
 * shared-library TEXT. A non-ELF file passes inspect_ro_prefix with
 * ro_runs == its whole span, so journald's grown journal (12.4 MiB
 * mapped PROT_READ, referee 39950787337) would pin ~200 runs behind
 * the reclaim loop's mapped-probe exemption: un-reclaimable while
 * mapped, and its 64-slot entry evicts real libraries. Files over
 * the cap map as plain private copies (freed at unmap/exit). 96
 * runs = 6 MiB covers every boot library (libcrypto.so.3 = 76). */
#define UML_NT_FCACHE_MAX_FILE_RUNS 96

struct uml_nt_fcache_chunk {
	unsigned long long run_off;
	unsigned int nruns;
};

struct uml_nt_fcache_entry {
	int used;
	const void *sb;
	unsigned long ino;
	unsigned long long fsize;
	long long mtime_sec;
	long mtime_nsec;
	unsigned int ro_runs;
	unsigned int nchunks;
	unsigned long long last_use;
	struct uml_nt_fcache_chunk chunks[UML_NT_FCACHE_CHUNKS];
};

static struct uml_nt_fcache_entry g_fcache[UML_NT_FCACHE_MAX];
static struct uml_nt_phys *g_fcache_ph;
static unsigned long long g_fcache_tick;
/* D20 sweep bookkeeping — M5.6a (referee 40197441363): a plain bit is
 * a lie once the content changes underneath it. Runs are SHARED (the
 * read-only file cache) and a later file fill memcpy's pristine bytes
 * over a patched run, restoring the guest's 0f 05 — which is a REAL
 * host syscall, i.e. a silent death with no dispatch and no record.
 * Record the generation the sweep patched instead of a bit, so any
 * re-created content re-arms the patch by construction. */
static unsigned long long fcache_run_swept_gen[UML_NT_PHYS_MAX_RUNS];

static int run_already_swept(struct uml_nt_stub_conn *c,
			     unsigned long long off, int exec_vma)
{
	unsigned int i = (unsigned int)(off / UML_NT_PHYS_RUN_SIZE);
	unsigned long long g;

	if (i >= UML_NT_PHYS_MAX_RUNS)
		return 0;
	g = (unsigned long long)uml_nt_phys_gen(c->ph, (long long)off);
	return !uml_nt_sweep_needed(exec_vma, fcache_run_swept_gen[i], g);
}

static void run_mark_swept(struct uml_nt_stub_conn *c,
			   unsigned long long off, int exec_vma)
{
	unsigned int i = (unsigned int)(off / UML_NT_PHYS_RUN_SIZE);

	if (i >= UML_NT_PHYS_MAX_RUNS)
		return;
	fcache_run_swept_gen[i] = exec_vma ?
		(unsigned long long)uml_nt_phys_gen(c->ph, (long long)off) : 0;
}

/* content was rewritten under the patch: forget, never carry the lie */
static void run_forget_swept(unsigned long long off, unsigned long long len)
{
	unsigned long long ro;

	for (ro = off & ~(unsigned long long)(UML_NT_PHYS_RUN_SIZE - 1);
	     ro < off + len; ro += UML_NT_PHYS_RUN_SIZE) {
		unsigned int i = (unsigned int)(ro / UML_NT_PHYS_RUN_SIZE);

		if (i < UML_NT_PHYS_MAX_RUNS)
			fcache_run_swept_gen[i] = 0;
	}
}

struct uml_nt_elf64_ehdr {
	unsigned char e_ident[16];
	u16 e_type;
	u16 e_machine;
	u32 e_version;
	u64 e_entry;
	u64 e_phoff;
	u64 e_shoff;
	u32 e_flags;
	u16 e_ehsize;
	u16 e_phentsize;
	u16 e_phnum;
	u16 e_shentsize;
	u16 e_shnum;
	u16 e_shstrndx;
};

struct uml_nt_elf64_phdr {
	u32 p_type;
	u32 p_flags;
	u64 p_offset;
	u64 p_vaddr;
	u64 p_paddr;
	u64 p_filesz;
	u64 p_memsz;
	u64 p_align;
};

static unsigned int uml_nt_inspect_ro_prefix(struct file *f,
					     unsigned long long fsize,
					     unsigned long long slen)
{
	static struct uml_nt_elf64_phdr phs[32];
	struct uml_nt_elf64_ehdr eh;
	unsigned int total_runs = (unsigned int)(slen / UML_NT_PHYS_RUN_SIZE);
	unsigned int ro_runs, i;
	unsigned long long min_rw, ro_bytes;
	int seen_load = 0;
	loff_t pos = 0;

	if (f == NULL || fsize == 0 || total_runs == 0)
		return 0;
	if (fsize < sizeof(eh) ||
	    kernel_read(f, &eh, sizeof(eh), &pos) != (ssize_t)sizeof(eh))
		return total_runs;
	if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E' ||
	    eh.e_ident[2] != 'L' || eh.e_ident[3] != 'F')
		return total_runs;
	if (eh.e_ident[4] != 2 ||
	    eh.e_phentsize != sizeof(struct uml_nt_elf64_phdr) ||
	    eh.e_phnum == 0 || eh.e_phnum > 32)
		return 0;
	if (eh.e_phoff + (unsigned long long)eh.e_phnum *
	    sizeof(struct uml_nt_elf64_phdr) > fsize)
		return 0;
	pos = (loff_t)eh.e_phoff;
	if (kernel_read(f, phs,
			(size_t)eh.e_phnum * sizeof(struct uml_nt_elf64_phdr),
			&pos) !=
	    (ssize_t)((size_t)eh.e_phnum * sizeof(struct uml_nt_elf64_phdr)))
		return 0;

	min_rw = slen;
	for (i = 0; i < eh.e_phnum; i++) {
		if (phs[i].p_type != 1)
			continue;
		if (!seen_load) {
			if ((phs[i].p_vaddr & ~(UML_NT_PHYS_RUN_SIZE - 1)) != 0)
				return 0;
			seen_load = 1;
		}
		if ((phs[i].p_flags & 2) && phs[i].p_vaddr < min_rw)
			min_rw = phs[i].p_vaddr;
	}
	if (!seen_load)
		return 0;
	ro_runs = (unsigned int)(min_rw / UML_NT_PHYS_RUN_SIZE);
	if (ro_runs > total_runs)
		ro_runs = total_runs;
	if (ro_runs == 0)
		return 0;
	ro_bytes = (unsigned long long)ro_runs * UML_NT_PHYS_RUN_SIZE;
	for (i = 0; i < eh.e_phnum; i++) {
		if (phs[i].p_type != 1 || phs[i].p_vaddr >= ro_bytes)
			continue;
		if (phs[i].p_flags & 2)
			return 0;
		if (phs[i].p_vaddr != phs[i].p_offset ||
		    phs[i].p_filesz != phs[i].p_memsz)
			return 0;
		if (phs[i].p_flags & 1) {
			unsigned long long ex_end =
				(phs[i].p_vaddr + phs[i].p_filesz +
				 UML_NT_FAULT_PAGE_SIZE - 1) &
				~(UML_NT_FAULT_PAGE_SIZE - 1);

			if (ex_end > ro_bytes)
				return 0;
		}
	}
	return ro_runs;
}

int uml_nt_fcache_reclaim_one(void)
{
	struct uml_nt_phys *ph = g_fcache_ph;
	int best = -1;
	unsigned long long best_use = ~0ULL;
	int i;

	if (ph == NULL)
		return 0;
	for (i = 0; i < UML_NT_FCACHE_MAX; i++) {
		struct uml_nt_fcache_entry *e = &g_fcache[i];
		unsigned int k, r;
		int busy = 0;

		if (!e->used)
			continue;
		for (k = 0; k < e->nchunks && !busy; k++) {
			unsigned long long sp = e->chunks[k].run_off;
			unsigned int nruns = e->chunks[k].nruns;

			for (r = 0; r < nruns; r++) {
				long long roff = (long long)(sp +
					(unsigned long long)r *
					UML_NT_PHYS_RUN_SIZE);

				if (uml_nt_phys_refs(ph, roff) != 1) {
					busy = 1;
					break;
				}
			}
			if (!busy &&
			    uml_nt_phys_mapped_probe !=
			    (uml_nt_phys_mapped_fn)0 &&
			    uml_nt_phys_mapped_probe((long long)sp,
						     (int)nruns) != 0)
				busy = 1;
		}
		if (!busy && e->last_use < best_use) {
			best_use = e->last_use;
			best = i;
		}
	}
	if (best < 0)
		return 0;
	{
		struct uml_nt_fcache_entry *e = &g_fcache[best];
		unsigned int k, r;

		e->used = 0;
		for (k = 0; k < e->nchunks; k++) {
			unsigned long long sp = e->chunks[k].run_off;
			unsigned int nruns = e->chunks[k].nruns;

			for (r = 0; r < nruns; r++) {
				unsigned int r_idx = (unsigned int)
					(sp / UML_NT_PHYS_RUN_SIZE) + r;

				if (r_idx < UML_NT_PHYS_MAX_RUNS)
					fcache_run_swept_gen[r_idx] = 0;
				uml_nt_phys_unref_for(ph,
					(long long)(sp +
					(unsigned long long)r *
					UML_NT_PHYS_RUN_SIZE),
					(const void *)0);
			}
		}
	}
	return 1;
}

void uml_nt_fcache_stats(int *entries, int *runs)
{
	int i, ne = 0, nr = 0;

	for (i = 0; i < UML_NT_FCACHE_MAX; i++) {
		if (!g_fcache[i].used)
			continue;
		ne++;
		nr += (int)g_fcache[i].ro_runs;
	}
	*entries = ne;
	*runs = nr;
}

static struct uml_nt_fcache_entry *uml_nt_fcache_get(
	struct uml_nt_stub_conn *c, struct file *f,
	unsigned long long fsize, unsigned int ro_runs)
{
	struct inode *inode = file_inode(f);
	const void *sb = inode->i_sb;
	unsigned long ino = inode->i_ino;
	long long mtime_sec = inode_get_mtime_sec(inode);
	long mtime_nsec = inode_get_mtime_nsec(inode);
	struct uml_nt_fcache_entry *e = NULL;
	unsigned int rem, k, r;
	unsigned long long foff = 0;
	int i, slot = -1;

	g_fcache_ph = c->ph;
	for (i = 0; i < UML_NT_FCACHE_MAX; i++) {
		if (!g_fcache[i].used) {
			if (slot < 0)
				slot = i;
			continue;
		}
		if (g_fcache[i].sb == sb &&
		    g_fcache[i].ino == ino &&
		    g_fcache[i].fsize == fsize &&
		    g_fcache[i].mtime_sec == mtime_sec &&
		    g_fcache[i].mtime_nsec == mtime_nsec &&
		    g_fcache[i].ro_runs == ro_runs) {
			g_fcache[i].last_use = ++g_fcache_tick;
			return &g_fcache[i];
		}
	}
	if (slot < 0) {
		if (uml_nt_fcache_reclaim_one() > 0) {
			for (i = 0; i < UML_NT_FCACHE_MAX; i++) {
				if (!g_fcache[i].used) {
					slot = i;
					break;
				}
			}
		}
		if (slot < 0)
			return NULL;
	}

	e = &g_fcache[slot];
	e->used = 0;
	e->nchunks = 0;
	rem = ro_runs;
	while (rem > 0) {
		unsigned int want = (rem > UML_NT_MMAP_SPAN_RUNS) ?
				    UML_NT_MMAP_SPAN_RUNS : rem;
		long long sp = -1;
		unsigned long long clen;

		if (e->nchunks >= UML_NT_FCACHE_CHUNKS)
			goto fail_fcache;
		while (want >= 1) {
			sp = uml_nt_phys_alloc_span(c->ph, (int)want);
			if (sp >= 0 || want == 1)
				break;
			{
				unsigned int p2 = 1;

				while ((p2 << 1) < want)
					p2 <<= 1;
				want = p2;
			}
		}
		if (sp < 0)
			goto fail_fcache;
		e->chunks[e->nchunks].run_off = (unsigned long long)sp;
		e->chunks[e->nchunks].nruns = want;
		e->nchunks++;
		for (r = 0; r < want; r++) {
			unsigned int r_idx =
				(unsigned int)((unsigned long long)sp /
					       UML_NT_PHYS_RUN_SIZE) + r;

			if (r_idx < UML_NT_PHYS_MAX_RUNS)
				fcache_run_swept_gen[r_idx] = 0;
		}
		clen = (unsigned long long)want * UML_NT_PHYS_RUN_SIZE;
		memset((char *)uml_boot.physmem_base + sp, 0, clen);
		if (foff < fsize) {
			unsigned long long avail = fsize - foff;
			unsigned long long n = (clen < avail) ? clen : avail;
			loff_t pos = (loff_t)foff;

			if (kernel_read(f, (char *)uml_boot.physmem_base + sp,
					n, &pos) != (ssize_t)n)
				goto fail_fcache;
		}
		foff += clen;
		rem -= want;
	}
	e->sb = sb;
	e->ino = ino;
	e->fsize = fsize;
	e->mtime_sec = mtime_sec;
	e->mtime_nsec = mtime_nsec;
	e->ro_runs = ro_runs;
	e->last_use = ++g_fcache_tick;
	e->used = 1;
	return e;

fail_fcache:
	for (k = 0; k < e->nchunks; k++) {
		unsigned long long sp = e->chunks[k].run_off;
		unsigned int nruns = e->chunks[k].nruns;

		for (r = 0; r < nruns; r++)
			uml_nt_phys_unref_for(c->ph,
				(long long)(sp + (unsigned long long)r *
					    UML_NT_PHYS_RUN_SIZE),
				(const void *)0);
	}
	e->nchunks = 0;
	return NULL;
}

/* File bytes at `off` → [map_start, map_start+len), zeros beyond EOF
 * (everywhere for the anon bss refill). Walks per-VMA pieces — the
 * range may cross VMAs (each segment mapping does); each piece lands
 * at ITS VMA's run offset. */
static int kcopy_budget = 24;

static int uml_nt_mmap_fill(struct uml_nt_stub_conn *c,
			    unsigned long long map_start,
			    unsigned long long len, struct file *f,
			    unsigned long long off,
			    unsigned long long fsize, int zero)
{
	unsigned long long cur = map_start, end = map_start + len;

	while (cur < end) {
		struct uml_nt_vma *v = uml_nt_vma_find(c->mm, cur);
		unsigned long long piece, dst, want, avail, n;
		loff_t pos;

		if (v == NULL || v->end <= cur) {
			os_info("[syscall] mmap fill 0x%llx: unmapped "
				"mid-range\n", cur);
			return -1;
		}
		piece = (end < v->end) ? end : v->end;
		if (!uml_nt_prot_writable(v->prot)) {
			cur = piece;
			continue;
		}
		dst = v->run_off + (cur - v->start);
		/* KCOPY WITNESS (M5.6a, referees 37089977192 +
		 * 37091284391 decode): the [tctrip] negative witness
		 * PROVED the poison writer never faults — it writes
		 * physmem DIRECTLY, bypassing the stub view and every
		 * funnel. This fill IS such a writer: kernel_read/
		 * memset pour file bytes (the "SYSTEMD_" text class =
		 * unit-file/lib bytes) straight into a VMA's run, and
		 * the comment above already flagged post-fork fills as
		 * needing COW surgery "later slice". A fill whose
		 * dest rides an early-heap VA window, or any run still
		 * COW-shared (refs > 1 — the sibling maps these bytes
		 * too), = the stomper named. Log-only: one run names
		 * the site. */
		if (kcopy_budget > 0 && c->mm != NULL &&
		    c->mm->heap_start != 0) {
			unsigned long long drs = dst &
				~(unsigned long long)
				(UML_NT_PHYS_RUN_SIZE - 1);

			if ((cur >= c->mm->heap_start - 0x10000 &&
			     cur < c->mm->heap_start + 0x20000) ||
			    uml_nt_phys_refs(c->ph, (long long)drs) > 1) {
				kcopy_budget--;
				os_info("[kcopy] fill dest va=0x%llx "
					"len=%llu dst_off=0x%llx run="
					"0x%llx refs=%d %s vma="
					"[0x%llx,0x%llx) zero=%d heap="
					"[0x%llx,0x%llx)\n",
					cur, piece - cur, dst, drs,
					uml_nt_phys_refs(c->ph,
							 (long long)drs),
					zero ? "anon" : "file", v->start,
					v->end, zero, c->mm->heap_start,
					c->mm->heap_end);
			}
		}
		/* WRITER-HUNT (M5.6a): a fill piece that would leave
		 * the VMA's allocated span (cross-block / dead run) is
		 * the direct-write heap-trasher caught red-handed —
		 * refuse the write, fail the mapping loud. */
		if (uml_nt_phys_block_check(c->ph, (long long)dst,
					    piece - cur) < 0) {
			os_info("[fillguard] mmap_fill 0x%llx+%llu: dst "
				"off=0x%llx leaves the block (vma "
				"[0x%llx,0x%llx) off=0x%llx) — refused\n",
				cur, piece - cur, dst, v->start, v->end,
				v->run_off);
			return -1;
		}
		/* 098 δ ledger for the fill itself (referee 37121882179
		 * decode): every bulk kernel-direct writer must appear
		 * in the [cowwatch] kernel-write census — the fill was
		 * the last one missing. A fill touching a cowwatch-armed
		 * run (arm-on-fire heap runs included) now names itself;
		 * census silence on a poisoned armed run then EXCLUDES
		 * the fill class too. Log-only.
		 * K6 [flatwr]: capture the (run, gen) at the piece
		 * translate — the memset and the (blocking) file read
		 * below are the writes, the compare after them proves
		 * they landed in the same backing the table still owns. */
		{
			unsigned long long fg = (unsigned long long)
				uml_nt_phys_gen(c->ph, (long long)dst);

			uml_nt_cowwatch_touch(dst, piece - cur,
					      "mmap-fill");
			memset((char *)uml_boot.physmem_base + dst, 0,
			       piece - cur);
			if (!zero && f != NULL) {
				want = off + (cur - map_start);
				avail = (want < fsize) ? fsize - want : 0;
				n = (piece - cur < avail) ? piece - cur
							  : avail;
				if (n > 0) {
					pos = (loff_t)want;
					if (kernel_read(f,
						(char *)uml_boot.physmem_base
							+ dst,
						n, &pos) != (ssize_t)n) {
						os_info("[syscall] mmap fill "
							"0x%llx: short "
							"read\n", cur);
						return -1;
					}
				}
			}
			uml_nt_flatwr_check(c,
				UML_NT_FLATWR_SITE_MMAP_FILL, cur,
				piece - cur, dst, fg, (long long)dst);
			/* D20 re-arm (M5.6a, referee 40197441363): the
			 * bytes we just wrote came from the FILE, not from
			 * a patched run — any earlier sweep of this run is
			 * void. Forget the mark, and if this VMA is code,
			 * patch the piece NOW: an unpatched guest syscall
			 * is a real host syscall and a silent death. */
			run_forget_swept(dst, piece - cur);
			if (uml_nt_prot_execable(v->prot)) {
				unsigned long long ro;
				unsigned long long np;

				np = uml_nt_patch_syscalls(
					(char *)uml_boot.physmem_base + dst,
					piece - cur, 0, NULL);
				for (ro = dst &
					 ~(unsigned long long)
					 (UML_NT_PHYS_RUN_SIZE - 1);
				     ro < dst + (piece - cur);
				     ro += UML_NT_PHYS_RUN_SIZE)
					run_mark_swept(c, ro, 1);
				if (np > 0)
					os_info("[d20-repatch] va=0x%llx "
						"len=%llu run=0x%llx: %llu "
						"syscall(s) re-patched after a "
						"file fill\n", cur,
						piece - cur, dst, np);
			}
		}
		cur = piece;
	}
	return 0;
}

/* D20 (a): sweep the exec-able mapping's syscalls at first map. */
static long long uml_nt_mmap_sweep(struct uml_nt_stub_conn *c,
				   unsigned long long map_start,
				   unsigned long long len)
{
	unsigned long long cur = map_start, end = map_start + len;
	long long total = 0;

	while (cur < end) {
		struct uml_nt_vma *v = uml_nt_vma_find(c->mm, cur);
		unsigned long long piece, off;

		if (v == NULL || v->end <= cur) {
			os_info("[syscall] mmap sweep 0x%llx: unmapped "
				"mid-range\n", cur);
			return -1;
		}
		piece = (end < v->end) ? end : v->end;
		off = v->run_off + (cur - v->start);
		if (!uml_nt_prot_writable(v->prot) &&
		    run_already_swept(c, off, uml_nt_prot_execable(v->prot))) {
			cur = piece;
			continue;
		}
		/* K6 [flatwr]: the sweep PATCHES guest code in place —
		 * zero-alloc in-place decode (no kvmalloc/kvfree). */
		{
			unsigned long long sg = (unsigned long long)
				uml_nt_phys_gen(c->ph, (long long)off);

			total += uml_nt_patch_syscalls(
				(char *)uml_boot.physmem_base + off,
				piece - cur, 0, NULL);
			/* 098 δ: the sweep PATCHES guest code in place —
			 * a cowwatch-armed run touched here is the writer. */
			uml_nt_cowwatch_touch(off, piece - cur,
					      "sweep-patch");
			uml_nt_flatwr_check(c, UML_NT_FLATWR_SITE_MMAP_SWEEP,
					    cur, piece - cur, off, sg,
					    (long long)off);
			if (!uml_nt_prot_writable(v->prot)) {
				unsigned long long ro;

				for (ro = off & ~(UML_NT_PHYS_RUN_SIZE - 1);
				     ro < off + (piece - cur);
				     ro += UML_NT_PHYS_RUN_SIZE)
					run_mark_swept(c, ro,
						       uml_nt_prot_execable(
							       v->prot));
			}
		}
		cur = piece;
	}
	return total;
}

/* ---- D27: lazy (demand-paged) file-backed VMAs --------------------
 *
 * Shelley 2026-10-23 (to-shelley/147): file-backed RO mappings must
 * demand-page like upstream — the run is allocated and the file read
 * at the FIRST fault. The eager fill stays for the exec ELF image
 * (binfmt's execve contract) and for bytes a syscall itself touches
 * (mmap_fill); the sharing cache (b6785e3) is untouched (it serves
 * its eligible mappings exactly as before).
 *
 * Eligibility (registration at mmap): fresh non-FIXED off==0
 * PROT_READ mapping, run-aligned VA, >= 1 MiB, that the eager cache
 * did NOT take. The referee case: udevd's 13 MiB hwdb.bin
 * single-mapper PROT_READ map — a binary-search trie touches a small
 * subset of its 199 runs but the eager copy burns 11% of the 120 MiB
 * budget before login.
 *
 * The region owns a struct file reference (get_file at mmap — the
 * guest may close the fd). A fault inside it materializes ONE run
 * (alloc -> zero -> kernel_read via the synchronous ubd path -> VMA +
 * MAP op) and the guest resumes. munmap/mprotect/refill/fresh-VA
 * overlap are structural: they eagerly materialize the region first
 * (fail-safe fallback; a long-lived database mapping never hits it).
 * fork clones the regions (the child materializes into its own mm);
 * mmctx destroy drops the file references. Budgeted [lazyfile] lines
 * register/demand/drop carry the touched-vs-file-run accounting that
 * quantifies the win. */
static unsigned long long lazy_demand_runs, lazy_eager_runs;
static int lazy_reg_budget = 16, lazy_drop_budget = 24;
static int lazy_demand_budget = 32;
/* live deferred regions + their file/touched run totals (the D28
 * point-1 instrument: the census prints the running ratio). */
static int g_regions;
static unsigned long long g_file_runs, g_touched;

void uml_nt_lazy_stats(int *regions, unsigned long long *file_runs,
		       unsigned long long *touched)
{
	*regions = g_regions;
	*file_runs = g_file_runs;
	*touched = g_touched;
}

static struct uml_nt_lazy_region *lazy_find(struct uml_nt_stub_conn *c,
					    unsigned long long addr)
{
	int i;

	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *r = &c->lazy[i];

		if (r->used && addr >= r->start && addr < r->end)
			return r;
	}
	return NULL;
}

int uml_nt_lazy_overlap(struct uml_nt_stub_conn *c, unsigned long long start,
			unsigned long long end)
{
	int i;

	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *r = &c->lazy[i];

		if (r->used && r->start < end && r->end > start)
			return 1;
	}
	return 0;
}

/* A hint-based VA search that SEES the deferred regions: the VMA
 * tree does not, so a plain find_free would hand the next mapping
 * the region's own VA (the guest would silently lose the file
 * mapping). Step the base past every collision. 0 = none. */
static unsigned long long lazy_find_free(struct uml_nt_stub_conn *c,
					 unsigned long long len,
					 unsigned long long base,
					 unsigned long long limit)
{
	unsigned long long va;
	int i;

	for (i = 0; i < 8; i++) {
		va = uml_nt_vma_find_free(c->mm, len, base, limit);
		if (va == 0)
			return 0;
		if (!uml_nt_lazy_overlap(c, va, va + len))
			return va;
		base = va + len;
	}
	return 0;
}

static int lazy_register(struct uml_nt_stub_conn *c, unsigned long long va,
			 unsigned long long slen, struct file *f,
			 unsigned long long fsize)
{
	struct uml_nt_lazy_region *r = NULL;
	int i;

	if ((va & (UML_NT_PHYS_RUN_SIZE - 1)) != 0)
		return -1;
	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		if (!c->lazy[i].used) {
			r = &c->lazy[i];
			break;
		}
	}
	if (r == NULL)
		return -1;
	get_file(f);
	r->start = va;
	r->end = va + slen;
	r->file_off = 0;
	r->fsize = fsize;
	r->file = f;
	r->used = 1;
	r->touched_runs = 0;
	g_regions++;
	g_file_runs += slen >> UML_NT_PHYS_RUN_SHIFT;
	if (lazy_reg_budget > 0) {
		lazy_reg_budget--;
		os_info("[lazyfile] register pid %lu va=0x%llx len=0x%llx "
			"fsize=%llu runs=%llu\n", (unsigned long)c->pid, va,
			slen, fsize, slen >> UML_NT_PHYS_RUN_SHIFT);
	}
	return 0;
}

/* One run: allocate, zero, read the file, install the VMA (+ MAP op
 * when the caller's stream needs it). 0 = ok/already mapped. */
static int lazy_run(struct uml_nt_stub_conn *c, struct uml_nt_lazy_region *r,
		    unsigned long long run_va, unsigned long long run_end,
		    int add_op)
{
	unsigned long long n, sp;
	loff_t pos;

	if (uml_nt_vma_find(c->mm, run_va) != NULL)
		return 0;
	sp = (unsigned long long)uml_nt_phys_alloc(c->ph);
	if ((long long)sp < 0)
		return -1;
	memset((char *)uml_boot.physmem_base + sp, 0, UML_NT_PHYS_RUN_SIZE);
	n = uml_nt_lazy_read_len(r->start, r->file_off, r->fsize, run_va,
				 run_end - run_va);
	if (n > 0) {
		pos = (loff_t)(r->file_off + (run_va - r->start));
		if (kernel_read(r->file,
				(char *)uml_boot.physmem_base + sp, n,
				&pos) != (ssize_t)n) {
			uml_nt_phys_unref(c->ph, (long long)sp);
			return -1;
		}
	}
	if (uml_nt_vma_add_gen(c->mm, run_va, run_end, sp,
			       UML_NT_PAGE_READONLY, UML_NT_VMA_FILE,
			       (unsigned long long)
			       uml_nt_phys_gen(c->ph, (long long)sp)) < 0) {
		uml_nt_phys_unref(c->ph, (long long)sp);
		return -1;
	}
	if (add_op &&
	    uml_nt_sc_plan_add(c, UML_NT_FOP_MAP, UML_NT_PAGE_READONLY,
			       run_va, run_end - run_va, sp) < 0) {
		uml_nt_vma_del(c->mm, run_va, run_end);
		uml_nt_phys_unref(c->ph, (long long)sp);
		return -1;
	}
	r->touched_runs++;
	lazy_demand_runs++;
	g_touched++;
	return 0;
}

int uml_nt_lazy_fault(struct uml_nt_stub_conn *c, unsigned long long va,
		      unsigned type)
{
	struct uml_nt_lazy_region *r;
	unsigned long long run_va, run_end;

	if (type != UML_NT_FAULT_READ && type != UML_NT_FAULT_EXEC)
		return 0;
	if (uml_nt_vma_find(c->mm, va) != NULL)
		return 0;
	r = lazy_find(c, va);
	if (r == NULL)
		return 0;
	/* Reset the plan exactly as the fault decision would (the tail
	 * arms it via view_release_complete and issues op 0). */
	c->plan.kill = 0;
	c->plan.kill_why = 0;
	c->plan.n_ops = 0;
	c->plan.copy_src_off = 0;
	c->plan.copy_dst_off = 0;
	c->plan.cap_gen_src = 0;
	c->plan.cap_gen_dst = 0;
	c->plan.copy_src_refs = 0;
	c->plan_next = 0;
	c->plan_left = 0;
	if (uml_nt_lazy_run_window(r->start, r->end, va, &run_va,
				   &run_end) < 0 ||
	    lazy_run(c, r, run_va, run_end, 1) < 0) {
		c->plan.kill = 1;
		c->plan.kill_why = 'w';
		c->plan.n_ops = 0;
		return -1;
	}
	if (lazy_demand_budget > 0) {
		lazy_demand_budget--;
		os_info("[lazyfile] demand pid %lu va=0x%llx run=0x%llx "
			"foff=0x%llx len=0x%llx\n",
			(unsigned long)c->pid, va, run_va,
			r->file_off + (run_va - r->start),
			run_end - run_va);
	}
	return 1;
}

int uml_nt_lazy_eager(struct uml_nt_stub_conn *c, unsigned long long start,
		      unsigned long long end)
{
	unsigned long long rv;
	int i, need = 0;

	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *r = &c->lazy[i];

		if (r->used && r->start < end && r->end > start)
			need += (int)((r->end - r->start) >>
				      UML_NT_PHYS_RUN_SHIFT);
	}
	if (need == 0)
		return 0;
	if (uml_nt_sc_plan_reserve(c, need + 1) < 0) {
		os_info("[lazyfile] eager 0x%llx+0x%llx: plan capacity "
			"%d op(s) refused\n", start, end - start, need);
		return -1;
	}
	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *r = &c->lazy[i];

		if (!r->used || r->start >= end || r->end <= start)
			continue;
		for (rv = r->start; rv < r->end;
		     rv += UML_NT_PHYS_RUN_SIZE) {
			unsigned long long re = rv + UML_NT_PHYS_RUN_SIZE;

			if (re > r->end)
				re = r->end;
			if (lazy_run(c, r, rv, re, 1) < 0) {
				os_info("[lazyfile] eager fail pid %lu "
					"va=0x%llx\n",
					(unsigned long)c->pid, rv);
				return -1;
			}
			lazy_eager_runs++;
		}
		if (lazy_drop_budget > 0) {
			lazy_drop_budget--;
			os_info("[lazyfile] drop pid %lu va=0x%llx "
				"file_runs=%llu touched=%llu (eager; "
				"demand_total=%llu eager_total=%llu)\n",
				(unsigned long)c->pid, r->start,
				(r->end - r->start) >>
				UML_NT_PHYS_RUN_SHIFT,
				r->touched_runs, lazy_demand_runs,
				lazy_eager_runs);
		}
		g_regions--;
		g_file_runs -= (r->end - r->start) >>
			       UML_NT_PHYS_RUN_SHIFT;
		g_touched -= r->touched_runs;
		fput(r->file);
		r->used = 0;
	}
	return 0;
}

/* A munmap/MAP_FIXED replace over a deferred region: a FULL cover
 * drops it (upstream unmaps the mapping — no bytes ever needed); a
 * partial cover materializes eagerly and lets the normal VMA path
 * carve it. -1 = refusal. */
static int lazy_unmap(struct uml_nt_stub_conn *c, unsigned long long start,
		      unsigned long long end)
{
	int i, partial = 0;

	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *r = &c->lazy[i];

		if (!r->used || r->start >= end || r->end <= start)
			continue;
		if (start <= r->start && end >= r->end) {
			if (lazy_drop_budget > 0) {
				lazy_drop_budget--;
				os_info("[lazyfile] drop pid %lu va=0x%llx "
					"file_runs=%llu touched=%llu "
					"(unmapped)\n",
					(unsigned long)c->pid, r->start,
					(r->end - r->start) >>
					UML_NT_PHYS_RUN_SHIFT,
					r->touched_runs);
			}
			g_regions--;
			g_file_runs -= (r->end - r->start) >>
				       UML_NT_PHYS_RUN_SHIFT;
			g_touched -= r->touched_runs;
			fput(r->file);
			r->used = 0;
		} else {
			partial = 1;
		}
	}
	if (partial)
		return uml_nt_lazy_eager(c, start, end);
	return 0;
}

int uml_nt_lazy_clone(struct uml_nt_stub_conn *child,
		      struct uml_nt_stub_conn *parent)
{
	int i;

	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *pr = &parent->lazy[i];

		if (!pr->used)
			continue;
		child->lazy[i] = *pr;
		get_file(pr->file);
	}
	return 0;
}

void uml_nt_lazy_drop(struct uml_nt_stub_conn *c)
{
	int i;

	for (i = 0; i < UML_NT_LAZY_MAX; i++) {
		struct uml_nt_lazy_region *r = &c->lazy[i];

		if (!r->used)
			continue;
		if (lazy_drop_budget > 0) {
			lazy_drop_budget--;
			os_info("[lazyfile] drop pid %lu va=0x%llx "
				"file_runs=%llu touched=%llu "
				"demand_total=%llu\n",
				(unsigned long)c->pid, r->start,
				(r->end - r->start) >>
				UML_NT_PHYS_RUN_SHIFT,
				r->touched_runs, lazy_demand_runs);
		}
		g_regions--;
		g_file_runs -= (r->end - r->start) >>
			       UML_NT_PHYS_RUN_SHIFT;
		g_touched -= r->touched_runs;
		fput(r->file);
		r->used = 0;
	}
}

/* The fd is a GUEST fd in the serving task's files_struct (the same
 * table every routed sys_vfs call uses). */
static unsigned long long sys_mmap_file(struct uml_nt_stub_conn *c,
					const unsigned long long *a)
{
	unsigned long long addr = a[0], len = a[1], off = a[5];
	unsigned long long rs, re, fsize, nruns, sp, va, map_start;
	unsigned long long hint_base = UML_NT_SYSCALLS_BASE;
	struct uml_nt_vma *v = NULL;
	u32 lprot = (u32)a[2];
	u32 flags = (u32)a[3];
	/* fd is an int in the mmap ABI (see sys_mmap's note) — the
	 * loader's fd numbers and the -1 sentinel both fit 32 bits. */
	long long fd = (long long)(int)(unsigned)a[4];
	struct fd fdesc;
	struct file *f;
	int kind;

	if (len == 0)
		return SC_RET(SC_EINVAL);
	if (flags & SC_MAP_SHARED) {
		/* M5.5a gate: journald mmaps its seqnum + journal
		 * files MAP_SHARED and exits(1) when the open fails
		 * (run 36872271305: "Failed to open runtime journal:
		 * Function not implemented" -> status=1/FAILURE,
		 * restart loop -> start-limit-hit). The file view is
		 * already RWX with writes landing directly in the
		 * run, so SINGLE-MAPPER shared semantics hold for
		 * free. What this does NOT give: a second mapper of
		 * the same file gets its own eager copy (no page
		 * cache to share through) and nothing is ever
		 * written back at msync/munmap/exit — the file on
		 * disk stays untouched. Acceptable for the boot
		 * gate (journald is the only mapper; its reads go
		 * through the same runs), but this is NOT real
		 * MAP_SHARED — writeback + cross-mapper coherence
		 * are the M5.5b slice. Loud log on every map so the
		 * semantics are visible in the boot log. */
		os_info("[syscall] mmap file: MAP_SHARED as "
			"single-mapper, NO writeback (M5.5b owes the "
			"real semantics)\n");
	}
	if ((addr | off) & (UML_NT_FAULT_PAGE_SIZE - 1)) {
		os_info("[syscall] mmap file 0x%llx+%llu off=0x%llx: not "
			"page-aligned\n", addr, len, off);
		return SC_RET(SC_EINVAL);
	}
	fdesc = fdget_raw((unsigned)fd);
	if (fd_empty(fdesc)) {
		os_info("[syscall] mmap file: fd %lld not open\n", fd);
		return SC_RET(SC_EBADF);
	}
	f = fd_file(fdesc);
	if (!(f->f_mode & FMODE_CAN_READ)) {
		fdput(fdesc);
		os_info("[syscall] mmap file: fd %lld not readable\n", fd);
		return SC_RET(SC_EACCES);
	}
	fsize = i_size_read(file_inode(f));

	/* D27: a structural op over a deferred region materializes it
	 * eagerly first (the VMA tree sees a real mapping from here on;
	 * the registration path never targets a long-lived database
	 * mapping this way). */
	if (addr != 0 && len != 0 &&
	    uml_nt_lazy_overlap(c, addr, addr + len)) {
		if (lazy_unmap(c, addr, addr + len) < 0) {
			fdput(fdesc);
			return SC_RET(SC_ENOMEM);
		}
	}

	rs = addr & ~(UML_NT_PHYS_RUN_SIZE - 1);
	re = (addr + len + UML_NT_PHYS_RUN_SIZE - 1) &
	     ~(UML_NT_PHYS_RUN_SIZE - 1);
	if (addr + len < addr || re < rs) {
		fdput(fdesc);
		return SC_RET(SC_EINVAL);
	}
	kind = uml_nt_vma_map_kind(c->mm, addr, addr + len, &v);
	if (kind != 0 && !(flags & SC_MAP_FIXED)) {
		/* c3: without MAP_FIXED the address is a HINT, not a
		 * location — Linux searches free space from it. Our
		 * run-rounding makes the loader's next hint overlap
		 * the previous mapping's rounded span (its own
		 * bookkeeping rounds to 4K), so a plain hint must
		 * relocate, not fail. */
		kind = 0;
		hint_base = addr;
		v = NULL;
	}
	if (kind < 0) {
		/* FIXED and MIXED: a file refill crossing chunk VMAs
		 * (c3) — every intersecting VMA must be file-backed,
		 * then the fill walk does the rest per-VMA. */
		int nfile = 0;

		if (!uml_nt_mmap_refill_ok(c->mm, addr, addr + len,
					   &nfile)) {
			fdput(fdesc);
			os_info("[syscall] mmap file 0x%llx+%llu: flank "
				"overlap — unsupported\n", addr, len);
			return SC_RET(SC_ENOMEM);
		}
		uml_nt_guard_del_range(c->mm, addr, addr + len);
		if (uml_nt_mmap_fill(c, addr, len, f, off, fsize, 0) < 0) {
			fdput(fdesc);
			return SC_RET(SC_EFAULT);
		}
		if (lprot & SC_PROT_EXEC) {
			long long p = uml_nt_mmap_sweep(c, addr, len);

			if (p < 0) {
				fdput(fdesc);
				return SC_RET(SC_EFAULT);
			}
			os_info("[syscall] mmap exec sweep 0x%llx+%llu: "
				"%lld syscall(s) patched (D20)\n", addr,
				len, p);
		}
		fdput(fdesc);
		os_info("[syscall] mmap file 0x%llx+%llu prot=0x%x -> "
			"refill 0x%llx off=0x%llx (size %llu, %d "
			"chunk(s))%s\n", addr, len, lprot, addr, off,
			fsize, nfile,
			(lprot & SC_PROT_EXEC) ? " EXEC" : "");
		return addr;
	}

	{
		unsigned long long slen = re - rs;
		unsigned long long cur = 0, clen = 0;
		unsigned long long err_ret = SC_RET(SC_ENOMEM);
		int plan_base = c->plan.n_ops;
		int plan_left_base = c->plan_left;
		int plan_next_base = c->plan_next;
		int have_fdesc = 1;

		if (kind == 0) {
			/* Fresh span. MAP_FIXED keeps the requested start (the
			 * VMA is run-rounded around it — the [rs, addr) head
			 * is a zero hole, run granularity); otherwise the
			 * mapping IS the VMA base (the file offset belongs to
			 * it). File VMAs map the view RWX (vma.h note).
			 *
			 * c3: a span is alloc_pages(order = RUN_ORDER +
			 * runs_order(nruns)) — order 10 (64 runs, 4MB) is the
			 * buddy's ceiling, so a bigger mapping (systemd's
			 * libcrypto.so.3 is 4.7MB) is split into chunk VMAs,
			 * each with its own span + view. fill/sweep and the
			 * refill walk per-VMA pieces already; nothing else
			 * knows the chunks exist. */
			if (flags & SC_MAP_FIXED) {
				va = rs;
				map_start = addr;
			} else {
				/* D28: a region-aware search — the VMA
				 * tree cannot see a deferred region. */
				va = lazy_find_free(c, slen, hint_base,
						    UML_NT_SYSCALLS_BASE +
						    uml_boot.physmem_size);
				if (va == 0) {
					fdput(fdesc);
					return SC_RET(SC_ENOMEM);
				}
				map_start = va;
			}
			cur = va;
			if (!(flags & (SC_MAP_SHARED | SC_MAP_FIXED)) &&
			    off == 0 && lprot == SC_PROT_READ) {
				unsigned int ro_runs =
					uml_nt_inspect_ro_prefix(f, fsize,
								 slen);
				struct uml_nt_fcache_entry *fce = NULL;

				if (ro_runs > UML_NT_FCACHE_MAX_FILE_RUNS) {
					os_info("[syscall] mmap file: %u ro "
						"runs > fcache cap — private "
						"copy (size %llu)\n",
						ro_runs, fsize);
					ro_runs = 0;
				}

				if (ro_runs > 0)
					fce = uml_nt_fcache_get(c, f, fsize,
								ro_runs);
				if (fce != NULL) {
					unsigned int ci;

					for (ci = 0; ci < fce->nchunks; ci++) {
						unsigned long long sp_c =
							fce->chunks[ci].run_off;
						unsigned long long clen_c =
							(unsigned long long)
							fce->chunks[ci].nruns *
							UML_NT_PHYS_RUN_SIZE;
						unsigned long long roff;

						if (uml_nt_sc_plan_reserve(c, 1) < 0)
							goto rollback_chunks;
						for (roff = sp_c;
						     roff < sp_c + clen_c;
						     roff += UML_NT_PHYS_RUN_SIZE) {
							if (uml_nt_phys_ref(c->ph,
								(long long)roff) < 0) {
								unsigned long long r2;

								for (r2 = sp_c;
								     r2 < roff;
								     r2 += UML_NT_PHYS_RUN_SIZE)
									uml_nt_phys_unref_for(
										c->ph,
										(long long)r2,
										(const void *)0);
								goto rollback_chunks;
							}
						}
						if (uml_nt_vma_add_gen(
							c->mm, cur,
							cur + clen_c, sp_c,
							UML_NT_PAGE_EXECUTE_READ,
							UML_NT_VMA_FILE,
							(unsigned long long)
							uml_nt_phys_gen(
								c->ph,
								(long long)sp_c)) < 0) {
							for (roff = sp_c;
							     roff < sp_c + clen_c;
							     roff += UML_NT_PHYS_RUN_SIZE)
								uml_nt_phys_unref_for(
									c->ph,
									(long long)roff,
									(const void *)0);
							goto rollback_chunks;
						}
						uml_nt_sc_plan_add(
							c, UML_NT_FOP_MAP,
							UML_NT_PAGE_EXECUTE_READ,
							cur, clen_c, sp_c);
						cur += clen_c;
					}
				}
			}
			/* D27: no eager bytes yet (the sharing cache did not
			 * take this mapping) and the guest asked for a
			 * read-only file view — DEFER it. Runs + file bytes
			 * are materialized at the first fault (the 13 MiB
			 * hwdb.bin case). Writable mappings stay eager (the
			 * single-mapper emulation lets writes land in the
			 * run; a lazy RO view would turn them into faults). */
			if (cur == va && !(flags & SC_MAP_FIXED) && off == 0 &&
			    lprot == SC_PROT_READ && len >= (1ull << 20) &&
			    fsize != 0 &&
			    lazy_register(c, va, slen, f, fsize) == 0) {
				fdput(fdesc);
				have_fdesc = 0;
				os_info("[syscall] mmap file 0x%llx+%llu: "
					"deferred (lazy runs, %llu byte(s))\n",
					va, len, fsize);
				return va;
			}

			/* Chunk allocation with buddy-order fallback and full
			 * rollback on mid-loop failure:
			 * 1. Try min(rem_runs, UML_NT_MMAP_SPAN_RUNS) first so a
			 *    normal shared library <= 4 MiB maps as a SINGLE VMA
			 *    (preserving the 128-slot UML_NT_VMA_MAX table).
			 * 2. If that order is fragmented in the buddy allocator,
			 *    step down to the largest power-of-2 run count strictly
			 *    below want ( down to 1 run = 64 KiB, order 4).
			 * 3. If any chunk fails (span alloc, plan reserve, or
			 *    VMA table), unref all runs of every chunk added in
			 *    [va, cur) and roll back VMAs + plan ops. */
			for (; cur < va + slen; cur += clen) {
				unsigned long long rem_runs =
					(va + slen - cur) / UML_NT_PHYS_RUN_SIZE;
				unsigned int want =
					(rem_runs > UML_NT_MMAP_SPAN_RUNS) ?
					UML_NT_MMAP_SPAN_RUNS :
					(unsigned int)rem_runs;

				sp = (unsigned long long)-1LL;
				while (want >= 1) {
					sp = (unsigned long long)
						uml_nt_phys_alloc_span(c->ph,
								       (int)want);
					if ((long long)sp >= 0)
						break;
					if (want == 1)
						break;
					{
						unsigned int p2 = 1;

						while ((p2 << 1) < want)
							p2 <<= 1;
						want = p2;
					}
				}
				if ((long long)sp < 0) {
					os_info("[syscall] mmap file 0x%llx+%llu: "
						"span of %llu run(s) at 0x%llx failed "
						"— ENOMEM\n", addr, len, rem_runs, cur);
					goto rollback_chunks;
				}
				nruns = want;
				clen = (unsigned long long)nruns *
				       UML_NT_PHYS_RUN_SIZE;
				if (uml_nt_sc_plan_reserve(c, 1) < 0) {
					unsigned long long roff;

					os_info("[syscall] mmap file 0x%llx+%llu: "
						"view-swap plan full at 0x%llx "
						"— ENOMEM\n", addr, len, cur);
					for (roff = sp; roff < sp + clen;
					     roff += UML_NT_PHYS_RUN_SIZE)
						uml_nt_phys_unref_for(c->ph,
								      (long long)roff,
								      (const void *)0);
					goto rollback_chunks;
				}
				if (uml_nt_vma_add_gen(c->mm, cur, cur + clen, sp,
						       UML_NT_PAGE_EXECUTE_READWRITE,
						       UML_NT_VMA_FILE,
						       (unsigned long long)
						       uml_nt_phys_gen(
							       c->ph,
							       (long long)sp)) < 0) {
					unsigned long long roff;

					os_info("[syscall] mmap file 0x%llx+%llu: "
						"vma table full at 0x%llx (nvma=%d) "
						"— ENOMEM\n", addr, len, cur,
						c->mm->nvma);
					for (roff = sp; roff < sp + clen;
					     roff += UML_NT_PHYS_RUN_SIZE)
						uml_nt_phys_unref_for(c->ph,
								      (long long)roff,
								      (const void *)0);
					goto rollback_chunks;
				}
				uml_nt_sc_plan_add(c, UML_NT_FOP_MAP,
						   UML_NT_PAGE_EXECUTE_READWRITE,
						   cur, clen, sp);
			}
		} else {
			va = addr;
			map_start = addr;
		}

		if (uml_nt_mmap_fill(c, map_start, len, f, off, fsize, 0) < 0) {
			err_ret = SC_RET(SC_EFAULT);
			if (kind == 0)
				goto rollback_chunks;
			fdput(fdesc);
			return err_ret;
		}
		fdput(fdesc);
		have_fdesc = 0;

		if (lprot & SC_PROT_EXEC) {
			long long p = uml_nt_mmap_sweep(c, map_start, len);

			if (p < 0) {
				err_ret = SC_RET(SC_EFAULT);
				if (kind == 0)
					goto rollback_chunks;
				return err_ret;
			}
			os_info("[syscall] mmap exec sweep 0x%llx+%llu: %lld "
				"syscall(s) patched (D20)\n", map_start, len, p);
		}
		if (0) {
			unsigned long long rb;
rollback_chunks:
			for (rb = va; rb < cur; ) {
				const struct uml_nt_vma *rv =
					uml_nt_vma_find(c->mm, rb);
				unsigned long long rlen, roff, roff_end;

				if (rv == NULL || rv->start != rb)
					break;
				rlen = rv->end - rv->start;
				roff = rv->run_off;
				roff_end = roff + rlen;
				uml_nt_vma_del(c->mm, rb, rb + rlen);
				for (; roff < roff_end;
				     roff += UML_NT_PHYS_RUN_SIZE)
					uml_nt_phys_unref_for(c->ph,
							      (long long)roff,
							      (const void *)0);
				rb += rlen;
			}
			c->plan.n_ops = plan_base;
			c->plan_left = plan_left_base;
			c->plan_next = plan_next_base;
			if (have_fdesc)
				fdput(fdesc);
			return err_ret;
		}
	}
	os_info("[syscall] mmap file 0x%llx+%llu prot=0x%x -> %s 0x%llx "
		"off=0x%llx (size %llu)%s\n", map_start, len, lprot,
		(kind == 0) ? "fresh" : "refill", va, off, fsize,
		(lprot & SC_PROT_EXEC) ? " EXEC" : "");
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
	/* M5.6a root-cause fix: the COMPLETE view-release set, one
	 * UNMAP op per removed whole VMA. Kernel-side serving is
	 * serialized (the pump owns it), so one shared static buffer
	 * serves every conn (the tce/claim_audit pattern) — the
	 * 16K-stack discipline forbids a second 10KB frame here. */
	static struct uml_nt_fault_op mun_views[UML_NT_VMA_MAX];
	static unsigned long long runs[UML_NT_PHYS_MAX_RUNS]; /* section offsets */
	unsigned long long addr = a[0], len = a[1];
	struct uml_nt_mm *mm = c->mm;
	int i, nruns, nviews;

	if (addr & (UML_NT_PHYS_RUN_SIZE - 1) || len == 0)
		return SC_RET(SC_EINVAL);
	len = (len + UML_NT_PHYS_RUN_SIZE - 1) &
	      ~(UML_NT_PHYS_RUN_SIZE - 1);
	/* D28: unmap of a deferred region — a full cover drops it (no
	 * bytes ever needed); a partial cover materializes it so the
	 * VMA enumeration below owns every byte it must release. */
	if (uml_nt_lazy_overlap(c, addr, addr + len)) {
		if (lazy_unmap(c, addr, addr + len) < 0)
			return SC_RET(SC_ENOMEM);
	}
	/* Partial-VMA refusal + the view enumeration in one pass:
	 * UnmapViewOfFile releases the WHOLE view at map_va, so the
	 * release op set is exactly one op per removed VMA (whole
	 * views only). The old code queued ONE op for the whole
	 * range: it released only the view containing `addr` and
	 * STRANDED every later VMA's view over runs the table had
	 * just dropped and recycled — the silent table-vs-view
	 * split-brain (guest stores through a stranded view land in
	 * a backing the table no longer owns, and the recycled runs
	 * are other mms' memory: the run-granular lost-update, dl18
	 * 37512134759's formation class). */
	nviews = uml_nt_fault_munmap_views(mm, addr, addr + len,
					   mun_views, UML_NT_VMA_MAX);
	if (nviews == -2) {
		for (i = 0; i < mm->nvma; i++) {
			unsigned long long s = mm->vma[i].start;
			unsigned long long e = mm->vma[i].end;

			if (s < addr + len && e > addr &&
			    (s < addr || e > addr + len)) {
				os_info("[syscall] munmap 0x%llx+%llu: "
					"partial VMA [0x%llx, 0x%llx) — "
					"unsupported (whole views "
					"only)\n", addr, len, s, e);
				break;
			}
		}
		return SC_RET(SC_EINVAL);
	}
	if (nviews < 0) {
		os_info("[syscall] munmap 0x%llx+%llu: view set overflow\n",
			addr, len);
		return SC_RET(SC_ENOMEM);
	}
	/* The unref set: each selected VMA contributes ITS OWN backing
	 * span, deduped per physical run (review M3.8: looping
	 * len/RUN from every VMA's run_off unrefs unrelated backing —
	 * underflows refcounts → premature frees). */
	nruns = uml_nt_vma_span_runs(mm, addr, addr + len, runs,
				     UML_NT_PHYS_MAX_RUNS);
	if (nruns < 0) {
		os_info("[syscall] munmap 0x%llx+%llu: unref set overflow\n",
			addr, len);
		return SC_RET(SC_ENOMEM);
	}
	if (nruns == 0)
		return 0; /* unmapped range: Linux succeeds */
	/* All-or-nothing: reserve the view ops BEFORE the table moves.
	 * A full plan refuses the munmap (loud) instead of dropping
	 * an op — a dropped op is the stranded-view class above. */
	if (uml_nt_sc_plan_reserve(c, nviews) < 0) {
		os_info("[syscall] munmap 0x%llx+%llu: view-swap plan "
			"full (%d op(s) needed) — ENOMEM\n", addr, len,
			nviews);
		return SC_RET(SC_ENOMEM);
	}
	if (uml_nt_vma_del(mm, addr, addr + len) < 0)
		return SC_RET(SC_ENOMEM);
	for (i = 0; i < nruns; i++)
		uml_nt_phys_unref_for(c->ph, (long long)runs[i], c);
	uml_nt_guard_del_range(mm, addr, addr + len); /* guards die too */
	for (i = 0; i < nviews; i++)
		if (uml_nt_sc_plan_add(c, UML_NT_FOP_UNMAP, 0,
				       mun_views[i].va,
				       mun_views[i].len, 0) < 0) {
			/* Cannot happen (reserved above) — never
			 * silent: the invariant is the fix's core. */
			os_info("[viewswap] munmap op dropped "
				"post-reserve — INVARIANT BROKEN "
				"(pid %lu)\n", (unsigned long)c->pid);
			break;
		}
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
	unsigned long long cur, end;
	unsigned prot = linux_prot_to_nt((u32)a[2]);
	struct uml_nt_vma *v;
	int nops = 0;

	if ((addr | len) & (UML_NT_FAULT_PAGE_SIZE - 1) || len == 0 ||
	    addr + len < addr)
		return SC_RET(SC_EINVAL);
	/* D27: mprotect over a deferred region materializes it (the
	 * walk below needs VMAs; a deferred region is invisible). */
	if (uml_nt_lazy_overlap(c, addr, addr + len)) {
		if (uml_nt_lazy_eager(c, addr, addr + len) < 0)
			return SC_RET(SC_ENOMEM);
	}
	end = addr + len;
	for (cur = addr; cur < end; ) {
		v = uml_nt_vma_find(c->mm, cur);
		if (v == NULL || v->end <= cur) {
			os_info("[syscall] mprotect 0x%llx+%llu: not inside "
				"mapped VMAs (hole at 0x%llx)\n",
				addr, len, cur);
			return SC_RET(SC_ENOMEM);
		}
		if ((v->flags & UML_NT_VMA_COW) &&
		    !(v->flags & UML_NT_VMA_FILE)) {
			os_info("[syscall] mprotect on COW VMA — unsupported "
				"(M4)\n");
			return SC_RET(SC_ENOSYS);
		}
		if (!(v->flags & UML_NT_VMA_FILE))
			nops++;
		cur = (end < v->end) ? end : v->end;
	}
	if (nops == 0) {
		/* File VMAs keep the union-privileged RWX view (vma.h
		 * note): a restriction (glibc's RELRO mprotect, which
		 * may span multiple chunk VMAs when a large library is
		 * split across buddy blocks) would brick later refills
		 * and fault repairs for no boot benefit — ack the call,
		 * change nothing. Guards under the range still die (the
		 * change wins). */
		int killed = uml_nt_guard_del_range(c->mm, addr, end);

		os_info("[syscall] mprotect 0x%llx+%llu -> 0x%x (file "
			"VMA — view stays RWX, %d guard(s) cleared)\n",
			addr, len, prot, killed);
		return 0;
	}
	/* M5.6a root-cause fix: the view PROTECT ops are reserved BEFORE
	 * the guard state / VMA prot moves — a dropped op here leaves the
	 * fault truth (the guard table / VMA prot) and the stub's view
	 * silently diverged (e.g. a NOACCESS guard the guest writes
	 * straight through). Refusal is loud, Linux-shaped. */
	if (uml_nt_sc_plan_reserve(c, nops) < 0) {
		os_info("[syscall] mprotect 0x%llx+%llu: view-swap plan "
			"full — ENOMEM\n", addr, len);
		return SC_RET(SC_ENOMEM);
	}
	for (cur = addr; cur < end; ) {
		unsigned long long piece, plen;
		int killed;

		v = uml_nt_vma_find(c->mm, cur);
		if (v == NULL || v->end <= cur)
			return SC_RET(SC_ENOMEM);
		piece = (end < v->end) ? end : v->end;
		plen = piece - cur;
		killed = uml_nt_guard_del_range(c->mm, cur, piece);
		if (v->flags & UML_NT_VMA_FILE) {
			cur = piece;
			continue;
		}
		if (cur == v->start && piece == v->end) {
			if (uml_nt_vma_chg(c->mm, cur, piece, prot) < 0)
				return SC_RET(SC_ENOMEM);
			/* An mprotect that makes a range exec-able for the
			 * FIRST time sweeps it too (D20 (a) — an unpatched
			 * guest syscall would be a real host syscall). Anon
			 * pages sweep to zero patches; file VMAs already
			 * swept at map (returned above). */
			if ((a[2] & SC_PROT_EXEC) &&
			    uml_nt_mmap_sweep(c, cur, plen) < 0)
				return SC_RET(SC_EFAULT);
			os_info("[syscall] mprotect 0x%llx+%llu -> 0x%x "
				"(whole VMA, was lprot 0x%llx, %d guard(s) "
				"cleared)\n", cur, plen, prot, a[2], killed);
		} else {
			if (prot == UML_NT_PAGE_NOACCESS) {
				if (uml_nt_guard_add(c->mm, cur, piece) < 0)
					return SC_RET(SC_ENOMEM);
			} else if ((a[2] & SC_PROT_EXEC) &&
				   uml_nt_mmap_sweep(c, cur, plen) < 0) {
				return SC_RET(SC_EFAULT);
			}
			os_info("[syscall] mprotect 0x%llx+%llu -> 0x%x "
				"(sub-run, was lprot 0x%llx, %d guard(s) %s)\n",
				cur, plen, prot, a[2], killed,
				(prot == UML_NT_PAGE_NOACCESS) ? "armed" :
				"cleared");
		}
		uml_nt_sc_plan_add(c, UML_NT_FOP_PROTECT, prot, cur,
				   plen, 0);
		cur = piece;
	}
	return 0;
}

/* clock_gettime(2): ns-since-boot (os_nsecs, QPC) split into the
 * timespec the guest asked for. CLOCK_MONOTONIC (1), CLOCK_REALTIME
 * (0) and CLOCK_BOOTTIME (7) all map to it — the kernel owns no
 * wall-clock offset (the sysbench gate times a monotonic window) and
 * this guest never suspends, so boottime == monotonic. */
static unsigned long long sys_clock_gettime(struct uml_nt_stub_conn *c,
					    const unsigned long long *a)
{
	long long nsecs;
	unsigned long long buf[2];

	if (a[0] != 0 /* CLOCK_REALTIME */ &&
	    a[0] != 1 /* CLOCK_MONOTONIC */ &&
	    a[0] != 7 /* CLOCK_BOOTTIME — == monotonic here: this guest
		       * never suspends. systemd's now() asserts
		       * clock_gettime == 0 (src/basic/time-util.c:54);
		       * the EINVAL aborted PID 1 into the coredump-fork
		       * spiral (run 36782313512). */)
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
	/* map 053 item 1, task-backed path (the POC hook's diag never
	 * fires for systemd): the parent's live regs at the fork
	 * round. Snapshot AFTER the sync — current_pt_regs is one
	 * round STALE before conn_pull_regs lands the trap state
	 * (M4.2), so a pre-sync snapshot compares stale vs live and
	 * false-positives every round. If the parent ever carries
	 * _Fork+0x23's cluster in a callee-saved reg here, the
	 * save/restore path is the vector; if the values CHANGE
	 * across the round, the round smeared them. */
	struct uml_pt_regs *pr = &current_pt_regs()->regs;
	unsigned long long rbx, rbp, r12, r13, r14, r15;

	uml_nt_sync_trap_regs(&current_pt_regs()->regs, d);
	rbx = REGS_BX(pr->gp);
	rbp = REGS_BP(pr->gp);
	r12 = REGS_R12(pr->gp);
	r13 = REGS_R13(pr->gp);
	r14 = REGS_R14(pr->gp);
	r15 = REGS_R15(pr->gp);
	os_info("[syscall] fork round nr=%llu: parent rip=0x%llx "
		"rbx=0x%llx rbp=0x%llx r12=0x%llx r13=0x%llx r14=0x%llx "
		"r15=0x%llx\n", nr, REGS_IP(pr->gp), rbx, rbp, r12, r13,
		r14, r15);
	uml_nt_fork_arm(c, d->regs.rsp);
	ret = sys_vfs(nr, a); /* generic fork/clone → copy_process */
	uml_nt_fork_disarm();
	if (REGS_BX(pr->gp) != rbx || REGS_BP(pr->gp) != rbp ||
	    REGS_R12(pr->gp) != r12 || REGS_R13(pr->gp) != r13 ||
	    REGS_R14(pr->gp) != r14 || REGS_R15(pr->gp) != r15)
		os_info("[syscall] fork round SMEARED parent regs: "
			"rbx 0x%llx->0x%llx rbp 0x%llx->0x%llx "
			"r12 0x%llx->0x%llx r13 0x%llx->0x%llx "
			"r14 0x%llx->0x%llx r15 0x%llx->0x%llx\n",
			rbx, REGS_BX(pr->gp), rbp, REGS_BP(pr->gp),
			r12, REGS_R12(pr->gp), r13, REGS_R13(pr->gp),
			r14, REGS_R14(pr->gp), r15, REGS_R15(pr->gp));
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
static int ioctl_once; /* M5.1c.3 diag: the ioctl-done breadcrumb, once */

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
	/* M5.6a [pivot trace]: the conn this exec birth creates adopts
	 * this name (mmctx_init → uml_nt_fork_seed) — the TF trace arms
	 * for the login class only, and every pivot line names the
	 * binary. */
	uml_nt_exec_path_set(path);

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

/* prctl(2) — M5.4 c3 (systemd): the process-option cluster. Per-conn
 * state only (this conn IS the guest process): PR_SET_NAME stores
 * the 16-byte comm (guest string via the D15 walker — shows up in
 * "Comm:" panics), PDEATHSIG/DUMPABLE/NO_NEW_PRIVS are recorded and
 * ack'd. Unknown options = -EINVAL (systemd tolerates; a blanket 0
 * would lie about Getmm). */
#define UML_NT_PR_SET_PDEATHSIG  1
#define UML_NT_PR_GET_PDEATHSIG  2
#define UML_NT_PR_SET_DUMPABLE   4
#define UML_NT_PR_GET_DUMPABLE   5
#define UML_NT_PR_SET_NAME       15
#define UML_NT_PR_GET_NAME       16
#define UML_NT_PR_SET_NO_NEW_PRIVS 38

static unsigned long long sys_prctl(struct uml_nt_stub_conn *c,
				    const unsigned long long *a)
{
	char name[16];
	int i;

	switch (a[0]) {
	case UML_NT_PR_SET_NAME:
		if (uml_nt_uacc_strncpy(name, c->mm, uml_boot.physmem_base,
					a[1], sizeof(name) - 1) < 0)
			return SC_RET(SC_EFAULT);
		name[sizeof(name) - 1] = 0;
		for (i = 0; i < (int)sizeof(c->comm) && name[i]; i++)
			c->comm[i] = name[i];
		c->comm[i] = 0;
		return 0;
	case UML_NT_PR_GET_NAME:
		if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a[1],
				     sizeof(c->comm), c->comm,
				     UML_NT_UACC_TO_GUEST) < 0)
			return SC_RET(SC_EFAULT);
		return 0;
	case UML_NT_PR_SET_PDEATHSIG:
		c->pdeathsig = (u32)a[1];
		return 0;
	case UML_NT_PR_GET_PDEATHSIG:
		if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a[1],
				     sizeof(c->pdeathsig),
				     (char *)&c->pdeathsig,
				     UML_NT_UACC_TO_GUEST) < 0)
			return SC_RET(SC_EFAULT);
		return 0;
	case UML_NT_PR_SET_DUMPABLE:
		c->dumpable = (a[1] == 1);
		return 0;
	case UML_NT_PR_GET_DUMPABLE:
		return c->dumpable ? 1 : 0;
	case UML_NT_PR_SET_NO_NEW_PRIVS:
		c->no_new_privs = (a[1] != 0);
		return 0;
	default:
		os_info("[syscall] prctl(cmd=%llu): unsupported — "
			"EINVAL\n", a[0]);
		return SC_RET(SC_EINVAL);
	}
}

/* ---- M5.4 c3: the malloc-assertion predicate capture ----
 *
 * Astra decode (archive astra-m55a-oneshot-blocked-d21.md §2) pinned
 * the PID1 ABRT family on a glibc malloc assertion: __libc_message()
 * formats "Fatal glibc error: malloc assertion failure in %s: %s\n"
 * (the malloc function + the failed predicate), writev()s it to fd 2,
 * mmaps an anonymous copy of the message (__abort_msg — the final
 * PID1 mmap at 0x605c0000 in run 36891891282) and only then
 * abort() -> raise() reaches the tgkill trap the [abrt] tripwire
 * already watches. Neither the iovecs nor the message text was ever
 * captured (the console shows no such line — SYSTEMD_LOG_TARGET does
 * not control libc's direct fd-2 output). Per the approved request:
 * capture the fd-2 iovecs at the writev, or the __abort_msg string
 * at the tgkill — either yields the real {function, predicate} pair
 * so the corrupting-writer hunt starts from data. NO speculative
 * fix (zeroing stack/env/SIMD is explicitly out until this lands). */

/* Bounded guest-string read (walker FROM_GUEST — read-only, no sink
 * needed, no COW surgery). NUL-terminates within cap; returns the
 * string length, -1 when the bytes are unmappable. */
static int abrt_read_str(struct uml_nt_stub_conn *c, unsigned long long va,
			 char *out, int cap)
{
	if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, va, cap, out,
			     UML_NT_UACC_FROM_GUEST) < 0)
		return -1;
	out[cap - 1] = 0;
	return (int)strnlen(out, cap);
}

/* os_info caps one line at 256 bytes (the R9 lesson: buf 256, cut
 * ~249) — chunk the message at 110. */
static void abrt_dump_text(const char *s, int len)
{
	int pos = 0, part = 0;

	while (pos < len && part < 5) {
		char chunk[112];
		int n = len - pos;

		if (n > (int)sizeof(chunk) - 1)
			n = (int)sizeof(chunk) - 1;
		memcpy(chunk, s + pos, n);
		chunk[n] = 0;
		os_info("[abrt] msg[%d]: \"%s\"\n", part, chunk);
		pos += n;
		part++;
	}
}

/* Record one successful mmap result (the dispatch tail calls this
 * for nr 9) — the tgkill-side capture's candidate ring. */
static void abrt_mmap_note(struct uml_nt_stub_conn *c,
			   unsigned long long ret)
{
	c->mmap_recent[c->mmap_recent_head] = ret;
	c->mmap_recent_head = (c->mmap_recent_head + 1) % 4;
	if (c->mmap_recent_n < 4)
		c->mmap_recent_n++;
}

/* The glibc fatal-message family (run 36898314217 decoded the OTHER
 * kind: malloc_printerr's plain strings — "malloc(): smallbin double
 * linked list corrupted" — carry the predicate in the message itself,
 * no %s args, and do NOT start with "Fatal glibc error"). */
static const char *const abrt_pfx[] = {
	"Fatal glibc ", "malloc():", "free():", "realloc():",
	"memalign():",
	/* glibc 2.36 malloc_printerr strings WITHOUT a function prefix
	 * (verified in the image's libc.so.6: 0x19805d = "corrupted
	 * double-linked list") — run 36919012169's task-1 abort fired
	 * through the writev (iov {libc+0x19805d, 28} in the raise
	 * dump) while the table missed it silently. */
	"corrupted", "invalid", "munmap", "unknown",
};

static int abrt_text_match(const char *s, int n)
{
	int p;

	for (p = 0; p < (int)ARRAY_SIZE(abrt_pfx); p++) {
		size_t len = strlen(abrt_pfx[p]);

		if (n >= (int)len && strncmp(s, abrt_pfx[p], len) == 0)
			return 1;
	}
	return 0;
}

/* The tgkill-half capture (primary per Astra §2). Two routes:
 *
 * 1. DIRECT — the raise frame carries the __abort_msg pointer at
 *    rsp+0x20 (0x605c0000 in BOTH the PID1 decode and every child
 *    dump): peek the message text there. Printable-ASCII gated.
 * 2. RING — this conn's recent successful mmap results, prefix-
 *    matched against the fatal-message family.
 *
 * Run 36898314217 (children aborting "malloc(): smallbin double
 * linked list corrupted") proved the prefix must cover the
 * malloc_printerr family too — the first capture stayed silent on
 * exactly those aborts. */
static void abrt_msg_capture(struct uml_nt_stub_conn *c,
			     unsigned long long msg_va)
{
	static int ncaptured, nmiss;
	char s[448];
	int k;

	if (ncaptured >= 3)
		return;
	if (msg_va) {
		int got = abrt_read_str(c, msg_va, s, sizeof(s));
		int i, printable = got > 8;

		for (i = 0; printable && i < 8; i++)
			if ((s[i] < 0x20 || s[i] > 0x7e) && s[i] != '\n')
				printable = 0;
		if (printable) {
			ncaptured++;
			os_info("[abrt] message @0x%llx (frame rsp+0x20, "
				"task %d)\n", msg_va,
				current ? current->pid : 0);
			abrt_dump_text(s, got);
			return;
		}
		/* The peek verdict (hex, first 32 bytes): the
		 * __abort_msg copy is a WRITE INTO A FRESH ANON RUN —
		 * a zero/garbage read-back here would make the
		 * abort_msg path a live witness of the same
		 * fresh-mapping consistency class the heap corruption
		 * suspects (run 36905053855: the peek failed with the
		 * ring holding the mapping — say WHY). */
		if (nmiss < 1) {
			nmiss = 1;
			if (got < 0)
				os_info("[abrt] peek 0x%llx: walk failed "
					"(got=%d) — the abort_msg VMA is "
					"gone/unmapped at tgkill\n",
					msg_va, got);
			else {
				os_info("[abrt] peek 0x%llx got=%d hex:",
					msg_va, got);
				for (i = 0; i < 32; i += 8)
					os_info(" "
					"%02x%02x%02x%02x%02x%02x%02x%02x",
					s[i], s[i + 1], s[i + 2],
					s[i + 3], s[i + 4], s[i + 5],
					s[i + 6], s[i + 7]);
				os_info("\n");
			}
		}
	}
	for (k = 0; k < c->mmap_recent_n; k++) {
		unsigned long long va;
		int idx, got;

		idx = (c->mmap_recent_head + 3 - k) % 4;
		va = c->mmap_recent[idx];
		got = abrt_read_str(c, va, s, sizeof(s));
		if (got <= 0 || !abrt_text_match(s, got))
			continue;
		ncaptured++;
		os_info("[abrt] __abort_msg @0x%llx (mmap candidate %d/%d, "
			"task %d)\n", va, k + 1, c->mmap_recent_n,
			current ? current->pid : 0);
		abrt_dump_text(s, got);
		return;
	}
	/* The miss diag (once): ring contents + the peek verdict — the
	 * writer hunt reads the NEXT capture's shape from here. */
	if (nmiss < 1) {
		nmiss = 1;
		os_info("[abrt] capture miss: ring n=%d head=%d "
			"{0x%llx,0x%llx,0x%llx,0x%llx} msg_va=0x%llx "
			"(task %d)\n", c->mmap_recent_n,
			c->mmap_recent_head, c->mmap_recent[0],
			c->mmap_recent[1], c->mmap_recent[2],
			c->mmap_recent[3], msg_va,
			current ? current->pid : 0);
	}
}

/* K3 starhost (referee 37133302551 decode): the ARENA/BIN audit at
 * the abort. "corrupted double-linked list" = unlink_chunk's
 * fd->bk != p || bk->fd != p (image libc 2.36, BuildID 93ac61ec…:
 * unlink_chunk at file 0x95060, the plain string at rodata
 * 0x19805d, printerr call site 0x9510f — detector ret 0x95114).
 * The tcache struct dump is blind to this family (bins live
 * outside it; the heapwalk checks chain geometry, never bin
 * back-pointers). iov[0] points AT the message string in libc
 * rodata (glibc's __libc_message iovecs reference the printerr
 * string in place): an EXACT (len+bytes) match against the
 * printerr table yields the string's rodata offset → libc_base →
 * main_arena (+0x1d3c60 — verified: iov0 0x6076805d + 0x3bc03 =
 * 0x607a3c60 = [rbp+0] in run 37133302551). Self-checks gate
 * every walk (av->top in heap, unsorted head shape) — a wrong
 * derivation skips loudly, never walks garbage. The audit checks
 * every bin head's fd->bk/bk->fd pairing (the unlink predicate at
 * the boundary), always walks the unsorted member chain (≤16), and
 * walks any failed bin's chain — the first desync = the poisoned
 * chunk, printed with run_off + raw qwords + neighbor headers.
 * Plus a stack scan above rbp for libc-text qwords: offline, the
 * first hit past the unlink frame names unlink_chunk's CALLER
 * (_int_malloc / _int_free / malloc_consolidate). */
static const struct {
	unsigned int off;
	const char *msg;
} abrt_strtab[] = {
	{ 0x198040, "corrupted size vs. prev_size" },
	{ 0x19805d, "corrupted double-linked list" },
	{ 0x1980b1, "free(): invalid pointer" },
	{ 0x1980c9, "free(): invalid size" },
	{ 0x1980de, "invalid fastbin entry (free)" },
	{ 0x198159, "malloc(): corrupted top size" },
	{ 0x19cf30, "corrupted double-linked list (not small)" },
	{ 0x19cfc8, "corrupted size vs. prev_size in fastbins" },
	{ 0x19d038, "free(): too many chunks detected in tcache" },
	{ 0x19d068, "free(): unaligned chunk detected in tcache 2" },
	{ 0x19d098, "free(): double free detected in tcache 2" },
	{ 0x19d0c8, "free(): invalid next size (fast)" },
	{ 0x19d0f0, "double free or corruption (fasttop)" },
	{ 0x19d118, "double free or corruption (top)" },
	{ 0x19d138, "double free or corruption (out)" },
	{ 0x19d158, "double free or corruption (!prev)" },
	{ 0x19d180, "free(): invalid next size (normal)" },
	{ 0x19d1a8, "corrupted size vs. prev_size while consolidating" },
	{ 0x19d1e0, "free(): corrupted unsorted chunks" },
	{ 0x19d480, "malloc(): unaligned fastbin chunk detected 2" },
	{ 0x19d4b0, "malloc(): unaligned fastbin chunk detected" },
	{ 0x19d4e0, "malloc(): memory corruption (fast)" },
	{ 0x19d508, "malloc(): unaligned fastbin chunk detected 3" },
	{ 0x19d538, "malloc(): smallbin double linked list corrupted" },
	{ 0x19d568, "malloc(): invalid size (unsorted)" },
	{ 0x19d590, "malloc(): invalid next size (unsorted)" },
	{ 0x19d5b8, "malloc(): mismatching next->prev_size (unsorted)" },
	{ 0x19d5f0, "malloc(): unsorted double linked list corrupted" },
	{ 0x19d620, "malloc(): invalid next->prev_inuse (unsorted)" },
	{ 0x19d650, "malloc(): largebin double linked list corrupted (nextsize)" },
	{ 0x19d690, "malloc(): largebin double linked list corrupted (bk)" },
	{ 0x19d6c8, "malloc(): unaligned tcache chunk detected" },
	{ 0x19d6f8, "malloc(): corrupted unsorted chunks" },
	{ 0x19d750, "malloc(): corrupted unsorted chunks 2" },
};

/* main_arena file offset in the pinned image libc (BuildID
 * 93ac61ec5a8eb1396f9fbd350e3169a558528a40) — from __libc_malloc's
 * arena_get path (lea 0x1d3c60 at file 0x98cd8). */
#define UML_NT_MAIN_ARENA_OFF 0x1d3c60ull

static int abrt_qword(struct uml_nt_stub_conn *c,
		      unsigned long long va, unsigned long long *out)
{
	long long off = uml_nt_vma_translate(c->mm, va, 8);

	if (off < 0)
		return -1;
	*out = *(const unsigned long long *)
		(const void *)((char *)uml_boot.physmem_base + off);
	return 0;
}

/* syscall.c-local twin of stub_ctl.c's dump_guest_bytes (static
 * there) — 64-byte hex rows via os_info, read-only translate. */
static void abrt_dump_bytes(struct uml_nt_mm *mm, unsigned long long va,
			    int n, const char *tag)
{
	unsigned char buf[128];
	char line[3 * 64 + 1];
	long long off;
	int i;

	if (n > (int)sizeof(buf))
		n = (int)sizeof(buf);
	off = uml_nt_vma_translate(mm, va, n);
	if (off < 0) {
		os_info("[abrt]   %s 0x%llx: untranslatable (%lld)\n",
			tag, va, off);
		return;
	}
	memcpy(buf, (char *)uml_boot.physmem_base + off, n);
	for (i = 0; i < n; i += 64) {
		int chunk = (n - i < 64) ? n - i : 64;
		int j;

		for (j = 0; j < chunk; j++)
			snprintf(line + 3 * j, 4, "%02x ", buf[i + j]);
		os_info("[abrt]   %s 0x%llx: %s\n", tag, va + i, line);
	}
}

/* Return the desynced chunk's VA (0 = chain clean to the cap). */
static unsigned long long abrt_bin_walk(struct uml_nt_stub_conn *c,
					unsigned long long head, int idx,
					int maxwalk)
{
	unsigned long long cur;
	int k;

	if (abrt_qword(c, head + 0x10, &cur) < 0)
		return 0;
	for (k = 0; k < maxwalk && cur != head; k++) {
		unsigned long long size, fd, bk, fdbk, bkfd;
		long long coff;
		int bad;

		if (abrt_qword(c, cur + 0x8, &size) < 0 ||
		    abrt_qword(c, cur + 0x10, &fd) < 0 ||
		    abrt_qword(c, cur + 0x18, &bk) < 0) {
			os_info("[abrt]   bin[%d] member 0x%llx: "
				"untranslatable\n", idx, cur);
			break;
		}
		bad = abrt_qword(c, fd + 0x18, &fdbk) < 0 ||
		      fdbk != cur ||
		      abrt_qword(c, bk + 0x10, &bkfd) < 0 ||
		      bkfd != cur;
		coff = uml_nt_vma_translate(c->mm, cur, 8);
		os_info("[abrt]   bin[%d] member 0x%llx size=0x%llx "
			"fd=0x%llx bk=0x%llx fd->bk=%s bk->fd=%s "
			"run=0x%llx%s\n", idx, cur, size & ~7ull, fd, bk,
			fdbk == cur ? "ok" : "BAD", bkfd == cur ? "ok" : "BAD",
			coff >= 0 ? (unsigned long long)coff &
				    ~(UML_NT_PHYS_RUN_SIZE - 1) : 0,
			bad ? "  <== DESYNC" : "");
		if (bad) {
			abrt_dump_bytes(c->mm, cur, 0x40, "desync-chunk");
			abrt_dump_bytes(c->mm, fd, 0x20, "desync-fd");
			abrt_dump_bytes(c->mm, bk, 0x20, "desync-bk");
			return cur;
		}
		cur = fd;
	}
	return 0;
}

/* TWIN SCAN (K3 starhost, referee 37137513174 decode): the desync
 * state = HALF of one glibc operation's stores landed (the chunk's
 * fd/bk keep stale bin links while the head's pairing points at it,
 * or vice versa). The missing stores could not have faulted (every
 * fault prints; none did for those qwords) — so they executed
 * against a STALE VIEW of the page: a COW twin run the conn's stub
 * kept mapping after the table moved (the view-desync class — the
 * uacc fixup no-rollback hole / a wrong-offset re-MAP). The stores
 * LANDED on the twin; the twin's lineage in the [cowcopy]/[phys]
 * ledger then names the mechanism. Sweep ALL of physmem for the
 * page holding the expected-if-landed values, twice:
 *   A (arena twin): qwords at the unsorted head fd/bk + the
 *     desynced bin head fd's page offsets = {uhead, uhead, victim}
 *     (the removal+insert stores as they SHOULD look);
 *   B (chunk twin): the chunk's fd/bk = {uhead, uhead} (the
 *     unsorted-insert stores as they should look).
 * The believed pages never self-match (they hold the stale values
 * by construction). Pure flat-view qword reads — 3 per run, cheap
 * at abort time; hits print refs (a FREE run hit = an old twin
 * whose lineage the ledger still names). */
static void abrt_twin_scan(struct uml_nt_stub_conn *c,
			   unsigned long long av,
			   unsigned long long victim)
{
	const unsigned long long uhead = av + 0x60;
	const unsigned long long a_fd = (av + 0x70) & (UML_NT_PHYS_RUN_SIZE - 1);
	const unsigned long long a_bk = (av + 0x78) & (UML_NT_PHYS_RUN_SIZE - 1);
	const unsigned long long v_fd = (victim + 0x10) & (UML_NT_PHYS_RUN_SIZE - 1);
	const unsigned long long v_bk = (victim + 0x18) & (UML_NT_PHYS_RUN_SIZE - 1);
	const char *base = (const char *)uml_boot.physmem_base;
	unsigned long long run, size = uml_boot.physmem_size;
	unsigned long long hits_a = 0, hits_b = 0;
	unsigned long long vbk, bfd_off = 0;
	int have_bfd = 0;

	if (victim == 0 || size == 0)
		return;
	/* The third A-qword: the bin the victim's stale bk points into
	 * (the earlier pass's insert target) — its head fd should have
	 * become `victim`. Only when bk lands exactly on a bin head. */
	if (abrt_qword(c, victim + 0x18, &vbk) == 0 &&
	    vbk >= uhead && vbk < uhead + 126 * 16 &&
	    ((vbk - uhead) & 0xf) == 0) {
		bfd_off = (vbk + 0x10) & (UML_NT_PHYS_RUN_SIZE - 1);
		have_bfd = 1;
	}
	for (run = 0; run + UML_NT_PHYS_RUN_SIZE <= size;
		     run += UML_NT_PHYS_RUN_SIZE) {
		unsigned long long q0, q1;

		q0 = *(const unsigned long long *)(const void *)(base +
							 run + a_fd);
		if (q0 == uhead) {
			q1 = *(const unsigned long long *)(const void *)(base +
								 run + a_bk);
			if (q1 == uhead && (!have_bfd ||
			    *(const unsigned long long *)(const void *)(base +
						  run + bfd_off) == victim)) {
				hits_a++;
				if (hits_a <= 4)
					os_info("[abrt] TWIN-A run=0x%llx "
						"refs=%d: [fd]=uhead "
						"[bk]=uhead [binfd]=victim "
						"(the missing removal+insert "
						"stores landed HERE)\n", run,
						uml_nt_phys_refs(c->ph,
								 (long long)run));
			}
		}
		q0 = *(const unsigned long long *)(const void *)(base +
							 run + v_fd);
		if (q0 == uhead) {
			q1 = *(const unsigned long long *)(const void *)(base +
								 run + v_bk);
			if (q1 == uhead) {
				hits_b++;
				if (hits_b <= 4)
					os_info("[abrt] TWIN-B run=0x%llx "
						"refs=%d: chunk fd/bk = "
						"uhead/uhead (the missing "
						"insert stores landed "
						"HERE)\n", run,
						uml_nt_phys_refs(c->ph,
								 (long long)run));
			}
		}
	}
	os_info("[abrt] twin scan: %llu A-hit(s), %llu B-hit(s) over "
		"0x%llx bytes\n", hits_a, hits_b, size);
}

static void abrt_arena_audit(struct uml_nt_stub_conn *c,
			     const struct uml_nt_stub_data *d,
			     unsigned long long iov0_base,
			     unsigned long long iov0_len,
			     const char *s)
{
	unsigned long long libc_base = 0, av, top, ufd, ubk, sp, q;
	unsigned long long desync = 0;
	int i, badbins = 0, hits = 0;

	for (i = 0; i < (int)ARRAY_SIZE(abrt_strtab); i++) {
		if (strlen(abrt_strtab[i].msg) == iov0_len &&
		    !memcmp(s, abrt_strtab[i].msg, iov0_len)) {
			libc_base = iov0_base - abrt_strtab[i].off;
			break;
		}
	}
	if (libc_base == 0) {
		os_info("[abrt] arena: no strtab match (iov0 len=%llu) — "
			"bin audit skipped\n", iov0_len);
		return;
	}
	av = libc_base + UML_NT_MAIN_ARENA_OFF;
	os_info("[abrt] arena: libc_base=0x%llx main_arena=0x%llx "
		"(msg off=0x%x)\n", libc_base, av, abrt_strtab[i].off);
	/* Self-checks: av->top (+0x60) is a heap chunk; the unsorted
	 * head (chunk at av+0x60, fd/bk at +0x70/+0x78) is empty
	 * (self-linked) or in-heap. */
	if (abrt_qword(c, av + 0x60, &top) < 0 ||
	    top < c->mm->heap_start || top >= c->mm->heap_end ||
	    abrt_qword(c, av + 0x70, &ufd) < 0 ||
	    abrt_qword(c, av + 0x78, &ubk) < 0 ||
	    !((ufd == av + 0x60 && ubk == av + 0x60) ||
	      (ufd >= c->mm->heap_start && ufd < c->mm->heap_end &&
	       ubk >= c->mm->heap_start && ubk < c->mm->heap_end))) {
		os_info("[abrt] arena: self-check FAILED top=0x%llx "
			"ufd=0x%llx ubk=0x%llx heap [0x%llx,0x%llx) — "
			"derivation wrong, audit skipped\n", top, ufd, ubk,
			c->mm->heap_start, c->mm->heap_end);
		return;
	}
	os_info("[abrt] arena: top=0x%llx unsorted head fd=0x%llx "
		"bk=0x%llx\n", top, ufd, ubk);
	/* Every bin head: fd->bk == head && bk->fd == head (the unlink
	 * predicate at the boundary). bins[i] pair for bin i (1..126)
	 * lives at av+0x70+(i-1)*16; the head CHUNK is 0x10 below. */
	for (i = 1; i <= 126 && badbins < 3; i++) {
		unsigned long long head = av + 0x60 +
					  (unsigned long long)(i - 1) * 16;
		unsigned long long fd, bk, fdbk, bkfd, d2;

		if (abrt_qword(c, head + 0x10, &fd) < 0 ||
		    abrt_qword(c, head + 0x18, &bk) < 0)
			continue;
		if (fd == head && bk == head)
			continue;
		if (abrt_qword(c, fd + 0x18, &fdbk) < 0)
			fdbk = 0;
		if (abrt_qword(c, bk + 0x10, &bkfd) < 0)
			bkfd = 0;
		if (fdbk == head && bkfd == head) {
			if (i == 1) {
				d2 = abrt_bin_walk(c, head, i, 16);
				if (d2 != 0 && desync == 0)
					desync = d2;
			}
			continue;
		}
		badbins++;
		os_info("[abrt]   bin[%d] head 0x%llx fd=0x%llx "
			"bk=0x%llx fd->bk=0x%llx bk->fd=0x%llx — HEAD "
			"DESYNC\n", i, head, fd, bk, fdbk, bkfd);
		d2 = abrt_bin_walk(c, head, i, 16);
		if (d2 != 0 && desync == 0)
			desync = d2;
	}
	if (badbins == 0)
		os_info("[abrt] arena: all bin head pairings clean "
			"(unsorted member walk above)\n");
	/* The desync = a half-landed glibc store set — find the twin
	 * run the missing stores actually landed on (the view-desync
	 * class; see abrt_twin_scan). */
	if (desync != 0)
		abrt_twin_scan(c, av, desync);
	/* M5.6a P-hunter: the aborting check's chunk P sits in a
	 * callee-saved register (unlink_chunk's caller keeps it
	 * there). For each callee-saved reg that names a heap chunk
	 * whose fd/bk are heap-or-arena pointers, P is bin-shaped:
	 * scan ALL bin heads (1..127) and name the bin whose chain
	 * holds it — the corrupting bin, exactly (dl2's audit walked
	 * only bins 1..5 and saw a clean world; dl4's tear lived in
	 * bin[102]). */
	{
		unsigned long long cand[5];
		int ci, bj;

		cand[0] = d->regs.rbx;
		cand[1] = d->regs.r12;
		cand[2] = d->regs.r13;
		cand[3] = d->regs.r14;
		cand[4] = d->regs.r15;
		for (ci = 0; ci < 5; ci++) {
			unsigned long long pv = cand[ci], pfd, pbk;

			if (pv < c->mm->heap_start ||
			    pv >= c->mm->heap_end)
				continue;
			if (abrt_qword(c, pv + 0x10, &pfd) < 0 ||
			    abrt_qword(c, pv + 0x18, &pbk) < 0)
				continue;
			if (!((pfd >= c->mm->heap_start &&
			       pfd < c->mm->heap_end) ||
			      (pfd >= av && pfd < av + 0x900)) ||
			    !((pbk >= c->mm->heap_start &&
			       pbk < c->mm->heap_end) ||
			      (pbk >= av && pbk < av + 0x900)))
				continue;
			os_info("[abrt]   P-candidate 0x%llx fd=0x%llx "
				"bk=0x%llx (bin-shaped)\n",
				pv, pfd, pbk);
			for (bj = 1; bj <= 127; bj++) {
				unsigned long long bh =
					av + 0x50 + 16ull * bj;
				unsigned long long m;
				int st;

				if (abrt_qword(c, bh + 0x10, &m) < 0)
					continue;
				for (st = 0; st < 24 && m != bh;
				     st++) {
					if (m == pv) {
						os_info("[abrt]   P IS "
							"bin[%d] member "
							"#%d\n",
							bj, st);
						break;
					}
					if (m < c->mm->heap_start ||
					    m >= c->mm->heap_end)
						break;
					if (abrt_qword(c, m + 0x10,
						       &m) < 0)
						break;
				}
			}
		}
	}
	/* The caller hint: libc-text qwords above __libc_message's
	 * frame — the first hit past the unlink frame (libc+0x95114)
	 * is unlink_chunk's caller. */
	for (sp = d->regs.rbp + 0x20; sp < d->regs.rbp + 0x120 &&
	     hits < 8; sp += 8) {
		if (abrt_qword(c, sp, &q) < 0)
			continue;
		if (q >= libc_base + 0x26000 && q < libc_base + 0x1b0000) {
			hits++;
			os_info("[abrt]   stacktext [rbp+0x%02llx]: "
				"libc+0x%llx\n", sp - d->regs.rbp,
				q - libc_base);
		}
	}
}

/* The writev-half capture: glibc __libc_message() writev()s the fatal
 * text to fd 2 BEFORE the __abort_msg mmap — this yields the same
 * {function, predicate} pair a round earlier, plus the writev retval
 * that explains why the text never reached the console. Signature-
 * gated on the glibc fatal-message family (abrt_text_match) so every
 * normal fd-2 writev stays silent. */
static void abrt_writev_capture(struct uml_nt_stub_conn *c,
				const struct uml_nt_stub_data *d,
				const unsigned long long *a,
				unsigned long long ret)
{
	static int ncaptured;
	struct { unsigned long long base, len; } iov[8];
	unsigned long long cnt = a[2];
	char s[448];
	int n, i;

	if (!c->task_backed || a[0] != 2 || ncaptured >= 3)
		return;
	if (cnt < 1 || cnt > 8)
		return;
	if (uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a[1],
			     cnt * sizeof(iov[0]), (char *)iov,
			     UML_NT_UACC_FROM_GUEST) < 0)
		return;
	if (!iov[0].base || iov[0].len < 16)
		return;
	n = abrt_read_str(c, iov[0].base, s, sizeof(s));
	/* 098 ε: fd 2 IS the abort channel — glibc writes every fatal
	 * message here, and the task-49/54 aborts died message-less
	 * because their texts didn't match the malloc family. Budget
	 * (3/boot) is the only spam guard; capture whatever stderr
	 * says. */
	if (n < 8)
		return;
	ncaptured++;
	os_info("[abrt] libc-message writev(2) -> %lld iovcnt=%llu "
		"(task %d conn-pid %lu)\n", (long long)ret, cnt,
		current ? current->pid : 0,
		(unsigned long)(c ? c->pid : 0));
	os_info("[abrt]   message class: %s\n",
		abrt_text_match(s, n) ? "malloc-family" : "OTHER");
	/* The writev trap is the EARLIEST fatal point — abort() has
	 * not unwound yet, so the callee-saved regs + the frame qwords
	 * still belong to __libc_message's malloc caller: the chunk
	 * context for the freelist decode (dump_ptr_at class). */
	os_info("[abrt] writev-trap regs: rip=0x%llx rsp=0x%llx "
		"rbx=0x%llx rbp=0x%llx r12=0x%llx r13=0x%llx "
		"r14=0x%llx r15=0x%llx\n", d->regs.rip, d->regs.rsp,
		d->regs.rbx, d->regs.rbp, d->regs.r12, d->regs.r13,
		d->regs.r14, d->regs.r15);
	for (i = 0; i < 6; i += 3) {
		long long foff = uml_nt_vma_translate(c->mm,
						      d->regs.rsp + i * 8,
						      24);

		if (foff >= 0) {
			const unsigned long long *q =
				(const void *)((char *)uml_boot.physmem_base +
					       foff);

			os_info("[abrt]   [rsp+0x%02x]: 0x%llx 0x%llx "
				"0x%llx\n", i * 8, q[0], q[1], q[2]);
		}
	}
	/* Writer hunt (065 item 3): the rbp chain. Run 36910037327's
	 * window stopped at rsp+0x30 — 0xd0 short of rbp. Frame math
	 * against the image's libc 2.36 (base 0x605d0000): trap rip
	 * 0x7f353 = the INLINE writev syscall inside __libc_message
	 * (frameless wrappers — trap rsp IS __libc_message's alloca'd
	 * rsp), rbp = its frame base; malloc_printerr (0x94850) is
	 * frameless with ONE call, so [rbp+8] = ret into malloc_
	 * printerr (0x9486a) and [rbp+0x10] = ret into the DETECTING
	 * malloc function (0x980b3 = tcache path in _int_malloc vs
	 * 0x98c27 = __libc_malloc fast path) — the one qword that
	 * names the detector. Read through the trap regs' rbp, no
	 * layout assumption at runtime. */
	for (i = 0; i < 4; i += 4) {
		long long foff = uml_nt_vma_translate(c->mm,
						      d->regs.rbp + i * 8,
						      32);

		if (foff < 0) {
			os_info("[abrt]   [rbp+0x%02x]: untranslatable "
				"(%lld)\n", i * 8, foff);
			continue;
		}
		{
			const unsigned long long *q =
				(const void *)((char *)uml_boot.physmem_base +
					       foff);

			os_info("[abrt]   [rbp+0x%02x]: 0x%llx 0x%llx "
				"0x%llx 0x%llx\n", i * 8, q[0], q[1],
				q[2], q[3]);
		}
	}
	/* K3 starhost: the arena/bin audit — the iov context anchors
	 * libc (iov[0] = the printerr string in rodata), the audit
	 * names the desynced bin chunk the tcache dump cannot see.
	 * s still holds iov[0]'s bytes here (the per-iov dump below
	 * reuses the buffer). */
	abrt_arena_audit(c, d, iov[0].base, iov[0].len, s);
	for (i = 0; i < (int)cnt; i++) {
		n = abrt_read_str(c, iov[i].base, s, sizeof(s));
		if (n < 0)
			os_info("[abrt]   iov[%d] base=0x%llx len=%llu "
				"unreadable\n", i, iov[i].base, iov[i].len);
		else {
			os_info("[abrt]   iov[%d] base=0x%llx len=%llu:\n",
				i, iov[i].base, iov[i].len);
			abrt_dump_text(s, n);
		}
	}
	/* Writer hunt: the tcache_perthread_struct — run 32907's rbp
	 * chain named the DETECTOR: [rbp+0x18] = 0x98c2c = ret into
	 * __libc_malloc's fastpath tcache_get, i.e. the tcache HEAD
	 * entry (mangled, safe-linked) for some index was unaligned.
	 * The struct is the first chunk of the task's main arena, data
	 * at heap_start+0x10: counts[64] then entries[64]. K3 starhost
	 * (referee 37133302551 decode): dump the FULL 0x290 struct
	 * (header row + all counts + all entries) at mm->heap_start —
	 * the fixed 0x67c00010 only ever covered task 1's layout; a
	 * child abort (task 49 class) found no VMA there and lost the
	 * struct. Offline decode: raw = mangled ^ (slot_va >> 12),
	 * compared against the SEGV-family wilds
	 * (0x7c9f8f0b93be870a / 0xf5aaec5571e07789). */
	{
		unsigned long long tcbase = c->mm->heap_start + 0x10;
		struct uml_nt_vma *hv = c->mm->heap_start != 0 ?
					uml_nt_vma_find(c->mm, tcbase) : NULL;

		if (hv != NULL) {
			int row;

			os_info("[abrt] tcache @0x%llx (vma "
				"[0x%llx,0x%llx) off=0x%llx):\n",
				tcbase, hv->start, hv->end, hv->run_off);
			/* [alias] census (decode 37095399220): same
			 * question as the tcdelta site, asked at the
			 * abort — who ELSE maps this run right now. */
			uml_nt_run_alias_census(c, hv->run_off,
						hv->end - hv->start);
			abrt_dump_bytes(c->mm, c->mm->heap_start, 0x10,
					"tcache-hdr");			for (row = 0; row < 10; row++) {
				long long foff =
					uml_nt_vma_translate(c->mm,
					tcbase + row * 64,
					64);

				if (foff < 0) {
					os_info("[abrt]   row %d: "
						"untranslatable (%lld)\n",
						row, foff);
					continue;
				}
				{
					const unsigned long long *q =
						(const void *)((
						char *)uml_boot.physmem_base +
						foff);

					os_info("[abrt]   +0x%03x: "
						"%016llx %016llx "
						"%016llx %016llx\n",
						row * 64, q[0], q[1],
						q[2], q[3]);
					os_info("[abrt]          "
						"%016llx %016llx "
						"%016llx %016llx\n",
						q[4], q[5], q[6], q[7]);
				}
			}
			/* WRITER-HUNT (068 suppl. 5): run
			 * 36936671540's dump — entries[1] =
			 * entries[2] = 0x5f444d455455245a =
			 * "Z$UTMED_" twice among mangled-sane
			 * pointers: a TEXT fragment over two bin
			 * heads. Offline grep: no rodata in the
			 * rootfs image nor vmlinux/launcher
			 * carries it — runtime string. When the
			 * head slot is text-shaped, scan the
			 * dying space + PID 1 + parent for the
			 * fragment itself (read-only, valscan
			 * machinery). entries[] start at
			 * data+0x80; entries[1] = data+0x88. */
			{
				unsigned long long frag = 0;
				long long foff =
					uml_nt_vma_translate(c->mm,
						tcbase + 0x88, 8);

				if (foff >= 0) {
					const unsigned char *b;
					int i;

					memcpy(&frag, (char *)
					       uml_boot.physmem_base +
					       foff, 8);
					b = (const unsigned char *)
					    &frag;
					for (i = 0; i < 8; i++)
						if (b[i] < 0x20 ||
						    b[i] > 0x7e)
							break;
					if (i == 8) {
						os_info("[abrt] fragscan pattern %016llx (\"%.8s\")\n",
							frag, b);
						uml_nt_stub_frag_scan(c,
								      b);
					}
				}
			}
		} else {
			os_info("[abrt] tcache: no VMA at heap_start+0x10 "
				"(0x%llx, nvma %d)\n", tcbase, c->mm->nvma);
		}
	}
	/* WRITER-HUNT (M5.6a, plan 085): the heap-chain walker. The
	 * fixed tcache watch stayed silent through run 36975582038 —
	 * counts <= 7, pair-state clean at abort — glibc's "corrupted
	 * double-linked list" fires on a BIN chunk elsewhere and 2.36's
	 * malloc_printerr names no address for this message. Walk the
	 * main-arena chunk chain from heap_start: geometry (size >=
	 * MINSIZE, 16-aligned below the flags, next <= heap_end),
	 * prev_size continuity (only when PREV_INUSE = 0 — otherwise
	 * prev_size is the previous chunk's data), and free-chunk fd
	 * (plain VA, NULL, or tcache-safe-linked with THE CHUNK'S OWN
	 * VA as the key — the walker knows it, so the mangle is
	 * reversible here; the entries[] slot was not). bk is checked
	 * soft (a fastbin's stale bk can be untranslatable garbage —
	 * printed, only geometry + fd convict). First bad link wins:
	 * VA + run off + raw qwords — the [cowcopy]/[eager]/[wire]/
	 * [phys] ledger around that run names the writer copy. One
	 * walk per boot (the first capture is the earliest fatal
	 * point). */
	{
		static int heapwalk_done;

		if (!heapwalk_done && c->mm->heap_start != 0 &&
		    c->mm->heap_end > c->mm->heap_start) {
			unsigned long long va, prev_va = 0, prev_cs = 0;
			unsigned long long g1_va = 0, g1_cs = 0;
			unsigned long long g2_va = 0, g2_cs = 0;
			unsigned long long cur_size = 0, cur_ps = 0;
			unsigned long long heap_brk;
			const char *why = NULL;
			int idx;

			heapwalk_done = 1;
			/* Referee 37117711740 decode: the walk convicted
			 * chunk #4578 (va=0x67d0e680, size 0x18981 ending
			 * EXACTLY at brk=0x67d27000 — the abort dump
			 * prints "brk=0x67d27000") as "free-chunk fd
			 * untranslatable". That is the TOP CHUNK: the
			 * walker crossed glibc's brk, read the never-
			 * written zero pages past it as a zero "next
			 * header", took PREV_INUSE=0 as "this chunk is
			 * free", and link-validated fd/bk that glibc
			 * NEVER maintains for the top chunk (they hold
			 * leftover body data — the recurring
			 * {fd=0x1a,bk=0x8000} shape). The real smallbin
			 * victim was never reached. Bound the walk by
			 * brk (binfmt + brk-syscall bookkeeping, fork
			 * preserves it) and skip link validation for the
			 * last chunk before brk — the top chunk by
			 * construction. */
			heap_brk = (c->mm->brk > c->mm->heap_start &&
				    c->mm->brk <= c->mm->heap_end) ?
				   c->mm->brk : c->mm->heap_end;
			for (va = c->mm->heap_start, idx = 0;
			     va < heap_brk && idx < 32768;
			     idx++) {
				long long off =
					uml_nt_vma_translate(c->mm, va, 16);
				unsigned long long hdr[2] = { 0, 0 };
				unsigned long long cs, cs_raw, nxt;

				if (off < 0) {
					why = "header untranslatable";
					break;
				}
				memcpy(hdr, (char *)uml_boot.physmem_base +
				       off, 16);
				cur_ps = hdr[0];
				cur_size = hdr[1];
				cs_raw = hdr[1] & ~(unsigned long long)0x7;
				cs = cs_raw;
				if (cs < 0x20) {
					why = "size < MINSIZE";
					break;
				}
				if ((cs & 0xF) != 0) {
					why = "size not 16-aligned";
					break;
				}
				if (va + cs > heap_brk) {
					why = "chunk runs past heap brk";
					break;
				}
				if ((hdr[1] & 1) == 0 && prev_va != 0 &&
				    hdr[0] != prev_cs) {
					why = "prev_size mismatch";
					break;
				}
				nxt = va + cs;
				/* nxt == heap_brk → this chunk is the
				 * top chunk: skip the free-link check —
				 * its fd/bk are leftovers, not bin
				 * links (the FP class of 37117711740). */
				if (nxt < heap_brk) {
					long long noff = uml_nt_vma_translate(
						c->mm, nxt, 16);
					unsigned long long nh[2];

					if (noff < 0) {
						why = "next header "
						      "untranslatable";
						break;
					}
					memcpy(nh, (char *)uml_boot.
					       physmem_base + noff, 16);
					if ((nh[1] & 1) == 0) {
						/* this chunk is FREE:
						 * validate its links */
						unsigned long long fd = 0;
						long long foff =
							uml_nt_vma_translate(
							c->mm, va + 0x10, 8);
						int fd_ok;

						if (foff >= 0)
							memcpy(&fd, (char *)
							       uml_boot.
							       physmem_base +
							       foff, 8);
						{
							unsigned long long
							un = fd ^ (va >> 12);

							fd_ok =
								foff < 0 ||
								fd == 0 ||
								uml_nt_vma_translate(
								c->mm, fd, 1)
								>= 0 ||
								un == 0 ||
								uml_nt_vma_translate(
								c->mm, un, 1) >= 0;
						}
						if (!fd_ok) {
							why = "free-chunk fd "
							      "untranslatable";
							break;
						}
					}
				}
				if (idx > 0) {
					g2_va = g1_va;
					g2_cs = g1_cs;
					g1_va = prev_va;
					g1_cs = prev_cs;
				}
				prev_va = va;
				prev_cs = cs;
				va += cs;
			}
			if (why != NULL) {
				long long off2 =
					uml_nt_vma_translate(c->mm, va, 1);
				long long foff =
					uml_nt_vma_translate(c->mm, va, 64);

				os_info("[heapwalk] BAD chunk #%d va=0x%llx "
					"run_off=0x%llx: %s\n", idx, va,
					off2 < 0 ? (unsigned long long)-1 :
					(unsigned long long)off2 &
					~(UML_NT_PHYS_RUN_SIZE - 1), why);
				os_info("[heapwalk]   size=0x%llx "
					"prev_size=0x%llx prev_cs=0x%llx "
					"heap [0x%llx,0x%llx)\n",
					cur_size, cur_ps, prev_cs,
					c->mm->heap_start, c->mm->heap_end);
				os_info("[heapwalk]   last good: va=0x%llx "
					"cs=0x%llx, before: va=0x%llx "
					"cs=0x%llx\n", g1_va, g1_cs, g2_va,
					g2_cs);
				if (foff >= 0) {
					const unsigned long long *q =
						(const void *)((char *)
						uml_boot.physmem_base + foff);

					/* 097 α': 64 bytes at the bad
					 * header — the prev chunk's
					 * tail data included (a writer
					 * over the headers leaves its
					 * payload's SHAPE: the 0x1a/
					 * 0x8000 pair + text lived
					 * exactly here in run
					 * 37031558530). */
					os_info("[heapwalk]   raw: %016llx "
						"%016llx %016llx %016llx\n",
						q[0], q[1], q[2], q[3]);
					os_info("[heapwalk]   raw2: "
						"%016llx %016llx %016llx "
						"%016llx\n", q[4], q[5],
						q[6], q[7]);
					{
						const unsigned char *b;
						int i, j;

						for (j = 0; j < 8; j++) {
							b = (const unsigned
							     char *)&q[j];
							for (i = 0; i < 8; i++)
								if (b[i] <
								    0x20 ||
								    b[i] >
								    0x7e)
									break;
							if (i == 8)
								break;
						}
						if (j < 8) {
							os_info("[heapwalk]   fragscan pattern %016llx (\"%.8s\")\n",
								q[j],
								(const char *)
								&q[j]);
							uml_nt_stub_frag_scan(
								c, (const
								unsigned char *)
								&q[j]);
						}
					}
				}
				/* 097 α': the next chunk's header as the
				 * walk saw it — PREV_INUSE=0 there is
				 * what convicted this chunk, so its
				 * raw values name the stomp's reach
				 * (the neighbor's header is the
				 * writer's other victim). */
				{
					long long noff =
						uml_nt_vma_translate(
						c->mm, va + (cur_size &
						~(unsigned long long)0x7),
						16);

					if (noff >= 0) {
						const unsigned long long *nq =
							(const void *)((char *)
							uml_boot.physmem_base +
							noff);

						os_info("[heapwalk]   next hdr @0x%llx: "
							"prev_size=%016llx "
							"size=0x%llx\n",
							va + (cur_size &
							~(unsigned long long)
							0x7), nq[0], nq[1]);
					}
				}
			} else if (va < heap_brk) {
				/* Run 36979286356: the old 4096 cap hit
				 * and the "clean" message lied — a
				 * 1.2 MB heap of 0x20 chunks walks
				 * ~24k links. Say CAP HIT. */
				os_info("[heapwalk] CAP HIT va=0x%llx "
					"after %d chunks — chain untested "
					"beyond (heap [0x%llx,0x%llx))\n",
					va, idx, c->mm->heap_start,
					c->mm->heap_end);
			} else {
				os_info("[heapwalk] chain clean to brk "
					"(%d chunks, heap [0x%llx,0x%llx) "
					"brk 0x%llx)\n",
					idx, c->mm->heap_start,
					c->mm->heap_end, heap_brk);
			}
			/* WRITER-HUNT (M5.6a): the tcache poison
			 * witness. Run 36979286356 died
			 * "malloc(): unaligned tcache chunk detected" —
			 * entries[i] (the RAW head pointers, heap_start
			 * +0x90) held a pointer glibc can't dequeue; the
			 * mangle-free tcwatch can't see it (counts +
			 * pair-state only) and the chain walk reads
			 * headers, not the entries array. Dump every
			 * entry that is neither NULL nor 16-aligned,
			 * with its translation: a value that translates
			 * through THIS mm is an in-heap writer (match
			 * the run off against the [cowcopy]/[eager]/
			 * [wire]/[phys] ledger); one that doesn't
			 * convicts a ghost view / foreign writer. */
			{
				long long toff = uml_nt_vma_translate(
					c->mm, c->mm->heap_start, 16);

				if (toff >= 0) {
					unsigned long long thdr[2];
					int tidx;

					memcpy(thdr, (char *)uml_boot.
					       physmem_base + toff, 16);
					if ((thdr[1] & ~0x7ull) == 0x290) {
						for (tidx = 0; tidx < 64;
						     tidx++) {
							unsigned long long ev;
							long long eoff =
								uml_nt_vma_translate(
								c->mm,
								c->mm->heap_start +
								0x90 +
								(unsigned long long)
								tidx * 8, 8);

							if (eoff < 0)
								break;
							memcpy(&ev, (char *)
							       uml_boot.
							       physmem_base +
							       eoff, 8);
							if (ev != 0 &&
							    (ev & 0xF) != 0) {
								long long voff =
									uml_nt_vma_translate(
									c->mm,
									ev &
									~0xFull,
									1);

								os_info("[heapwalk] "
									"tcache entries[%d]"
									"=0x%llx MISALIGNED"
									" — translate %s"
									" (off=0x%llx)\n",
									tidx, ev,
									voff >= 0 ?
									"IN-mm" :
									"FOREIGN",
									voff < 0 ?
									(unsigned long long)-1 :
									(unsigned long long)voff &
									~(UML_NT_PHYS_RUN_SIZE - 1));
							}
						}
					}
				}
			}
		}
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
	unsigned long long uacc_prev_nr;

	/* [deadwrite] leak guard (lead 115): the exit route arms the
	 * destroy-path witness and do_exit never returns, so a fresh
	 * round on ANY conn (this thread serves them all) is the one
	 * point that reliably retires the armed context. */
	uml_nt_deadwrite_disarm();

	uacc_prev_mm = uml_nt_uacc_set_mm(c->mm);
	/* K6 (M5.6a): the current round's nr for the [uawrite]
	 * full-buffer witness — uml_nt_uacc_nr_enter installs the
	 * global AND stamps c->active_nr, the slot the stack-switch
	 * boundary re-arms from (stub_ctl.c uml_nt_switch_trace: a
	 * task woken inside its blocked handler keeps its OWN nr even
	 * after an intervening do_exit'd task never unwound its
	 * dispatch). Same nesting save/restore as the mm above (the
	 * local prev + plain set_nr at out:) — see uaccess_walk.h. */
	uacc_prev_nr = uml_nt_uacc_nr_enter(&c->active_nr, nr);
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
	/* [cowtrap] carrier: re-queue the armed page's NOACCESS op
	 * right after the plan reset (the serve-round tail where the
	 * arm appended it would be wiped by THIS reset). */
	uml_nt_cowtrap_pending(c);

	switch (nr) {
	case 60: /* exit */
	case 231: /* exit_group — POC conns: the halt parks the stub
		   * (no task to reap behind it). Task-backed conns go
		   * through the REAL exit_group → do_exit: PID 1
		   * trips the kernel's own "Attempted to kill init!"
		   * panic (the launcher stops with the M1 panic
		   * convention, exit 1 — the reader, the timers and
		   * every conn die with the process; the
		   * 100-real-alpine zombie had init exiting into a
		   * halt nobody served), and any other task reaps
		   * clean through the scheduler — its conn dies with
		   * its mm at destroy_context, never a panic. */
		d->retval = a[0];
		if (c->task_backed) {
			/* do_exit — for PID 1 the kernel panics (the
			 * launcher exits with the M1 panic code); for
			 * any other task the mm is dropped and the
			 * conn is freed MID-DISPATCH (the execve
			 * model): nothing of c/d may be touched
			 * after — same `goto out` the exec path
			 * uses, whose tail only unwinds the uacc
			 * globals. */
			/* [deadwrite] arm (lead 115): from here to conn
			 * death the DYING task's exit path owns this
			 * thread — the robust-list exit-fixup class
			 * writes through the walker/futex primitives
			 * right here. Every translate-then-write into
			 * the heap window logs with tag=exit. */
			uml_nt_deadwrite_arm(current ? current->pid : 0,
					     "exit");
			sys_vfs(nr, a);
			goto out;
		}
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
	case 262: /* newfstatat — glibc's fstat/stat shape (AT_EMPTY_PATH) */
	case 332: /* statx — glibc stat variants */
	case 137: /* statfs — systemd probes mount-point fs types */
	case 138: /* fstatfs */
	case 318: /* getrandom — systemd + libcrypto key material */
	case 319: /* memfd_create — the executor's anonymous files */
	case 321: /* bpf — systemd probes; the honest kernel answer
		   * (enabled or -ENOSYS from the table) beats ours */
	case 439: /* faccessat2 — systemd file probes (RENAME flags) */
	case 83: /* mkdir — systemd /run /tmp /var runtime dirs */
	case 258: /* mkdirat */
	case 84: /* rmdir */
	case 87: /* unlink */
	case 263: /* unlinkat — the whole tmpfile/lockfile family */
	case 88: /* symlink */
	case 266: /* symlinkat — the systemd run-dir wiring */
	case 89: /* readlink — /proc/self/exe + unit aliases */
	case 267: /* readlinkat — glibc's canonicalize */
	case 90: /* chmod */
	case 91: /* fchmod */
	case 268: /* fchmodat — /run sockets/units perms */
	case 92: /* chown */
	case 93: /* fchown */
	case 260: /* fchownat */
	case 82: /* rename */
	case 264: /* renameat */
	case 316: /* renameat2 — atomic unit state moves */
	case 280: /* utimensat — timestamp touch */
	case 133: /* mknod — /dev/null-ish nodes systemd creates */
	case 165: /* mount — proc/sysfs/devtmpfs/cgroup2 by systemd */
	case 166: /* umount2 */
	case 8: /* lseek — ash reads the script by chunks */
	case 17: /* pread64 — glibc ld.so reads the ELF headers of the
		  * libs it maps (M5.4 c2 census, D20) */
	case 21: /* access — the glibc startup cluster's probe calls */
	case 273: /* set_robust_list — glibc TCB init (per-task record,
		   * no guest memory touched at registration) */
	case 302: /* prlimit64 — glibc stack/rlimit queries at start */
	case 334: /* rseq — glibc registers the per-task rseq block;
		   * failure is tolerated by the guest, but the real
		   * syscall rides the walker fine */
	case 80: /* chdir — systemd asserts chdir("/") at start
		  * (main.c:2906 "Assertion 'chdir("/") == 0' failed
		  * ... Aborting" ended the previous boot) */
	case 81: /* fchdir */
	case 259: /* mknodat — do_static_devnodes creates /dev/null,
		   * zero, full, random, urandom when /dev/null is
		   * missing (5 calls named by run 36772786755; mknod
		   * 133 was routed, the at-suffix twin was not) */
	case 79: /* getcwd — ash prompt/pwd */
	case 217: /* getdents64 — ash PATH search, glob */
	case 20: /* writev — musl __stdio_write IS writev: every byte
		  * busybox prints goes through here (fd 1/2 = the
		  * real console files of the exec'd task). The ABRT
		  * capture rides AFTER the real writev: glibc
		  * __libc_message (malloc assertion, Astra §2) emits
		  * the fatal text as fd-2 writev before it mmaps
		  * __abort_msg and aborts — signature-gated, silent
		  * for every normal console writev. */
		ret = sys_vfs(nr, a);
		abrt_writev_capture(c, d, a, ret);
		break;
	case 41: /* socket — M5.1c: AF_PACKET (udhcpc), AF_INET/ICMP
		  * (ping) — in-guest kernel sockets, no host side */
	case 42: /* connect */
	case 43: /* accept */
	case 44: /* sendto — the DHCP DISCOVER / ICMP echo */
	case 45: /* recvfrom — the OFFER/ACK / echo reply */
	case 46: /* sendmsg */
	case 47: /* recvmsg */
	case 48: /* shutdown */
	case 49: /* bind — udhcpc's AF_PACKET sll bind */
	case 50: /* listen */
	case 53: /* socketpair */
	case 54: /* setsockopt — SO_BROADCAST, SO_ATTACH_FILTER */
	case 55: /* getsockopt */
	case 51: /* getsockname — systemd's netlink open checks the
		  * bound address ("Failed to open netlink, ignoring"
		  * run 36774586381 — socket+bind succeeded, this was
		  * the missing tail) */
	case 52: /* getpeername */
	case 22: /* pipe — udhcpc's self-pipe (signal wakeup) */
	case 293: /* pipe2 */
	case 7: /* poll — udhcpc waits the lease window in poll() */
	case 23: /* select */
	case 270: /* pselect6 */
	case 271: /* ppoll — systemd's netlink wait ("Failed to wait
		   * for netlink event, ignoring") */
	case 35: /* nanosleep — ping interval, retry loops (hrtimer
		  * machinery: the same clock the sysbench window ran) */
		ret = sys_vfs(nr, a);
		break;
	case 77: /* ftruncate */
	case 74: /* fsync */
	case 75: /* fdatasync */
	case 285: /* fallocate — journal files */
	case 28: /* madvise */
	case 24: /* sched_yield */
	case 99: /* sysinfo */
	case 98: /* getrusage */
	case 202: /* futex — guest pthreads (the walker serves the
		   * guest pointers; hazard-3 fixups apply) */
	case 230: /* clock_nanosleep — unit timeout arithmetic */
	case 291: /* epoll_create1 — the systemd event loop */
	case 233: /* epoll_ctl */
	case 232: /* epoll_wait — rides the kernel poll backend */
	case 283: /* timerfd_create */
	case 286: /* timerfd_settime — unit timers */
	case 287: /* timerfd_gettime */
	case 289: /* signalfd4 */
	case 290: /* eventfd2 — the wake channel */
	case 253: /* inotify_init */
	case 254: /* inotify_add_watch */
	case 255: /* inotify_rm_watch */
	case 294: /* inotify_init1 — manager_new's control-group inotify
		   * object: "Failed to create control group inotify
		   * object" → "Failed to allocate manager object" →
		   * "Freezing execution" (run 36774586381) — THE hard
		   * stop of this boot; the real fs/notify machinery is
		   * kernel-internal and rides the bridge as-is */
	case 428: /* open_tree */
	case 437: /* openat2 — the glibc 2.34+ open shape */
	case 436: /* close_range — systemd closing its fds */
	case 34: /* pause — MUST block (a busy-looping unit ate 1.4M
		  * instant ENOSYS returns in one 2.7-minute boot) */
	case 112: /* setsid — systemd early boot (tolerated ENOSYS
		   * so far; the real call is one route away) */
	case 170: /* sethostname — "Failed to set hostname to <uml>" */
	case 169: /* reboot — RB_DISABLE_CAD bookkeeping ("Failed to
		   * enable ctrl-alt-del handling"); a real poweroff
		   * would ride machine_power_off — correct semantics */
	case 95: /* umask — systemd sets the boot umask */
	case 125: /* capget */
	case 126: /* capset — unit capability drops */
	case 227: /* clock_settime — systemd corrects the wall clock */
	case 164: /* settimeofday */
	case 159: /* adjtimex */
	case 162: /* sync */
	case 247: /* waitid */
	case 234: /* tgkill — glibc abort()/raise() (the previous boot
		   * died in the abort retry loop after the chdir assert
		   * fired; the kernel protects init from fatal
		   * default-action signals, non-init tasks die right) */
	case 37: /* alarm — the real itimer (SIGALRM to current via the
		  * M4d delivery machinery); ENOSYS counter 1x/boot
		  * (run 36782313512) */
	case 62: /* kill — the ABRT cascade of run 36786525015: every
		  * generator's crash handler forks a coredump child
		  * whose kill(getpid(), sig) got ENOSYS, so the child
		  * survived to assert_not_reached (crash-handler.c:85)
		  * and aborted its parent — the whole system-generators
		  * phase "terminated by signal ABRT" */
	case 197: /* removexattr — the cgroup/tmpfs xattr cleanup
		   * systemd does at boot (6x, same run); a missing
		   * attribute is the real -ENODATA answer */
	case 188: /* setxattr — systemd's "systemd" / "security.SMACK64"
		   * tmpfs xattr writes (14x in run 36787150906); the
		   * real VFS answers (or -ENOTSUP where the fs says
		   * so — the honest errno beats ENOSYS) */
	case 146: /* sched_getscheduler — systemd's cpu-shaping probe
		   * (1x in the same run) */
	case 147: /* sched_rr_get_interval — the probe's tail */
	case 303: /* name_to_handle_at — the file-handle probe; real
		   * VFS answers, systemd takes its graceful fallback
		   * path on any errno */
	case 27: /* mincore — residency probe; the generic impl walks
		  * the task's real kernel mm and answers (or -ENOMEM
		  * where nothing is mapped — callers tolerate) */
	case 73: /* flock — the guest's own file locks (kernel-
		  * internal; D13's no-op os_lock_file is the HOST
		  * layer, different thing) */
	case 131: /* sigaltstack — glibc's crash-handler setup on
		   * every pthread start; the kernel records the
		   * stack (delivery uses it via the M4d machinery) */
	case 191: /* getxattr — the GET side of the setxattr traffic:
		  * systemd reads the security/user namespaces' attrs
		  * back */
	case 192: /* lgetxattr (no-follow) */
	case 193: /* fgetxattr (fd-based) */
	case 190: /* fsetxattr — journald sets the journal-file attrs in
		   * its open path (run 36889953754: the MAP_SHARED
		   * single-mapper map succeeded, then fsetxattr +
		   * pwrite64 both ENOSYS'd → "Failed to open runtime
		   * journal" → restart loop). fd-based twin of
		   * 191/192/193. */
	case 18: /* pwrite64 — journald writes the journal header +
		  * seqnum right after the MAP_SHARED map (same run);
		  * the explicit-offset twin of write/pread64. */
	case 105: /* setuid */
	case 106: /* setgid */
	case 109: /* setpgid */
	case 111: /* getpgrp */
	case 113: /* setreuid — sd-executor setup_keyring() chowns the
		   * per-service user keyring under the service's UID/GID
		   * (systemd-resolved / systemd-networkd 237/KEYRING in
		   * referee H1/H2 when nr=114/113 hit default ENOSYS
		   * after b64ef19 enabled add_key). */
	case 114: /* setregid */
	case 115: /* getgroups */
	case 116: /* setgroups — systemd's "Failed at step GROUP
		   * spawning systemd-networkd" (execute.c:5314,
		   * "Failed to determine supplementary groups" — the
		   * initgroups tail; archive m5.4-c3 recorded it as
		   * "networkd chết 216/GROUP (setgroups?)" — this is
		   * the answer: the nr was never routed) */
	case 117: /* setresuid */
	case 118: /* getresuid */
	case 119: /* setresgid */
	case 120: /* getresgid */
	case 121: /* getpgid */
	case 122: /* setfsuid */
	case 123: /* setfsgid */
	case 124: /* getsid */
	case 204: /* sched_getaffinity — systemd's CPU-shaping probe
		   * (1x in run 36889953754); the honest answer here
		   * is 1 CPU (CPUs=1) */
	case 96:  /* gettimeofday */
	case 161: /* chroot */
	case 201: /* time */
	case 229: /* clock_getres */
	case 272: /* unshare */
	case 288: /* accept4 — socket activation (the AF_UNIX
		   * journald listeners are kernel-internal, D8 only
		   * bans the kernel<->helper channel) */
	case 429: /* move_mount */
	case 430: /* fsopen */
	case 431: /* fsconfig */
	case 432: /* fsmount */
	case 433: /* fspick */
	case 442: /* mount_setattr */
		ret = sys_vfs(nr, a);
		break;
	case 1: /* write — fds 1/2 on console tty ride the console
		  * hand-path (probe conns have no files_struct; the
		  * bench markers ride here too, M4.1). fd >= 3, fd 0
		  * on task-backed conns (e.g. agetty opening /run/utmp
		  * on fd 0), or fds 1/2 redirected to pipes, sockets,
		  * regular files, or /dev/null ride the REAL VFS. */
		if (a[0] > 2 || (c->task_backed && a[0] == 0)) {
			ret = sys_vfs(nr, a);
		} else if (c->task_backed) {
			struct fd f = fdget((unsigned int)a[0]);
			int use_vfs = 0;

			if (!fd_file(f)) {
				use_vfs = 1;
			} else {
				struct inode *ino = file_inode(fd_file(f));

				if (!S_ISCHR(ino->i_mode) ||
				    imajor(ino) == MEM_MAJOR)
					use_vfs = 1;
			}
			fdput(f);
			ret = use_vfs ? sys_vfs(nr, a) : sys_write(c, a);
		} else {
			ret = sys_write(c, a);
		}
		break;
	case 9: /* mmap — file-backed (fd != -1) = the dynamic-loader
		 * path (M5.4 c2, D20); anon stays below. fd is an INT
		 * in the mmap ABI: glibc materializes -1 as the
		 * 32-bit 0xFFFFFFFF (mov r8d, -1 — zero-extended into
		 * the register), Linux reads only the low 32 bits. */
		if (!(a[3] & SC_MAP_ANONYMOUS) &&
		    (long long)(int)(unsigned)a[4] != -1L)
			ret = sys_mmap_file(c, a);
		else
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
	case 14: /* rt_sigprocmask — REAL on task-backed conns: glibc
		  * abort() unblocks SIGABRT before raising it, and the
		  * POC ack-only answer below (zero oldset, ignore the
		  * new mask) would lie about the blocked set the
		  * delivery machinery consults. POC conns keep the
		  * ack (bench markers M4.1). */
		if (c->task_backed) {
			ret = sys_vfs(nr, a);
			break;
		}
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
			/* M5.4 c3 (map 056): zero the DEAD frame. Upstream
			 * leaves the bytes too, but nothing may READ them:
			 * below-rsp is dead by the ABI. Here the residue
			 * went LIVE — the frame's uc_mcontext.rip (the
			 * fork-resume rip, trap+2: _Fork+0x23) survived at
			 * every depth the task ever ran at, deeper forks
			 * inherited it as "live" caller frames above the
			 * fork rsp (the seed's below-rsp zero cannot reach
			 * there), and the exec_child env-merge descending
			 * to deterministic depths read the mcontext/siginfo
			 * cluster as strv/vararg pointers — the 56×
			 * SIGSEGV strcspn signature, self-perpetuating
			 * (the victim's own SIGSEGV frame re-seeds it).
			 * Deliberate Linux-parity deviation, same class as
			 * the fork-seed zero (aca83a6). 0x600 covers the
			 * frame (pretcode + ucontext + siginfo) plus the
			 * fpstate block with slack — all dead at this
			 * point: the restore already read them into
			 * thread.regs, and the interrupted true_sp sits
			 * 0x2000 higher. */
			{
				unsigned long long frame = d->regs.rsp - 8;

				if (uml_nt_uacc_walk(c->mm,
						     uml_boot.physmem_base,
						     frame, 0x600, NULL,
						     UML_NT_UACC_ZERO_GUEST) <
				    0)
					os_info("[syscall] rt_sigreturn: "
						"dead-frame zero EFAULT "
						"(frame 0x%llx)\n", frame);
			}
			c->sig_regs_current = 1;
			c->push_verbatim = 1;
			break;
		}
		ret = SC_RET(SC_ENOSYS);
		break;
	case 16: /* ioctl — REAL: the net ioctls (SIOCGIFHWADDR/
		 * SIOCGIFINDEX/SIOCSIFADDR/SIOCSIFFLAGS/SIOCADDRT —
		 * ifconfig/udhcpc/ping wiring) plus the tty ioctls
		 * musl isatty sends. The console IS a real tty and the
		 * net stack is real — the generic bridge serves both;
		 * a non-tty fd gets the real ENOTTY. */
		/* §4a feed alignment: TCSETSF (= tcsetattr TCSAFLUSH)
		 * and TCFLSH with input are the tty's own flush
		 * boundary — drop the console ring's un-fed bytes there
		 * too, or a pre-prompt feed cycle lands on the next
		 * prompt as username/password (the "uml login: echo
		 * LOGIN-OK" desync). */
		if (a[1] == 0x5404 /* TCSETSF */ ||
		    (a[1] == 0x540b /* TCFLSH */ &&
		     (a[2] == 0 /* TCIFLUSH */ || a[2] == 2 /* TCIOFLUSH */)))
			uml_nt_console_drop_input();
		ret = sys_vfs(nr, a);
		if (!ioctl_once) {
			ioctl_once = 1;
			os_info("[syscall] ioctl(0x%llx) -> %lld (done)\n",
				a[1], (long long)ret);
		}
		break;
	case 39: /* getpid */
	case 186: /* gettid — one thread per task on this port */
		/* M5.4 c3: task-backed conns report the KERNEL's pid —
		 * the init task IS pid 1 and systemd refuses to run
		 * otherwise (its exec chain degraded to the systemctl
		 * client and exit(1) with the windows pid). POC conns
		 * keep the windows stub pid (the probe fork contract
		 * asserts it). */
		ret = c->task_backed ? current->pid : c->pid;
		break;
	case 110: /* getppid */
		if (c->task_backed) {
			ret = sys_vfs(nr, a);
			break;
		}
		ret = c->ppid;
		break;
	case 102: /* getuid */
	case 104: /* getgid */
	case 107: /* geteuid */
	case 108: /* getegid */
		if (c->task_backed) {
			ret = sys_vfs(nr, a);
			break;
		}
		ret = 0;
		break;
	case 135: /* personality — see the conn field comment (systemd
		  * LockPersonality=yes units died 228/SECCOMP on
		  * ENOSYS and journald restart-looped, run
		  * 36869737934). glibc passes the get sentinel as
		  * 0xffffffff (upper 32 zeroed by the mov). */
		ret = (long long)c->persona;
		if (a[0] != 0xffffffffULL)
			c->persona = a[0];
		break;
	case 32: /* dup */
	case 33: /* dup2 — xmove_fd (ping's socket setup) */
	case 292: /* dup3 */
		ret = sys_vfs(nr, a);
		break;
	case 58: /* vfork — busybox's run_script (udhcpc's lease script).
		  * The per-stub model has no shared-mm vfork (the generic
		  * sys_vfork would clone with CLONE_VM): serve it as a
		  * plain COW fork — the child execs immediately, and COW
		  * isolation is strictly safer than vfork sharing. */
		if (c->task_backed) {
			ret = sys_fork_real(c, d, a, 57);
			break;
		}
		uml_nt_sys_fork(c, d);
		ret = d->retval;
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
	case 157: /* prctl — M5.4 c3: the systemd process-option
		   * cluster. REAL on task-backed conns: the generic
		   * prctl carries the commands the hand-rolled table
		   * lacked with honest cred/cap checks — sd-executor's
		   * PR_SET_PDEATHSIG (1 — the defines had 1/2 swapped:
		   * "Failed to set death signal: Invalid argument"),
		   * PR_SET_MM (35), PR_GET_AUXV (47, the repeated
		   * cmd=47 EINVALs). POC conns keep the hand-rolled
		   * answer. */
		if (c->task_backed) {
			ret = sys_vfs(nr, a);
			break;
		}
		ret = sys_prctl(c, a);
		break;
	case 228: /* clock_gettime — the guest's time source (M4 sysbench):
		   * CLOCK_MONOTONIC/REALTIME both read os_nsecs() (QPC,
		   * D6) — the boot-relative ns clock the whole kernel
		   * already runs on. timespec walks the D15 walker
		   * (guest pointer). */
		ret = sys_clock_gettime(c, a);
		break;
	case 221: /* fadvise64 — the boot's single nr=221 of the
		   * referee ENOSYS table (dl13 + dl15, one call).
		   * POSIX_FADV_* is a page-cache hint: with no page
		   * cache to advise (the M4 mem model keeps none),
		   * the honest kernel answer is a no-op success —
		   * callers tolerate ENOSYS too, but the login-path
		   * table must go quiet. */
		ret = 0;
		break;
	case 248: /* add_key — the table's other straggler (dl13 +
		   * dl15, one call per boot). Same phantom-keyring
		   * family as keyctl JOIN below (b583f28): we keep
		   * no keyring, so the "added" key is a phantom
		   * serial — if a real keyring user reads it back
		   * through keyctl, the loud-ENOSYS branch below
		   * names it. */
		ret = 0x2ea; /* phantom key serial (keyring is 0x2e9) */
		break;
	case 250: /* keyctl — systemd's exec KEYRING step calls
		   * keyctl(KEYCTL_JOIN_SESSION_KEYRING) for every
		   * sandboxed service; ENOSYS fails the whole spawn
		   * (status=237/KEYRING — the dl1 networkd crash-loop).
		   * We keep no keyring: JOIN/GET_KEYRING_ID return a
		   * fake positive serial (the step succeeds, the
		   * session keyring is a phantom — nothing in the boot
		   * reads it back) and metadata/link mutations on the
		   * phantom serial (CHOWN/SETPERM/LINK/UNLINK/SET_TIMEOUT/
		   * SET_REQKEY_KEYRING/SESSION_TO_PARENT) succeed as
		   * no-ops. Other commands stay loud-ENOSYS so real
		   * keyring users name themselves. */
		if (a[0] == 0 /* KEYCTL_GET_KEYRING_ID */ ||
		    a[0] == 1 /* KEYCTL_JOIN_SESSION_KEYRING */)
			ret = 0x2e9;
		else if (a[0] == 4 /* KEYCTL_CHOWN */ ||
			 a[0] == 5 /* KEYCTL_SETPERM */ ||
			 a[0] == 8 /* KEYCTL_LINK */ ||
			 a[0] == 9 /* KEYCTL_UNLINK */ ||
			 a[0] == 14 /* KEYCTL_SET_REQKEY_KEYRING */ ||
			 a[0] == 15 /* KEYCTL_SET_TIMEOUT */ ||
			 a[0] == 18 /* KEYCTL_SESSION_TO_PARENT */)
			ret = 0;
		else {
			os_info("[syscall] keyctl cmd=%llu not "
				"implemented → ENOSYS\n", a[0]);
			ret = SC_RET(SC_ENOSYS);
		}
		break;
	case 312: /* kcmp — journald probes fd equality for stream dedup
		   * and falls back cleanly on ENOSYS; keep off the
		   * default loud table so 2200+ probes per boot do not
		   * flood the console. */
		ret = SC_RET(SC_ENOSYS);
		break;
	default:
		/* [fork-entry] audit: a fork-class nr that reaches the
		 * default = the child's conn spawns WITHOUT the arm/
		 * seed wrapper — an empty mirror at birth ("INIT: 0
		 * map op(s)" → rip=0, conn 3124's death). Loud here so
		 * the log names the branch; the generic sys_vfs below
		 * still runs (upstream parity). */
		if (nr == 56 || nr == 57 || nr == 58 || nr == 435)
			os_info("[fork-entry] nr=%llu hit the DEFAULT "
				"dispatch — arm/seed will MISS (child "
				"spawns unseeded)\n", nr);
		/* M5.6a writer-hunt follow-up: a nr outside the table
		 * cannot be a guest syscall — the stub's gate should have
		 * refused it (resume_model.h). Record the trap site and
		 * the table's bytes: the ab boot's cascade started exactly
		 * here (nr=0x6001b560, a code address, then nr=-ENOSYS). */
		if (nr >= (unsigned long long)syscall_table_size /
			  sizeof(sys_call_ptr_t)) {
			long long bo = -1;
			unsigned long long bq = 0;

			if (c->mm != NULL)
				bo = uml_nt_vma_translate(c->mm,
							  d->regs.rip, 8);
			if (bo >= 0)
				memcpy(&bq, (char *)uml_boot.physmem_base +
				       bo, 8);
			os_info("[syscall-BADNR] pid %lu nr=%llu (0x%llx) "
				"rip=0x%llx rsp=0x%llx tbl_insn=%016llx "
				"— an illegal instruction off the ud2 "
				"sentinel reached the dispatch\n",
				(unsigned long)c->pid, nr, nr, d->regs.rip,
				d->regs.rsp, bq);
		}
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
	/* M5.4 c3 diag: feed the SIGSEGV print (stub_ctl.c) — see the
	 * conn field comment. */
	c->last_nr = nr;
	c->last_ret = ret;
	/* The __abort_msg candidate ring (see abrt_mmap_note): every
	 * successful mmap is one entry — the fatal-message mapping is
	 * the last one before the ABRT tgkill trap. */
	if (nr == 9 && (long long)ret > 0)
		abrt_mmap_note(c, ret);
	/* Map 049 item 3 — the ABRT census: init dies "Caught <ABRT>
	 * (si_pid=1)" with NO assert text anywhere on the console
	 * (SYSTEMD_LOG_TARGET=console confirmed nothing routes past
	 * it). glibc abort()/raise() reach the kernel as tgkill(234)/
	 * kill(62) with sig==6, and every aborter installs SIGABRT
	 * (rt_sigaction 13) first — name the raiser's task + the
	 * syscall round in the log. */
	if ((nr == 234 && a[2] == 6) || (nr == 62 && a[1] == 6)) {
		/* Follow-up (run 36863167824): init STILL aborts with
		 * no assert or malloc text — the kmsg relay surfaced
		 * 2 systemd[1]: lines all boot, so the text is
		 * presumed lost in transit and the return-address
		 * chain is the only witness left. glibc abort() ->
		 * raise() -> tgkill trap puts abort()'s caller (the
		 * code that DECIDED to abort) one frame up the guest
		 * stack. Dump [rsp, rsp+0x120) at the trap — the frame
		 * math against the base-image libc 2.36: pthread_kill
		 * frame 0x38 + ret-to-raise 0x8 + raise's rbx 0x8 +
		 * ret-to-abort 0x8 + abort's frame 0xb8 = the abort
		 * CALLER's return address at trap_rsp+0x108. Decode
		 * the qwords offline against the rootfs binaries. */
		unsigned long long q[36];
		unsigned long long msg_va = 0;
		long long off;
		int i;

		os_info("[abrt] raise: nr=%llu a0=0x%llx a1=0x%llx -> %lld "
			"(task %d comm=%.16s)\n", nr, a[0], a[1],
			(long long)ret,
			current ? current->pid : 0,
			current ? current->comm : "(none)");
		off = uml_nt_vma_translate(c->mm, d->regs.rsp, sizeof(q));
		if (off >= 0) {
			memcpy(q, (char *)uml_boot.physmem_base + off,
			       sizeof(q));
			for (i = 0; i < 36; i += 4)
				os_info("[abrt]   rip=0x%llx [rsp+0x%02x]: "
					"0x%llx 0x%llx 0x%llx 0x%llx\n",
					d->regs.rip, i * 8, q[i], q[i + 1],
					q[i + 2], q[i + 3]);
			msg_va = q[4];
		} else {
			os_info("[abrt]   rip=0x%llx rsp=0x%llx stack "
				"untranslatable (%lld)\n", d->regs.rip,
				d->regs.rsp, off);
		}
		/* Astra request §2 — the predicate capture. msg_va =
		 * [rsp+0x20] = the __abort_msg pointer (both the PID1
		 * decode and every child dump agree on that slot). */
		abrt_msg_capture(c, msg_va);
		/* [cowtrap] follow-up (run 37054050100): the heapwalk
		 * spanned [0x67c00000,0x67d30000) while every logged
		 * brk grow stopped at 0x67c50000 — the arena VMA at
		 * [0x67d00000,...) sat inside the WALK's range. Name
		 * the bookkeeping at the abort so a walk that reads
		 * an adjacent arena as heap chunks is visible in the
		 * same boot. */
		os_info("[abrt] heap bookkeeping: start=0x%llx "
			"end=0x%llx brk=0x%llx nvma=%d\n",
			c->mm->heap_start, c->mm->heap_end,
			c->mm->brk, c->mm->nvma);
	} else if (nr == 13 && a[0] == 6 && c->task_backed)
		os_info("[abrt] sigaction SIGABRT act=0x%llx -> %lld "
			"(task %d)\n", a[1], (long long)ret,
			current ? current->pid : 0);
	/* M5.4 c3: the negative-retval census. Run 36800430061's
	 * dominant kill (28 SIGSEGVs, all at one libc memmove/strlen
	 * rip, faulting through a 0xffffffffffffffff pointer/length)
	 * = a guest consumer feeding a syscall's -1 into a length.
	 * glibc's own wrappers check (unsigned jae -4095), so the
	 * suspect is a raw-syscall user fed an unexpected errno. Log
	 * every DISTINCT (nr, errno) pair once — run 36804503133
	 * burned all 32 lines on init's routine openat/newfstatat
	 * ENOENT probing because the consecutive-pair dedup never
	 * fired on an alternating pattern; a global seen-table
	 * collapses that to a handful and the budget survives to the
	 * interesting tail of the boot. */
	{
		static unsigned long long seen[32][2];
		static int nseen, nlogged;

		if ((long long)ret < 0 && (long long)ret > -512) {
			unsigned long long err =
				(unsigned long long)(-(long long)ret);
			int i, found = 0;

			for (i = 0; i < nseen; i++) {
				if (seen[i][0] == nr && seen[i][1] == err) {
					found = 1;
					break;
				}
			}
			if (!found && nlogged < 32) {
				if (nseen < 32) {
					seen[nseen][0] = nr;
					seen[nseen][1] = err;
					nseen++;
				}
				nlogged++;
				os_info("[syscall] neg-retval #%d: nr=%llu "
					"-> %lld (task %d)\n",
					nlogged, nr, (long long)ret,
					current ? current->pid : 0);
			}
		}
	}
	if (c->plan.n_ops > 0) {
		/* The syscall carries stub ops: park the return value —
		 * the op results travel through d->retval and the plan
		 * re-publishes ours on the final NONE. K6 (cowcopy-
		 * race-class-fix): the test is the PLAN CONTENT, not
		 * plan_left — a round whose only view ops were uaccess
		 * COW fixups (uacc_plan_op appends without arming)
		 * left plan_left == 0, the retval never parked, and
		 * the ops never streamed: the fixup's cow_split had
		 * already moved the table while the stale view kept
		 * serving guest stores into the abandoned backing (the
		 * dl26 37539992560 conviction class). The tail's
		 * uml_nt_view_release_complete arms the stream from
		 * the same count. */
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
		/* M5.4 c3 (map 057): the walker records WHERE (pure
		 * globals — uaccess_walk.c can't log). Round-correlated
		 * with the fork-residue cluster in run 36854409213. */
		os_info("[stubtest]   cow-fixup: vma [0x%llx,0x%llx) "
			"run 0x%llx -> 0x%llx (write va=0x%llx "
			"page=0x%llx)\n",
			uml_nt_uacc_fixup_vma_start,
			uml_nt_uacc_fixup_vma_end,
			uml_nt_uacc_fixup_old_run,
			uml_nt_uacc_fixup_new_run,
			uml_nt_uacc_fixup_va,
			uml_nt_uacc_fixup_page);
	}
out:
	uml_nt_uacc_set_mm(uacc_prev_mm);
	uml_nt_uacc_set_nr(uacc_prev_nr);
	uml_nt_uacc_set_sink(&uacc_prev_sink);
}
