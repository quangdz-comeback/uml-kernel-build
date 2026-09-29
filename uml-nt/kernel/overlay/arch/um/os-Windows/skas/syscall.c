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
#include <linux/string.h>

#include <os.h>
#include <internal.h>
#include <stub-panic.h>
#include <stub_nt.h>
#include <syscall.h>
#include <uaccess_walk.h>

#define UML_NT_SYSCALLS_BASE UML_STUB_RAM_BASE

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

/* Prime a one-op plan for the syscall answer (the stub executes it
 * in its own address space, exactly like a fault repair). */
static void sc_plan1(struct uml_nt_stub_conn *c, unsigned op, unsigned prot,
		     unsigned long long va, unsigned long long len,
		     unsigned long long off)
{
	c->plan.kill = 0;
	c->plan.n_ops = 1;
	c->plan.ops[0].op = op;
	c->plan.ops[0].prot = prot;
	c->plan.ops[0].va = va;
	c->plan.ops[0].len = len;
	c->plan.ops[0].off = off;
	c->plan.copy_src_off = 0;
	c->plan.copy_dst_off = 0;
	c->plan_next = 0;
	c->plan_left = 1;
}

static int overlaps(const struct uml_nt_mm *mm, unsigned long long s,
		    unsigned long long e)
{
	int i;

	for (i = 0; i < mm->nvma; i++) {
		if (s < mm->vma[i].end && e > mm->vma[i].start)
			return 1;
	}
	return 0;
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
	return a[2];
}

/* brk(2): the mm owns a pre-reserved, pre-mapped heap run (set up by
 * the exec path — the buddy cannot promise an ADJACENT block, so the
 * heap never outgrows its reservation; out-of-room = -ENOMEM loud
 * until M3.8 wires multi-run growth). Linux returns the CURRENT brk
 * (not an errno) on failure. */
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
	if (a[0] < mm->heap_start || a[0] > mm->heap_end) {
		os_info("[syscall] brk 0x%llx outside reserved heap "
			"[0x%llx, 0x%llx] — kept 0x%llx\n",
			a[0], mm->heap_start, mm->heap_end, mm->brk);
		return mm->brk;
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
		va = addr;
		if ((va & (UML_NT_PHYS_RUN_SIZE - 1)) ||
		    overlaps(c->mm, va, va + len)) {
			os_info("[syscall] mmap MAP_FIXED 0x%llx+%llu not "
				"a free run-aligned range\n", va, len);
			return SC_RET(SC_ENOMEM);
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
	sc_plan1(c, UML_NT_FOP_MAP, prot, va, len, (unsigned long long)sp);
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
	int i, j, nruns = 0;

	if (addr & (UML_NT_PHYS_RUN_SIZE - 1) || len == 0)
		return SC_RET(SC_EINVAL);
	len = (len + UML_NT_PHYS_RUN_SIZE - 1) &
	      ~(UML_NT_PHYS_RUN_SIZE - 1);
	for (i = 0; i < mm->nvma; i++) {
		unsigned long long s = mm->vma[i].start;
		unsigned long long e = mm->vma[i].end;
		unsigned long long ro = mm->vma[i].run_off;

		if (s >= addr + len || e <= addr)
			continue;
		if (s < addr || e > addr + len) {
			os_info("[syscall] munmap 0x%llx+%llu: partial "
				"VMA [0x%llx, 0x%llx) — unsupported "
				"(whole views only)\n", addr, len, s, e);
			return SC_RET(SC_EINVAL);
		}
		/* distinct backing runs only (adjacent VMAs may share
		 * one run — refcounts track contexts, not pieces) */
		for (j = 0; j < nruns && runs[j] != ro; j++)
			;
		if (j == nruns && nruns < UML_NT_VMA_MAX)
			runs[nruns++] = ro;
	}
	if (nruns == 0)
		return 0; /* unmapped range: Linux succeeds */
	if (uml_nt_vma_del(mm, addr, addr + len) < 0)
		return SC_RET(SC_ENOMEM);
	for (j = 0; j < nruns; j++) {
		int k;

		for (k = 0; k < (int)(len / UML_NT_PHYS_RUN_SIZE); k++)
			uml_nt_phys_unref(c->ph, (long long)runs[j] +
					  (long long)k *
					  UML_NT_PHYS_RUN_SIZE);
	}
	sc_plan1(c, UML_NT_FOP_UNMAP, 0, addr, len, 0);
	return 0;
}

/* mprotect(2), POC: single VMA, no COW (a real mprotect(RW) on a COW
 * VMA forces a private copy first — M4 with the signal work). */
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
	if (uml_nt_vma_chg(c->mm, addr, addr + len, prot) < 0)
		return SC_RET(SC_ENOMEM);
	sc_plan1(c, UML_NT_FOP_PROTECT, prot, addr,
		 len, 0);
	return 0;
}

/* rt_sigprocmask(2): signals are M4; the POC answers "mask was
 * empty" (zero the oldset the caller asked back) and succeeds. */
static unsigned long long sys_sigprocmask(struct uml_nt_stub_conn *c,
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

void uml_nt_syscall_handle(struct uml_nt_stub_conn *c,
			   struct uml_nt_stub_data *d)
{
	const unsigned long long *a = d->args;
	unsigned long long nr = d->regs.rax;
	unsigned long long ret;

	uml_nt_uacc_set_mm(c->mm);
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
	case 0: /* read — stdin/stdfile via the guest VFS (M3.8) */
		os_info("[syscall] read: not implemented (M3.8) → "
			"ENOSYS\n");
		ret = SC_RET(SC_ENOSYS);
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
	case 13: /* rt_sigaction — POC: succeed, no old-state writeback
		  * (musl reads oldact back only when querying) */
		ret = 0;
		break;
	case 14: /* rt_sigprocmask */
		ret = sys_sigprocmask(c, a);
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
		uml_nt_sys_fork(c, d); /* fork semantics (POC) */
		ret = d->retval;
		break;
	case 57: /* fork */
		uml_nt_sys_fork(c, d);
		ret = d->retval;
		break;
	case 61: /* wait4 */
		uml_nt_sys_wait4(c, d, a);
		ret = d->retval;
		break;
	case 218: /* set_tid_address */
		c->clear_tid_va = a[0];
		ret = c->pid;
		break;
	default:
		os_info("[syscall] nr=%llu not implemented → ENOSYS "
			"(add it: STATUS M3.7 order)\n", nr);
		ret = SC_RET(SC_ENOSYS);
		break;
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
out:
	uml_nt_uacc_set_mm(NULL);
}
