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
#include <linux/uaccess.h>
#include <asm/futex.h>

#include <internal.h>
#include <uaccess_walk.h>

static struct uml_nt_mm *uacc_mm;

void uml_nt_uacc_set_mm(struct uml_nt_mm *mm)
{
	uacc_mm = mm;
}

struct uml_nt_mm *uml_nt_syscall_mm(void)
{
	return uacc_mm;
}

unsigned long raw_copy_from_user(void *to, const void __user *from,
				 unsigned long n)
{
	if (uml_nt_uacc_walk(uacc_mm, uml_boot.physmem_base,
			     (unsigned long long)(unsigned long)from, n,
			     to, UML_NT_UACC_FROM_GUEST) < 0)
		return n;
	return 0;
}

unsigned long raw_copy_to_user(void __user *to, const void *from,
			       unsigned long n)
{
	if (uml_nt_uacc_walk(uacc_mm, uml_boot.physmem_base,
			     (unsigned long long)(unsigned long)to, n,
			     (char *)from, UML_NT_UACC_TO_GUEST) < 0)
		return n;
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
	*uval = v;
	return 0;
}
