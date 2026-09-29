// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/binfmt.c — binfmt_umlnt (D17): the guest exec
 * handler. Upstream analogue: fs/binfmt_elf.c load_elf_binary —
 * do_execve runs for real (VFS + ext4/ubd, D13), the binfmt table
 * calls us for the guest binary.
 *
 * WHY a new binfmt (D17, approved 2026-09-29): upstream backs the
 * guest image through page tables (setup_arg_pages + elf_map into
 * bprm->mm) — on NT the stub's guest VA space is per-VMA VIEWS of
 * the physmem section (D10/D11, MapViewOfFile offset granularity
 * 64K), so pte-backed mappings cannot express it. binfmt_umlnt keeps
 * do_execve (bprm mm, copy_strings, exec_mmap — all generic) and
 * replaces ONLY the loader: uml_nt_elf_load (D11/D12 spans + VMA
 * tree in the conn the bprm mm spawned at init_new_context, S1)
 * + SysV stack tables + the central patch scan. NOT a parallel
 * protocol: kernel_init returns → new_thread_handler enters the S2
 * userspace() loop, which serves this conn through the same
 * stub_data/plan machinery the probe proved (INIT plan streams,
 * stub applies init_regs — written by start_thread below — and
 * jumps).
 *
 * Deliberate S3 scope: argv/envp strings are NOT copied onto the
 * guest stack yet (argc=0 — the static init reads nothing; the
 * tables are the real ABI so S4/busybox only wires bprm strings).
 * CONFIG_BINFMT_ELF is OFF under OS_WINDOWS (defconfig): its
 * pte-backed load path has no stub backing — the image it "loaded"
 * would fault as soon as the stub jumped there.
 *
 * D1: freestanding — HANDLE = void*, NT only through the D9 table.
 */
#include <linux/binfmts.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <asm/processor.h>
#include <elf.h>
#include <mm_id.h>
#include <skas.h>
#include <stub_nt.h>
#include <syscall.h>
#include <os.h>
#include "internal.h"

/* scan_patch.c (stub_ctl.c re-declares the same way — no shared
 * header yet) */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off);

static int uml_nt_load_binary(struct linux_binprm *bprm);

static struct linux_binfmt uml_nt_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = uml_nt_load_binary,
};

/* Static init ceiling: the ext4 image is read whole into kernel
 * memory; a guest binary beyond 8 MiB is not the POC shape. */
#define UML_NT_BINFMT_MAX_FILE (8ull << 20)

/* Header sniff BEFORE begin_new_exec: non-ELF files must return
 * -ENOEXEC so the binfmt search stays honest (and the failure stays
 * recoverable). Full validation happens in the loader after commit. */
static int uml_nt_elf_sniff(const void *buf, unsigned long long len)
{
	const unsigned char *b = buf;
	unsigned type, machine;

	if (len < 20)
		return -ENOEXEC;
	if (b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' ||
	    b[4] != 2 /* ELFCLASS64 */ || b[5] != 1 /* little-endian */)
		return -ENOEXEC;
	/* e_type (offset 16), e_machine (18) — unaligned-safe reads */
	type = b[16] | (b[17] << 8);
	machine = b[18] | (b[19] << 8);
	if ((type != 2 /*ET_EXEC*/ && type != 3 /*ET_DYN*/) ||
	    machine != 62 /*EM_X86_64*/)
		return -ENOEXEC;
	return 0;
}

static int uml_nt_load_binary(struct linux_binprm *bprm)
{
	struct mm_id *id = &bprm->mm->context.id;
	struct uml_nt_stub_conn *c;
	struct uml_nt_elf_image img;
	unsigned long long len, stack_top, heap_va, patched;
	loff_t fsize, pos = 0;
	unsigned char rnd[16];
	struct uml_nt_vma *stk;
	char *buf;
	long long used, heap_off;
	int rc, si;

	/* No conn = the mm never got the NT lifecycle (no stub path
	 * configured — init_new_context already failed the exec before
	 * the binfmt search; this is belt-and-suspenders). */
	if (bprm->mm == NULL || id->nt_conn == NULL)
		return -ENOEXEC;
	c = id->nt_conn;

	fsize = i_size_read(file_inode(bprm->file));
	if (fsize <= 0 || fsize > UML_NT_BINFMT_MAX_FILE)
		return -ENOEXEC;
	len = (unsigned long long)fsize;

	buf = kvmalloc(len, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;
	rc = kernel_read(bprm->file, buf, len, &pos);
	if (rc < 0 || (unsigned long long)rc != len) {
		os_info("binfmt_umlnt: short read (%lld/%llu)\n",
			(long long)rc, len);
		kvfree(buf);
		return -EIO;
	}
	rc = uml_nt_elf_sniff(buf, len);
	if (rc) {
		kvfree(buf);
		return rc;
	}

	/* Commit the exec (de_thread + exec_mmap — upstream binfmt_elf
	 * order); from here failures are fatal to the task, there is
	 * no unwinding to the old mm. */
	rc = begin_new_exec(bprm);
	if (rc) {
		kvfree(buf);
		return rc;
	}
	setup_new_exec(bprm);
	rc = setup_arg_pages(bprm, STACK_TOP, 0 /* non-exec stack */);
	if (rc)
		return rc; /* bprm strings stay unwired — S4 */

	set_binfmt(&uml_nt_binfmt);

	/* Load into the conn: spans (D12), bytes through the flat
	 * view, one VMA per merged region — the loader rolls back
	 * everything on failure. */
	memset(&img, 0, sizeof(img));
	rc = uml_nt_elf_load(&img, c->mm, c->ph, buf, len,
			     uml_boot.physmem_base);
	kvfree(buf);
	if (rc != UML_NT_ELF_OK) {
		os_info("binfmt_umlnt: load failed rc=%d\n", rc);
		return -ENOEXEC;
	}
	rc = uml_nt_elf_stack_place(&img, c->mm, c->ph, &stack_top);
	if (rc != UML_NT_ELF_OK) {
		os_info("binfmt_umlnt: stack place failed rc=%d\n", rc);
		return -ENOMEM;
	}

	/* Initial stack block (argc=0 for the S3 init; S4 wires bprm's
	 * argv/envp strings — the layout is final ABI either way). */
	stk = uml_nt_vma_find(c->mm, stack_top - 1);
	if (stk == NULL)
		return -ENOEXEC;
	get_random_bytes(rnd, sizeof(rnd));
	used = uml_nt_elf_stack_tables(
		(char *)uml_boot.physmem_base + stk->run_off,
		stack_top - UML_NT_PHYS_RUN_SIZE, UML_NT_PHYS_RUN_SIZE,
		0, NULL, NULL, rnd);
	if (used < 0) {
		os_info("binfmt_umlnt: stack tables overflow\n");
		return -E2BIG;
	}

	/* Central patch contract §5.1: every `syscall` in exec-only
	 * regions becomes ud2 before any stub view maps the pages. */
	patched = 0;
	for (si = 0; si < img.nseg; si++) {
		if (!uml_nt_prot_execable(img.seg[si].prot))
			continue;
		patched += uml_nt_patch_syscalls(
			uml_boot.physmem_base + img.seg[si].run_off,
			img.seg[si].end - img.seg[si].start, 0);
	}

	/* The M3.7 brk contract: one pre-reserved, pre-mapped heap run
	 * (buddy owes no adjacency — the heap never outgrows it until
	 * multi-run growth lands). */
	heap_off = uml_nt_phys_alloc_span(c->ph, 1);
	if (heap_off < 0)
		return -ENOMEM;
	heap_va = UML_NT_GUEST_VA_BASE + (unsigned long long)heap_off;
	if (uml_nt_vma_add(c->mm, heap_va, heap_va + UML_NT_PHYS_RUN_SIZE,
			   (unsigned long long)heap_off,
			   UML_NT_PAGE_READWRITE, 0) < 0) {
		uml_nt_phys_unref(c->ph, heap_off);
		return -ENOMEM;
	}
	c->mm->heap_start = heap_va;
	c->mm->heap_end = heap_va + UML_NT_PHYS_RUN_SIZE;
	c->mm->brk = heap_va;

	/* start_thread = UML's own (arch/um/kernel/exec.c): entry +
	 * stack into current->thread.regs — kernel_init returns,
	 * new_thread_handler enters userspace() (S2) and the FIRST
	 * round bootstraps the conn from these regs (conn_bootstrap:
	 * d->init_regs + entry_va → stub applies after the INIT plan
	 * streams). */
	start_thread(current_pt_regs(), img.entry, stack_top - used);

	os_info("binfmt_umlnt: init loaded: %d region(s), entry 0x%llx, "
		"rsp 0x%llx, %llu syscall(s) patched, heap 0x%llx\n",
		img.nseg, img.entry, stack_top - used, patched, heap_va);
	return 0;
}

static int __init uml_nt_binfmt_init(void)
{
	register_binfmt(&uml_nt_binfmt);
	return 0;
}
fs_initcall(uml_nt_binfmt_init);
