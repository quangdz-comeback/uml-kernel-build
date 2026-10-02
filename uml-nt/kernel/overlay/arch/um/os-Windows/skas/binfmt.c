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
 * The S3 scope (argc=0) grew up in S4: the exec strings —
 * copy_strings packs them into the bprm mm's stack pages (generic:
 * the kernel-side page machinery works, it is the STUB views that
 * needed the D17 parallel) — are read back through the new mm
 * (upstream create_elf_tables reads the same pages post-switch),
 * split (elf_split.c) and re-placed on OUR stack run with the real
 * argv/envp vectors. CONFIG_BINFMT_ELF is OFF under OS_WINDOWS
 * (defconfig): its pte-backed load path has no stub backing — the
 * image it "loaded" would fault as soon as the stub jumped there.
 *
 * D1: freestanding — HANDLE = void*, NT only through the D9 table.
 */
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
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
 * header yet). M5.1c.6b: `mark` = caller scratch (>= len bytes) —
 * the patcher's alloca(len) buried the neighbouring task stacks on
 * whole-image execs (see scan_patch.c). */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off, void *mark);

/* Sanity cap for the packed exec-string blob (copy_strings already
 * enforced RLIMIT_STACK + MAX_ARG_STRLEN per string; this only stops
 * a bogus layout from kvmalloc'ing wild). */
#define UML_NT_ELF_ARG_BLOB_MAX (1ull << 20)

/* The brk heap's VA headroom, carved at the TOP of the guest VA
 * window (binfmt places the 1-run heap VMA there; sys_brk grows it
 * upward within the reserve). 64 runs = 4MB — a systemd boot's heap
 * on Linux peaks ~2-4MB; past it glibc takes its mmap-arena
 * fallback. The loader's bottom-up find_free fill never reaches the
 * top of the window in a boot (~20MB of 64 in run 36787150906), so
 * the heap's growth range stays free — the mid-space island the
 * identity VA created got surrounded and its first grow failed
 * "VMA resize failed — kept", twice, in that run. */
#define UML_NT_HEAP_VA_RESERVE (64ull * UML_NT_PHYS_RUN_SIZE)

/* S4: read the packed exec-string blob through the mm whose pages
 * copy_strings wrote (the bprm mm — the conn's kernel mm; passed
 * explicitly because the tables build PRE-commit now, where
 * current->mm is still the OLD mm), split it (elf_split.c) and build
 * the SysV block on OUR stack run. *used_out = bytes consumed
 * (rsp = stack_top - used_out). `ax` carries the D20 auxv fields. */
static int uml_nt_elf_wire_args(struct linux_binprm *bprm,
				struct mm_struct *mm, char *dst,
				unsigned long long va_base,
				unsigned long long cap,
				const unsigned char *rand16,
				const struct uml_nt_elf_auxv *ax,
				long long *used_out)
{
	unsigned long long blob_len, fn_len, done = 0, npages;
	struct page **pages;
	const char **argv;
	const char **envp;
	unsigned char *blob;
	int locked = 1; /* the GUP external contract: locked starts 1 */
	int rc;

	fn_len = strlen(bprm->filename) + 1;
	/* The blob = [bprm->p, bprm->exec + fn_len): argv strings
	 * lowest, then envp, the filename highest (copy_strings packs
	 * backward from the stack top). exec >= p always; the splitter
	 * validates the string counts against the bytes. */
	if ((unsigned long long)bprm->exec < (unsigned long long)bprm->p)
		return -EINVAL; /* layout changed upstream — fail loud */
	blob_len = (unsigned long long)bprm->exec + fn_len -
		   (unsigned long long)bprm->p;
	if (blob_len > UML_NT_ELF_ARG_BLOB_MAX ||
	    bprm->argc + bprm->envc + 1 > UML_NT_ELF_MAX_STR)
		return -E2BIG;

	pages = kvmalloc_array((blob_len >> PAGE_SHIFT) + 2,
			       sizeof(*pages), GFP_KERNEL);
	blob = kvmalloc(blob_len, GFP_KERNEL);
	argv = kvmalloc_array((unsigned long)bprm->argc + 1,
			      sizeof(*argv), GFP_KERNEL);
	envp = kvmalloc_array((unsigned long)bprm->envc + 1,
			      sizeof(*envp), GFP_KERNEL);
	if (pages == NULL || blob == NULL || argv == NULL || envp == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	/* Upstream GUP contract: the caller holds mm->mmap_lock for the
	 * duration (get_user_pages_remote asserts it via
	 * mmap_assert_locked — find_vma, __get_user_pages and the outer
	 * layer each WARN'd rwsem.h:80 per call on this port, because
	 * nothing here ever took the lock; the UML mm's rw_semaphore is
	 * a real, initialized lock — take it like upstream does). */
	mmap_read_lock(mm);
	while (done < blob_len) {
		unsigned long long pg_va =
			((unsigned long long)bprm->p + done) & PAGE_MASK;
		unsigned long long pg_len = PAGE_SIZE;
		char *kaddr;
		struct page *page;
		long long got;

		if (blob_len - done < pg_len)
			pg_len = blob_len - done;
		got = get_user_pages_remote(mm, pg_va, 1,
					    FOLL_FORCE, &page, &locked);
		if (got != 1) {
			os_info("binfmt_umlnt: arg gup va=0x%llx got=%d "
				"(p=0x%lx exec=0x%lx len=%llu)\n", pg_va,
				(int)got, bprm->p, bprm->exec, blob_len);
			rc = -EFAULT;
			break;
		}
		/* UML: pages live in the one flat kernel mapping —
		 * page_address() IS the host-mapped bytes (no highmem
		 * window to set up). */
		memcpy(blob + done, page_address(page) +
		       (((unsigned long long)bprm->p + done) & ~PAGE_MASK),
		       pg_len);
		put_page(page);
		done += pg_len;
	}
	mmap_read_unlock(mm);
	if (rc)
		goto out;

	rc = uml_nt_elf_split_args(blob, blob_len, bprm->argc, bprm->envc,
				   argv, envp);
	if (rc) {
		rc = -EINVAL; /* counts disagree with the blob */
		goto out;
	}
	argv[bprm->argc] = NULL;
	envp[bprm->envc] = NULL;

	*used_out = uml_nt_elf_stack_tables(dst, va_base, cap, bprm->argc,
					    argv, envp, rand16, ax);
	rc = *used_out < 0 ? -E2BIG : 0;
out:
	kvfree(envp);
	kvfree(argv);
	kvfree(blob);
	kvfree(pages);
	return rc;
}

/* Static init ceiling: the ext4 image is read whole into kernel
 * memory; a guest binary beyond 8 MiB is not the POC shape. */
#define UML_NT_BINFMT_MAX_FILE (8ull << 20)

static int uml_nt_load_binary(struct linux_binprm *bprm);

/* D20 cluster 1: read the interpreter file whole (same shape + cap as
 * the main image read — the bytes are all the loader needs; the file
 * is dropped right after the load). NULL = open/read failure. */
static char *uml_nt_read_interp(const char *path,
				unsigned long long *len_out)
{
	struct file *f;
	loff_t fsize, pos = 0;
	char *buf;
	long long rc;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return NULL;
	fsize = i_size_read(file_inode(f));
	if (fsize <= 0 || fsize > UML_NT_BINFMT_MAX_FILE) {
		filp_close(f, NULL);
		return NULL;
	}
	buf = kvmalloc(fsize, GFP_KERNEL);
	if (buf == NULL) {
		filp_close(f, NULL);
		return NULL;
	}
	rc = kernel_read(f, buf, fsize, &pos);
	filp_close(f, NULL);
	if (rc < 0 || (unsigned long long)rc != (unsigned long long)fsize) {
		kvfree(buf);
		return NULL;
	}
	*len_out = (unsigned long long)fsize;
	return buf;
}

/* Central patch contract §5.1, per image: every `syscall` in
 * exec-only regions becomes ud2 before any stub view maps the pages.
 * M5.1c.6b: the mark scratch is a real allocation — a whole busybox
 * text segment is 0x30000, three times the kernel stack the old
 * alloca burned through. Negative = mark alloc failure. */
static long long uml_nt_patch_image(const struct uml_nt_elf_image *im)
{
	unsigned long long total = 0;
	int si;

	for (si = 0; si < im->nseg; si++) {
		unsigned long long slen, mk;

		if (!uml_nt_prot_execable(im->seg[si].prot))
			continue;
		slen = im->seg[si].end - im->seg[si].start;
		mk = (unsigned long long)(uintptr_t)
		     kvmalloc(slen, GFP_KERNEL);
		if (mk == 0) {
			os_info("binfmt_umlnt: patch mark alloc failed "
				"(%llu bytes)\n", slen);
			return -ENOMEM;
		}
		total += uml_nt_patch_syscalls(
			uml_boot.physmem_base + im->seg[si].run_off,
			slen, 0, (void *)(uintptr_t)mk);
		kvfree((void *)(uintptr_t)mk);
	}
	return (long long)total;
}

static struct linux_binfmt uml_nt_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = uml_nt_load_binary,
};

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
	struct uml_nt_elf_image img, iimg;
	const struct cred *cr;
	struct uml_nt_elf_auxv ax;
	unsigned long long len, interp_len = 0, stack_top, heap_va, patched;
	unsigned long long entry;
	loff_t fsize, pos = 0;
	unsigned char rnd[16];
	struct uml_nt_vma *stk;
	char *buf, *interp_buf = NULL;
	char interp_path[256];
	long long used, heap_off;
	int rc, have_interp = 0;

	/* No conn = the mm never got the NT lifecycle (no stub path
	 * configured — init_new_context already failed the exec before
	 * the binfmt search; this is belt-and-suspenders). */
	if (bprm->mm == NULL || id->nt_conn == NULL)
		return -ENOEXEC;
	c = id->nt_conn;
	/* S4c2: os_info is a DIRECT console write (reliable append
	 * order, unlike the printk WARN batches) — this pins which
	 * exec the following prints belong to when the log interleaves
	 * three execs. */
	os_info("binfmt_umlnt: load_binary %s (conn pid %d)\n",
		bprm->filename, c->pid);

	fsize = i_size_read(file_inode(bprm->file));
	if (fsize <= 0 || fsize > UML_NT_BINFMT_MAX_FILE)
		return -ENOEXEC;
	len = (unsigned long long)fsize;
	os_info("binfmt_umlnt: loading %s (%llu bytes)\n", bprm->filename,
		len);

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
	os_info("binfmt_umlnt: read %llu bytes\n", len);
	rc = uml_nt_elf_sniff(buf, len);
	if (rc) {
		kvfree(buf);
		return rc;
	}
	os_info("binfmt_umlnt: sniff ok, committing exec\n");

	/* D20 cluster 1: PT_INTERP — a dynamic binary names its starter.
	 * Parse + read NOW, while a failure is still recoverable
	 * (-ENOEXEC keeps the binfmt search honest); like the main
	 * image, the LOAD itself runs pre-commit (recoverable). */
	interp_path[0] = '\0';
	rc = uml_nt_elf_interp_path(buf, len, interp_path,
				    sizeof(interp_path));
	if (rc < 0) {
		os_info("binfmt_umlnt: broken PT_INTERP\n");
		kvfree(buf);
		return -ENOEXEC;
	}
	if (rc == 1) {
		os_info("binfmt_umlnt: interp %s requested\n", interp_path);
		interp_buf = uml_nt_read_interp(interp_path, &interp_len);
		if (interp_buf == NULL) {
			os_info("binfmt_umlnt: interp %s read failed\n",
				interp_path);
			kvfree(buf);
			return -ENOEXEC;
		}
	}

	/* ---- PRE-COMMIT: every fallible step (upstream elf_map
	 * parity — the load builds into the bprm mm BEFORE the exec
	 * commits). On any failure the exec returns, the binfmt search
	 * continues, and the bprm mm dies with its fresh conn
	 * (destroy_context → mmctx destroy unrefs every run) — the
	 * old conn never noticed. Post-commit only the
	 * upstream-shape infallible tail remains. */
	memset(&img, 0, sizeof(img));
	rc = uml_nt_elf_load(&img, c->mm, c->ph, buf, len,
			     uml_boot.physmem_base);
	kvfree(buf);
	if (rc != UML_NT_ELF_OK) {
		os_info("binfmt_umlnt: load failed rc=%d\n", rc);
		/* WRITER-HUNT (M5.6a): the pure loader parks the fill
		 * guard's context in the globals — print them here. */
		if (rc == UML_NT_ELF_FILL)
			os_info("[fillguard] elf load region %d: "
				"off=0x%llx len=%llu leaves the "
				"block\n", uml_nt_elf_fill_region,
				uml_nt_elf_fill_off,
				uml_nt_elf_fill_len);
		/* D21: NOMEM is a resource failure, not a format one —
		 * execve must report -ENOMEM. Converting it to -ENOEXEC
		 * masks the physalloc root cause AND breaks systemd's
		 * exec retry logic (ENOEXEC means "no handler for this
		 * file"; ENOMEM means retry/later may succeed). */
		if (rc == UML_NT_ELF_NOMEM)
			return -ENOMEM;
		return -ENOEXEC;
	}
	os_info("binfmt_umlnt: elf mapped %d region(s), entry 0x%llx\n",
		img.nseg, img.entry);

	/* D20 cluster 1: the interpreter loads as a SECOND image —
	 * ET_DYN first-fit above the main regions (D12); the ENTRY
	 * becomes the interp's (the starter runs first and jumps to
	 * AT_ENTRY, which points at the main image). */
	have_interp = (interp_buf != NULL);
	if (have_interp) {
		memset(&iimg, 0, sizeof(iimg));
		rc = uml_nt_elf_load(&iimg, c->mm, c->ph, interp_buf,
				     interp_len, uml_boot.physmem_base);
		kvfree(interp_buf);
		interp_buf = NULL;
		if (rc != UML_NT_ELF_OK) {
			os_info("binfmt_umlnt: interp load failed rc=%d\n",
				rc);
			/* WRITER-HUNT (M5.6a): the fill guard's context
			 * (pure loader parks it in the globals). */
			if (rc == UML_NT_ELF_FILL)
				os_info("[fillguard] elf interp load "
					"region %d: off=0x%llx "
					"len=%llu leaves the block\n",
					uml_nt_elf_fill_region,
					uml_nt_elf_fill_off,
					uml_nt_elf_fill_len);
			if (rc == UML_NT_ELF_NOMEM)
				return -ENOMEM;
			return -ENOEXEC;
		}
		os_info("binfmt_umlnt: interp loaded base 0x%llx entry "
			"0x%llx\n", iimg.base, iimg.entry);
	}
	entry = have_interp ? iimg.entry : img.entry;

	rc = uml_nt_elf_stack_place(&img, c->mm, c->ph, &stack_top);
	if (rc != UML_NT_ELF_OK) {
		os_info("binfmt_umlnt: stack place failed rc=%d\n", rc);
		return -ENOMEM;
	}

	/* Initial stack block with the REAL argv/envp (S4): read the
	 * packed string blob copy_strings left in the bprm mm's stack
	 * pages (GUP on the bprm mm explicitly — pre-commit,
	 * current->mm is still the old mm), split it, and let the
	 * tables re-place it on OUR run with the guest-VA vectors
	 * (the create_elf_tables analogue). */
	stk = uml_nt_vma_find(c->mm, stack_top - 1);
	if (stk == NULL)
		return -ENOEXEC;
	get_random_bytes(rnd, sizeof(rnd));
	/* D20 cluster 1: the auxv a starter needs — AT_BASE points at
	 * the interp (0 static), AT_ENTRY/AT_PHDR at the MAIN image.
	 * The ids come from bprm->cred (the prepared exec cred —
	 * current_cred() is still the OLD one pre-commit). */
	memset(&ax, 0, sizeof(ax));
	ax.at_base = have_interp ? iimg.base : 0;
	ax.at_entry = img.entry;
	ax.at_phdr = img.phdr_va;
	ax.at_phnum = img.phnum;
	ax.execfn = bprm->filename;
	cr = bprm->cred;
	ax.uid = cr->uid.val;
	ax.euid = cr->euid.val;
	ax.gid = cr->gid.val;
	ax.egid = cr->egid.val;
	ax.secure = bprm->secureexec ? 1 : 0;
	os_info("binfmt_umlnt: wiring stack tables (run_off %#llx)\n",
		stk->run_off);
	/* The stack VMA's run must be a REAL section offset: a garbage
	 * run_off (seen 0xffffffffffffffff on run 36789783203's
	 * systemd-run-generator exec — the buddy was order-10 starved:
	 * mem= defaults to 64M while the section is 128 MiB) reaches
	 * the wire as physmem_base + (-1) — a wild kernel write, and
	 * the INIT plan's MAP op fails with the conn killed (the
	 * "exit status 127" generator class). Fail the exec cleanly
	 * instead: the task exits, systemd logs and moves on. */
	if (stk->run_off >= uml_boot.physmem_size) {
		int di;

		os_info("binfmt_umlnt: stack run_off %#llx insane — mm "
			"dump (%d vma(s)):\n", stk->run_off,
			c->mm->nvma);
		for (di = 0; di < c->mm->nvma; di++)
			os_info("  vma[%d] [0x%llx,0x%llx) run_off=%#llx "
				"prot=0x%x flags=0x%x\n", di,
				c->mm->vma[di].start,
				c->mm->vma[di].end,
				c->mm->vma[di].run_off,
				c->mm->vma[di].prot,
				c->mm->vma[di].flags);
		return -ENOMEM;
	}
	/* WRITER-HUNT (M5.6a): the stack tables' bulk fill rides this
	 * run — refuse the exec if its span is rotten (the direct-
	 * write tripwire; the pure table code has no logger). */
	if (uml_nt_phys_block_check(c->ph, (long long)stk->run_off,
				    UML_NT_PHYS_RUN_SIZE) < 0) {
		os_info("[fillguard] stack run off=0x%llx leaves the "
			"block — exec refused\n", stk->run_off);
		return -ENOMEM;
	}
	rc = uml_nt_elf_wire_args(bprm, bprm->mm,
				  (char *)uml_boot.physmem_base +
				  stk->run_off,
				  stack_top - UML_NT_PHYS_RUN_SIZE,
				  UML_NT_PHYS_RUN_SIZE, rnd, &ax, &used);
	if (rc) {
		os_info("binfmt_umlnt: stack tables failed rc=%d\n", rc);
		return rc;
	}
	/* WRITER-HUNT (M5.6a) provenance ledger: the exec's stack-top
	 * image (argv/env vectors + strings) is the one structure the
	 * victim dumps keep matching byte-for-byte (the "US.UTF-8"
	 * qword sits in a .data run whose peer generation holds a
	 * relocated pointer). The tail 16 bytes = the execfn's tail —
	 * a fingerprint that ties a poisoned run back to THE exec
	 * that wrote it (plus this line's run_off). */
	{
		const unsigned char *fp =
			(const unsigned char *)
			((char *)uml_boot.physmem_base + stk->run_off +
			 UML_NT_PHYS_RUN_SIZE - 16);
		char hex[49];
		int hi;

		for (hi = 0; hi < 16; hi++)
			snprintf(hex + hi * 3, sizeof(hex) - hi * 3,
				 "%02x ", fp[hi]);
		os_info("[wire] run_off=%#llx used=%llu fp=%s\n",
			stk->run_off, (unsigned long long)used, hex);
	}

	/* Central patch contract §5.1: every `syscall` in exec-only
	 * regions becomes ud2 before any stub view maps the pages —
	 * BOTH images now (the interp is exec code that traps like
	 * any other). */
	patched = 0;
	{
		long long p = uml_nt_patch_image(&img);

		if (p < 0)
			return (int)p;
		patched = (unsigned long long)p;
	}
	if (have_interp) {
		long long p = uml_nt_patch_image(&iimg);

		if (p < 0)
			return (int)p;
		patched += (unsigned long long)p;
	}

	/* The M3.7 brk contract: one pre-reserved, pre-mapped heap run
	 * (brk past it re-homes the heap in a bigger contiguous span —
	 * syscall.c sys_brk, M4 slice 4).
	 *
	 * The heap VA is a TOP-OF-SPACE reserve, NOT the identity
	 * base+phys_off: the buddy's position for the run says nothing
	 * about VA space, and the loader's find_free fills upward from
	 * the image — a mid-space heap island got surrounded on both
	 * sides and the first brk grow failed "VMA resize failed —
	 * kept" (run 36787150906, twice: the heap never grew past its
	 * one run, glibc fell to mmap arenas for the rest of the
	 * boot). At the top with UML_NT_HEAP_VA_RESERVE of headroom,
	 * the loader's bottom-up fill (which consumed ~20MB of VA in
	 * that run against a 64MB window) cannot take the heap's
	 * growth range, and brk grows in place like Linux's
	 * [heap_start, brk) region does. On reserve exhaustion sys_brk
	 * keeps the old brk and glibc takes its mmap-arena fallback —
	 * the path the same run proved works. */
	heap_off = uml_nt_phys_alloc_span(c->ph, 1);
	if (heap_off < 0)
		return -ENOMEM;
	heap_va = UML_NT_GUEST_VA_BASE + uml_boot.physmem_size -
		  UML_NT_HEAP_VA_RESERVE;
	heap_va &= ~(UML_NT_PHYS_RUN_SIZE - 1);
	if (heap_va <= UML_NT_GUEST_VA_BASE ||
	    uml_nt_vma_add(c->mm, heap_va, heap_va + UML_NT_PHYS_RUN_SIZE,
			   (unsigned long long)heap_off,
			   UML_NT_PAGE_READWRITE, 0) < 0) {
		uml_nt_phys_unref(c->ph, heap_off);
		os_info("binfmt_umlnt: heap vma failed at 0x%llx\n",
			heap_va);
		return -ENOMEM;
	}
	c->mm->heap_start = heap_va;
	c->mm->heap_end = heap_va + UML_NT_PHYS_RUN_SIZE;
	c->mm->brk = heap_va;

	/* COMMIT the exec (de_thread + exec_mmap — upstream binfmt_elf
	 * order): the old conn dies here; only the infallible tail
	 * follows. */
	rc = begin_new_exec(bprm);
	if (rc)
		return rc;
	setup_new_exec(bprm);
	os_info("binfmt_umlnt: exec committed (new conn live)\n");
	rc = setup_arg_pages(bprm, STACK_TOP, 0 /* non-exec stack */);
	if (rc)
		return rc; /* upstream-shape post-commit failure: -ENOMEM
			    * kills the task, never the kernel */
	set_binfmt(&uml_nt_binfmt);

	/* start_thread = UML's own (arch/um/kernel/exec.c): entry +
	 * stack into current->thread.regs — kernel_init returns,
	 * new_thread_handler enters userspace() (S2) and the FIRST
	 * round bootstraps the conn from these regs (conn_bootstrap:
	 * d->init_regs + entry_va → stub applies after the INIT plan
	 * streams). D20: the entry is the INTERP's for a dynamic
	 * binary — the starter runs first and jumps to AT_ENTRY. */
	/* ELF_PLAT_INIT parity (upstream arch/x86/um/asm/elf.h zeroes
	 * BX,CX,DX,SI,DI,BP,AX,R8-R15 before START_THREAD at exec;
	 * fs/binfmt_elf.c:1375). binfmt_umlnt skipped it: conn_bootstrap
	 * fills the exec conn's init_regs from these very pt_regs, so a
	 * fork+exec child started its new image with the exec'ing
	 * task's live callee-saved regs — for a fork child, the PARENT
	 * fork-moment state (rip=_Fork+0x23's register cluster among
	 * them). Stack and heap are fresh-zeroed at exec (D11/D12), so
	 * registers were the ONLY fork residue that crossed the exec
	 * boundary; spilled by the new image's early frames, they are
	 * the deterministic _strv_env_merge/strcspn SIGSEGV cluster
	 * (M5.4 c3). Zero them like upstream — the SysV ABI promises
	 * the new image nothing about incoming GPRs. */
	{
		struct uml_pt_regs *r = &current_pt_regs()->regs;

		REGS_BX(r->gp) = 0;
		REGS_CX(r->gp) = 0;
		REGS_DX(r->gp) = 0;
		REGS_SI(r->gp) = 0;
		REGS_DI(r->gp) = 0;
		REGS_BP(r->gp) = 0;
		REGS_AX(r->gp) = 0;
		REGS_R8(r->gp) = 0;
		REGS_R9(r->gp) = 0;
		REGS_R10(r->gp) = 0;
		REGS_R11(r->gp) = 0;
		REGS_R12(r->gp) = 0;
		REGS_R13(r->gp) = 0;
		REGS_R14(r->gp) = 0;
		REGS_R15(r->gp) = 0;
	}
	start_thread(current_pt_regs(), entry, stack_top - used);

	os_info("binfmt_umlnt: init loaded: %d region(s)%s, entry 0x%llx, "
		"rsp 0x%llx, %llu syscall(s) patched, heap 0x%llx\n",
		img.nseg,
		have_interp ? " + interp" : "",
		entry, stack_top - used, patched, heap_va);
	return 0;
}

static int __init uml_nt_binfmt_init(void)
{
	register_binfmt(&uml_nt_binfmt);
	return 0;
}
fs_initcall(uml_nt_binfmt_init);
