// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/mmctx.c — per-mm NT context lifecycle (S1).
 *
 * Upstream analogue: arch/um/kernel/skas/mmu.c init_new_context/
 * destroy_context — upstream allocates the stub_data pages, clones
 * the stub process (start_userspace) and tracks it on mm_list for
 * SIGCHLD reaping. On NT (D3/D10) the whole stub-side protocol state
 * lives in ONE conn (struct uml_nt_stub_conn) that this module
 * kzallocs into mm_id->nt_conn; the stub.exe process spawns
 * suspended (uml_nt_spawn_stub — the S5 pattern the probe uses).
 *
 * Upstream parity kept: init_new_context still runs from mm_init()
 * for EVERY new mm (bprm_mm_init at exec, dup_mm at fork) and
 * destroy_context from mmdrop — same call order, different
 * mechanics. mm_list/SIGCHLD-irq reaping is upstream-only (S4/M4:
 * the conn alive flag + explicit destroy cover the POC lifetime).
 *
 * Spawn safety (M2 pitfall 11): CreateProcessA burned >2 MB of stack
 * natively — the spawn runs on a dedicated fat NT thread, never on
 * a UML task stack (UML tasks are THREAD_SIZE switch stacks).
 *
 * D1: freestanding — every NT call goes through the D9 table, HANDLE
 * = void*, no windows.h.
 */
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <mm_id.h>
#include <ntabi.h>
#include <os.h>
#include <physalloc.h>
#include <stub_nt.h>
#include <syscall.h>
#include <vma.h>
#include "internal.h"

struct uml_nt_spawn_req {
	struct uml_nt_stub_conn *c;
	int rc;
};

/* Runs on its own fat thread: CreateProcessA needs the stack room
 * (M2 pitfall 11 — the boot/task stacks are 16 KB). */
static unsigned long __attribute__((ms_abi)) mmctx_spawn_thread(void *arg)
{
	struct uml_nt_spawn_req *req = arg;
	struct uml_nt_gp_regs init;

	/* No guest code yet: entry/stack/init stay zero until the
	 * owning task hands the conn its first state (binfmt, S3+).
	 * The stub stays suspended until then. */
	memset(&init, 0, sizeof(init));
	req->rc = uml_nt_spawn_stub(req->c, 0, 0, &init);
	return 0;
}

/* init_new_context body (CONFIG_OS_WINDOWS). Returns 0 on success,
 * -errno on failure — mm_init() aborts the mm (and the exec/fork)
 * exactly like the upstream start_userspace failure. */
int uml_nt_mmctx_init(struct mm_id *id)
{
	struct uml_nt_stub_conn *c;
	struct uml_nt_spawn_req req;
	struct uml_nt_phys *ph;
	struct uml_nt_mm *mm;
	ULONG tid;
	HANDLE th;

	id->nt_conn = NULL;
	id->pid = -1;

	if (uml_nt_stub_path() == NULL) {
		os_warn("mmctx: no stub path configured (uml_nt_stub=<exe>)\n");
		return -ENODEV;
	}

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	mm = kzalloc(sizeof(*mm), GFP_KERNEL);
	ph = kzalloc(sizeof(*ph), GFP_KERNEL);
	if (c == NULL || mm == NULL || ph == NULL)
		goto fail;

	/* Fresh address-space bookkeeping: empty VMA tree + a private
	 * refcount table over the SHARED buddy backend (the buddy owns
	 * exclusivity — the table only tracks runs this mm allocated;
	 * fork shares the PARENT's table via conn cloning, S3). */
	uml_nt_mm_init(mm);
	if (uml_nt_phys_init(ph, uml_boot.physmem_size) < 0) {
		os_warn("mmctx: phys run table init failed\n");
		goto fail;
	}
	c->mm = mm;
	c->ph = ph;

	/* Fat thread for CreateProcessA (pitfall 11); the spawn itself
	 * is CreateProcess(suspended) — S5 measured ~1ms. */
	req.c = c;
	req.rc = -1;
	th = nt->CreateThread(NULL, 0x2000000, mmctx_spawn_thread, &req,
			      0, &tid);
	if (th == NULL) {
		os_warn("mmctx: spawn thread failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		goto fail;
	}
	nt->NtWaitForSingleObject(th, 0, UML_NT_INFINITE);
	nt->CloseHandle(th);

	if (req.rc < 0) {
		os_warn("mmctx: stub spawn failed\n");
		goto fail;
	}

	id->nt_conn = c;
	id->pid = (int)c->pid;
	os_info("mmctx: stub spawned pid %d (suspended, entry pending)\n",
		id->pid);
	return 0;

fail:
	/* Tear down whatever was created (destroy walks the conn
	 * handle set as-soon-as-created, so this cannot leak). */
	if (c != NULL) {
		id->nt_conn = c;
		uml_nt_mmctx_destroy(id);
	}
	return -ENOMEM;
}

/* destroy_context body (CONFIG_OS_WINDOWS). nt_conn NULL = the mm
 * never got a conn (init_new_context never ran/completed) — the
 * upstream pid sanity check covers the same cases there. */
void uml_nt_mmctx_destroy(struct mm_id *id)
{
	struct uml_nt_stub_conn *c;

	if (id == NULL || id->nt_conn == NULL)
		return;
	c = id->nt_conn;

	/* Kernel owns the kill (M2.2 parity): the stub may still be
	 * suspended (never got guest code — the normal S1/S2 fate for
	 * an mm whose exec failed) or parked after a halt. */
	if (c->alive) {
		nt->NtTerminateProcess(c->proc, 0);
		c->alive = 0;
	}
	os_info("mmctx: destroy pid %d: stub terminated\n", id->pid);
	if (c->d != NULL)
		nt->UnmapViewOfFile(c->d);
	if (c->dsec != NULL)
		nt->CloseHandle(c->dsec);
	if (c->evt_in != NULL)
		nt->CloseHandle(c->evt_in);
	if (c->evt_out != NULL)
		nt->CloseHandle(c->evt_out);
	os_info("mmctx: destroy pid %d: section + events closed\n",
		id->pid);
	if (c->proc != NULL)
		nt->CloseHandle(c->proc);
	if (c->thread != NULL)
		nt->CloseHandle(c->thread);

	os_info("mmctx: stub pid %d destroyed\n", id->pid);
	kfree(c->mm);
	kfree(c->ph);
	kfree(c);
	id->nt_conn = NULL;
	id->pid = -1;
}
