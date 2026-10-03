// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/main.c — UML host-process entry.
 * Upstream: linux v6.18.37 arch/um/os-Linux/main.c
 *
 * Launcher.exe maps vmlinux.elf (ET_EXEC, D2), builds uml_boot_info on
 * the stack and jumps to _start with [rsp] = boot-info pointer (D9).
 * The bootstrap mirrors the upstream main() shape: validate the handoff,
 * then linux_main() (kernel/um_arch.c) — which itself runs start_uml()
 * → start_kernel(). The malloc __wrap_* interposers upstream are dead
 * here (D1): the kernel heap is RtlAllocateHeap via the D9 table.
 */
#include <linux/init.h>
#include <linux/types.h>
#include <ntabi.h>
#include <os.h>
#include <vma.h>
#include "boot-info.h"
#include "internal.h"

struct uml_boot_info uml_boot;
struct uml_nt_api_table *nt;

extern int linux_main(int argc, char **argv, char **envp);

__attribute__((naked)) void _start(void)
{
	/* [rsp] = boot-info pointer; nt_main is SysV (kernel ELF, D2):
	 * first arg travels in %rdi. sub $8 mimics call-alignment
	 * (rsp%16==8 at a normal function entry) — nt_main is compiled
	 * with standard SysV assumptions. */
	__asm__ volatile(
		"movq (%rsp), %rdi\n\t"
		"subq $8, %rsp\n\t"
		"jmp nt_main\n\t");
}

/* no-header decl (kernel-side, um_arch.c) — mirrors upstream main.c */
extern void os_dump_core(void) __attribute__((noreturn));

void nt_main(struct uml_boot_info *bi)
{
	if (bi == NULL)
		os_dump_core();
	if (bi->magic != UML_BOOT_MAGIC || bi->version != UML_BOOT_VERSION)
		os_dump_core();

	nt = bi->api;
	if (nt == NULL || nt->version != UML_NT_API_VERSION ||
	    nt->size < sizeof(*nt))
		os_dump_core();

	/* Table validated — from here every native fault is LOUD
	 * (upstream: the UML process's SIGSEGV kernel-fault handler). */
	uml_nt_install_crash_reporter();

	/* Copy the handoff out of the launcher-controlled stack area. */
	uml_boot = *bi;

	/* The translate boundary is the physmem window itself (048):
	 * every legit run offset lives below physmem_size by
	 * construction — the phys run table covers exactly that many
	 * bytes. Anything at/above it is a rotten-VMA read. */
	uml_nt_vma_phys_limit = uml_boot.physmem_size;

	/* Map 049: phys refcount events (block free / unbalanced drop /
	 * backend double-alloc) go to the console log — the run
	 * 0x28b0000 double-claim class names its thief this way. */
	uml_nt_phys_event = uml_nt_phys_event_log;

	/* Map 121: every fresh handout crosses the live-VMA scan — a
	 * stale translation into the new range names the
	 * alloc-over-live-run writer (heap-trasher family). */
	uml_nt_alloc_alias_probe = uml_nt_alloc_alias_scan;

	linux_main(uml_boot.argc, uml_boot.argv, uml_boot.envp);

	/* linux_main runs start_uml() → start_kernel() → (M1) panic
	 * "No filesystem could mount root". Nothing below is reached. */
	os_dump_core();
}

int main(int argc, char **argv, char **envp)
{
	/* Host-main of upstream; on NT the launcher is the host — kept
	 * only so the symbol exists for section references. */
	os_dump_core();
}
