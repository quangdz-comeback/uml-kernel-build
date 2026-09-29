/* SPDX-License-Identifier: GPL-2.0 */
/*
 * boot-info.h — launcher→kernel handoff contract (D9), uml-nt.
 *
 * launcher.exe (PE) resolves the NT API, maps vmlinux.elf at its ET_EXEC
 * address, builds this struct ON THE KERNEL STACK and jumps to _start
 * with [rsp] == struct uml_boot_info *. The kernel copies it out before
 * anything can clobber the stack. launcher/ and kernel/ include the same
 * header — layout drift fails loudly at boot (magic/version checks).
 */
#ifndef __UML_BOOT_INFO_H
#define __UML_BOOT_INFO_H

#include <ntabi.h>

/* "UMLB" little-endian. */
#define UML_BOOT_MAGIC   0x424C4D55u
#define UML_BOOT_VERSION 2u /* v2: exec section (M3.4 ELF loader source) */

struct uml_boot_info {
	unsigned int magic;
	unsigned int version;

	/* D9: resolved NT API (launcher-owned). */
	struct uml_nt_api_table *api;

	/* Guest physical memory: pagefile-backed section mapped as ONE
	 * view at physmem_base (== guest RAM base, the memfd analogue):
	 * guest physical X lives at physmem_base + X. The kernel image
	 * itself was loaded into this view by the launcher (image_base
	 * = physmem_base for an ET_EXEC at the RAM base; size kept for
	 * logging/parity). */
	HANDLE physmem_section;
	void *physmem_base;
	unsigned long long physmem_size; /* bytes (mem=) */
	void *image_base;
	unsigned long long image_size;

	/* Early console targets (inherited handles). */
	HANDLE stdio_out;
	HANDLE stdio_err;

	/* UML command line, launcher-built. */
	int argc;
	char **argv;
	char **envp;

	/* ---- v2 (M3.4): guest exec image, launcher path ----------
	 * The launcher scans the UML cmdline for `uml_nt_exec=<file>`,
	 * reads the guest ELF and hands it over as a pagefile-backed
	 * section (the execveat(memfd) source analogue — the kernel
	 * maps it read-only and parses; real file sources arrive with
	 * ubd, M3.5). NULL/0 = no exec image (legacy embedded-blob
	 * probe mode). Append-only: fields above stay frozen. */
	HANDLE exec_section;
	unsigned long long exec_size;
};

#endif /* __UML_BOOT_INFO_H */
