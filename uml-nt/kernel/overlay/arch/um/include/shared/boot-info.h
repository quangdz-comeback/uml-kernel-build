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
#define UML_BOOT_VERSION 1u

struct uml_boot_info {
	unsigned int magic;
	unsigned int version;

	/* D9: resolved NT API (launcher-owned). */
	struct uml_nt_api_table *api;

	/* Guest physical memory: pagefile-backed section, mapped on demand
	 * by os_map_memory (upstream memfd equivalent). */
	HANDLE physmem_section;
	unsigned long long physmem_size; /* bytes (mem=) */

	/* Early console targets (inherited handles). */
	HANDLE stdio_out;
	HANDLE stdio_err;

	/* UML command line, launcher-built. */
	int argc;
	char **argv;
	char **envp;
};

#endif /* __UML_BOOT_INFO_H */
