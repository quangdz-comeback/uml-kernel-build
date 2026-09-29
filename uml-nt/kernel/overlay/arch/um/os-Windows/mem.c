// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/mem.c — physical-memory backing for the guest.
 * Upstream: linux v6.18.37 arch/um/os-Linux/mem.c
 *
 * Upstream: tmpfs memfd + ftruncate; os_map_memory (process.c) mmaps
 * pieces at fixed addresses. NT: launcher created a pagefile-backed
 * SECTION (boot.physmem_section, D9) — create_mem_file validates the
 * size and hands back a pseudo-fd; mapping happens on demand.
 */
#include <ntabi.h>
#include <os.h>
#include "internal.h"

int create_mem_file(unsigned long long size)
{
	if (uml_boot.physmem_section == NULL ||
	    size > uml_boot.physmem_size) {
		os_info("mem: requested %llu bytes exceeds launcher "
			"physmem section (%llu)\n", size,
			(unsigned long long)uml_boot.physmem_size);
		return -1;
	}
	return UML_NT_MEMFD_PHYS;
}
