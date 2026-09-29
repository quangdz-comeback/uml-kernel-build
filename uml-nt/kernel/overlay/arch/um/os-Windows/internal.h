/* SPDX-License-Identifier: GPL-2.0 */
/*
 * os-Windows/internal.h — state + helpers shared between os-Windows
 * modules. Upstream: arch/um/os-Linux/internal.h.
 */
#ifndef __UM_OS_WINDOWS_INTERNAL_H
#define __UM_OS_WINDOWS_INTERNAL_H

#include <ntabi.h>
#include <boot-info.h>

/* Validated copy of the launcher handoff (main.c, before any os_* call). */
extern struct uml_boot_info uml_boot;

/* Shorthand: the D9 table. main.c has validated version/size first. */
extern struct uml_nt_api_table *nt;

/* Pseudo-fd create_mem_file hands back (M1: single guest RAM bank). */
#define UML_NT_MEMFD_PHYS 0

/* Early console: NtWriteFile to boot.stdio_out (util.c). */
void nt_console_write(const char *s, unsigned int n);

#endif
