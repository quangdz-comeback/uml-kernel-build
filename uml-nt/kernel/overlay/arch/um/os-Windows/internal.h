/* SPDX-License-Identifier: GPL-2.0 */
/*
 * os-Windows/internal.h — decls shared between os-Windows modules only.
 * Upstream: linux v6.18.37 arch/um/os-Linux/internal.h
 * Status: M1.3 skeleton — filled in as modules gain implementations.
 */
#ifndef __UM_OS_WINDOWS_INTERNAL_H
#define __UM_OS_WINDOWS_INTERNAL_H

/* elf_aux.c does not exist on NT: no host auxv to scan (D1). */

/*
 * mem.c
 */
void check_tmpexec(void);

/*
 * skas/process.c
 */
void maybe_sigio_broken(int fd); /* moved to sigio.c upstream parity */

#endif
