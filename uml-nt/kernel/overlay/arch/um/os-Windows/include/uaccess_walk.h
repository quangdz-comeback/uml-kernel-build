/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uaccess_walk.h — guest VA walker for the OS_WINDOWS uaccess (D15).
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI
 * (test_uaccess.c) and glued to raw_copy_* by skas/uaccess.c.
 */
#ifndef __UM_OS_WINDOWS_UACCESS_WALK_H
#define __UM_OS_WINDOWS_UACCESS_WALK_H

#include <vma.h>

/* Walk guest VA [va, va+len) through the mm's VMA tree in page-sized
 * chunks and copy against `base` (the kernel's flat physmem view).
 * A chunk can never cross a VMA edge: VMAs are 64K-run multiples,
 * chunks are page (4K) bounded. All-or-nothing: -1 when any byte is
 * unmapped (partial bytes may have been moved — callers retry with
 * Linux left-over semantics, none of the M3.7 users care).
 *
 *   from_guest: guest -> buf (copy_from_user)
 *   to_guest:   buf -> guest (copy_to_user)
 *   zero_guest: guest <- 0 (clear_user)
 */
#define UML_NT_UACC_FROM_GUEST 0
#define UML_NT_UACC_TO_GUEST   1
#define UML_NT_UACC_ZERO_GUEST 2

int uml_nt_uacc_walk(const struct uml_nt_mm *mm, char *base,
		     unsigned long long va, unsigned long long len,
		     char *buf, int op);

/* strncpy_from_user analogue: copy up to maxlen bytes up to and
 * including NUL into dst; return the length NOT counting NUL, or -1
 * when unterminated within maxlen / any byte unmapped. */
long long uml_nt_uacc_strncpy(char *dst, const struct uml_nt_mm *mm,
			      char *base, unsigned long long va,
			      unsigned long long maxlen);

/* strnlen_user analogue: length INCLUDING the NUL within maxlen, or
 * 0 when unterminated / unmapped (upstream convention: 0 = fault). */
long long uml_nt_uacc_strnlen(const struct uml_nt_mm *mm, char *base,
			      unsigned long long va,
			      unsigned long long maxlen);

#endif /* __UM_OS_WINDOWS_UACCESS_WALK_H */
