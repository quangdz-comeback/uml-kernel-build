/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uaccess_walk.h — guest VA walker for the OS_WINDOWS uaccess (D15).
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI
 * (test_uaccess.c) and glued to raw_copy_* by skas/uaccess.c.
 */
#ifndef __UM_OS_WINDOWS_UACCESS_WALK_H
#define __UM_OS_WINDOWS_UACCESS_WALK_H

#include <vma.h>
#include <fault.h>

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
 *
 * WRITE paths (to_guest/zero_guest) never touch a run they must not:
 * a chunk landing on a COW-shared run (refs > 1) gets the COW surgery
 * INLINE (fresh run + copy + cow_split — hazard 3, review M3.8: a
 * direct write would corrupt the sharing process through the shared
 * page) and queues the stub remap ops into the sink's plan; a chunk
 * on a read-only VMA faults (-EFAULT class) instead of writing.
 * Requires the sink (below): without it, writes to shared runs fault
 * fail-safe rather than silently corrupt.
 */
#define UML_NT_UACC_FROM_GUEST 0
#define UML_NT_UACC_TO_GUEST   1
#define UML_NT_UACC_ZERO_GUEST 2

/* The write-fixup channel, installed by the syscall dispatch for one
 * handler run (the same single-threaded pattern as set_mm): `ph`
 * allocates the fresh run, `plan` receives the stub remap ops (the
 * dispatch streams them after the handler, with the syscall retval
 * parked per D16). */
struct uml_nt_uacc_sink {
	struct uml_nt_phys *ph;
	struct uml_nt_fault_plan *plan;
};

/* Both installers return the PREVIOUS value — dispatches nest on the
 * one host thread (the parent blocks inside its handler, M4.2), so
 * the dispatch saves at entry and restores at exit; clearing to NULL
 * would EFAULT every writeback of the woken outer dispatch. */
struct uml_nt_mm *uml_nt_uacc_set_mm(struct uml_nt_mm *mm);
struct uml_nt_uacc_sink uml_nt_uacc_set_sink(const struct uml_nt_uacc_sink *s);

/* Read-only peek at the installed fixup channel (M5.4 c3 EFAULT
 * census): the to_user tracer classifies a failed walk's residue —
 * a COW-shared run with ph == NULL means "no-sink" (fail-safe
 * EFAULT), with a plan it can report the headroom to MAX_OPS.
 * Pure accessors, no state change — unit tests stay valid. */
struct uml_nt_phys *uml_nt_uacc_sink_phys(void);
const struct uml_nt_fault_plan *uml_nt_uacc_sink_plan(void);

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

/* Flat-view pointer for the byte at `va` after ensuring a kernel
 * WRITE to its page is safe: COW-shared runs are copied private
 * first (surgery + remap ops through the sink), read-only VMAs fault.
 * Returns 0 on fault (EFAULT class). The walker's write paths use it
 * per chunk; the futex atomics glue uses it instead of translating
 * directly (same hazard: a COW-shared futex write would land on the
 * shared page). */

/* How many runs the fixups have copied private so far (boot-wide).
 * Pure counter — the logging lives in the conn layer (stub_ctl.c /
 * syscall.c own os_info; this file stays unit-testable on Linux),
 * which turns the delta into the CI gate line. */
extern unsigned long uml_nt_uacc_fixups;
/* M5.4 c3 (map 057): the LAST cow-fixup's coordinates, recorded by the
 * walker (pure data — uaccess_walk.c stays log-free for the Linux CI
 * unit tests) and logged by the conn layer when the fixup counter
 * moves (syscall.c has os_info). Run 36854409213 round-correlated the
 * fork-residue cluster with this fixup; these name the target VMA and
 * the write that caused it. */
extern unsigned long long uml_nt_uacc_fixup_va;
extern unsigned long long uml_nt_uacc_fixup_page;
extern unsigned long long uml_nt_uacc_fixup_vma_start;
extern unsigned long long uml_nt_uacc_fixup_vma_end;
extern unsigned long long uml_nt_uacc_fixup_old_run;
extern unsigned long long uml_nt_uacc_fixup_new_run;

char *uml_nt_uacc_write_ptr(const struct uml_nt_mm *mm, char *base,
			    unsigned long long va);

#endif /* __UM_OS_WINDOWS_UACCESS_WALK_H */
