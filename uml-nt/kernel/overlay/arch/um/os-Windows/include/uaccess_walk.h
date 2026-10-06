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

/* K6 (M5.6a) uawrite full-buffer witness — pure helpers, unit-
 * tested standalone (test_uaccess.c) and used by uaccess.c's
 * logging (this file stays log-free):
 *   fnv1a64:   FNV-1a 64 over buf[0..n) — canonical vectors.
 *   fnv_mix_nr: 8 more FNV rounds mixing the syscall nr in (LE
 *              bytes) — the [uawrite] line prints fnv= as
 *              fnv_mix_nr(fnv1a64(from, n), nr): buffer AND
 *              round in one word, no cross-correlation with
 *              c->last_nr (which is only stamped at handler EXIT).
 *   dump_gate: 1 when the buffer deserves a full hex dump: it
 *              holds "SYSTEMD_" or "LANG=en_US.UTF-8" anywhere
 *              (dl13 proved the poison text can sit mid-buffer,
 *              beyond the q0/q1 16B window), or the dest overlaps
 *              the tcache page [heap_start, heap_start+0x1000). */
unsigned long long uml_nt_uacc_fnv1a64(const void *buf, unsigned long n);
unsigned long long uml_nt_uacc_fnv_mix_nr(unsigned long long h,
					  unsigned long long nr);
int uml_nt_uacc_dump_gate(const void *from, unsigned long n,
			  unsigned long long va,
			  unsigned long long heap_start);

/* K6 (M5.6a, scrutiny fix) — the [uawrite] nr-context protocol:
 * the CURRENT handler nr of the dispatch on this host thread.
 * nr_current feeds the fnv_mix_nr above and the line's nr=. The
 * state lives in this file's .c on purpose — the whole protocol is
 * unit-tested standalone on Linux CI (test_uaccess.c drives the
 * REAL functions, not a replica). Installed three ways, mirroring
 * set_mm/set_sink:
 *   nr_enter: the dispatch at entry — stamps the conn's slot
 *             (c->active_nr, syscall.h) AND installs the global
 *             in one call; the local prev the dispatch saves
 *             covers NESTED handler returns at exit (set_nr).
 *   set_nr:   plain install, returns the PREVIOUS value (the
 *             dispatch's exit restore).
 *   nr_switch: the stack-switch boundary (stub_ctl.c
 *             uml_nt_switch_trace, beside the mm/sink re-arm):
 *             installs the incoming task's conn-stamped nr — the
 *             path a parent woken INSIDE its blocked wait4 (61)
 *             crosses after an intervening child exited through
 *             do_exit (exit/exit_group never unwinds the dispatch,
 *             so the global still names the child's 60/231; the
 *             stamp re-arms the parent's own). NULL slot
 *             (conn-less/stale-refused) installs 0 — the honest
 *             "no active handler" attribution. Returns the value
 *             installed. */
unsigned long long uml_nt_uacc_nr_current(void);
unsigned long long uml_nt_uacc_set_nr(unsigned long long nr);
unsigned long long uml_nt_uacc_nr_enter(unsigned long long *slot,
					unsigned long long nr);
unsigned long long uml_nt_uacc_nr_switch(const unsigned long long *slot);

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

/* Refusal telemetry (map 121 follow-up): every walker refusal
 * (stolen-run refs guard OR [gen] generation mismatch) records its
 * coordinates here — the boot-wide count + the LAST refusal's va /
 * claim-gen / run-gen / kind (0 = refs, 1 = gen). Pure data: the
 * kernel side (uaccess.c) turns it into the log line; the conn
 * layer can delta the counter per serve round. A refusal that
 * produces a guest-visible errno with NO counter delta = the errno
 * came from somewhere else (fs layer) — the discriminator the
 * EPERM-wall decode needs. */
extern unsigned long long uml_nt_uacc_refuses;
extern unsigned long long uml_nt_uacc_refuse_va;
extern unsigned long long uml_nt_uacc_refuse_claim_gen;
extern unsigned long long uml_nt_uacc_refuse_run_gen;
extern unsigned long uml_nt_uacc_refuse_kind;

char *uml_nt_uacc_write_ptr(const struct uml_nt_mm *mm, char *base,
			    unsigned long long va);

#endif /* __UM_OS_WINDOWS_UACCESS_WALK_H */
