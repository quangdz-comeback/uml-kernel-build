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

/* K6 (M5.6a decision-tree step 2) — the [tcekey] syscall-park
 * witness's PURE tcache-chain logic: the safe-linked reveal, the
 * per-bin chain walk, the snapshot record with dup detect, and the
 * three fire predicates. Unit-tested standalone (test_uaccess.c
 * drives the REAL functions stub_ctl.c's snapshotter calls); this
 * file stays log-free (stub_ctl.c owns os_info).
 *
 * glibc tcache contract (2.32+ safe-linking), as seen at a
 * quiescent syscall park:
 *   entries[i]  head of bin i's singly-linked list (chunk DATA va)
 *   counts[i]   the list's length — tcache_get/put keep it equal
 *               to the walked length at any park
 *   e->next (chunk+0):  PROTECT_PTR(pos, ptr) = (pos>>12) ^ ptr,
 *               pos = the member's own va; a NULL ptr stores
 *               va>>12, which reveals to 0 = chain end
 *   e->key  (chunk+8):  the tcache ptr while listed (tcache_put
 *               writes it, tcache_get NULLs it at the pop) — a
 *               LISTED chunk whose key != the tcache ptr is
 *               glibc's dup-check BLINDED: a second free of that
 *               chunk passes _int_free's walk and dup-inserts
 *   the insert's 4 stores: next(1) key(2) entries[i](3) counts(4)
 *               — the known tear LOSES one; a chain whose walk
 *               ends early (broke next) under a higher count is
 *               exactly the missing store #1 fingerprint. */
#define UML_NT_TCE_DEPTH 8   /* walk cap per bin (a healthy bin holds <= 7) */
/* chunks recorded per snapshot, all bins: the FULL tcache —
 * 64 bins x 7 members (glibc's tcache_count default) = 448. The
 * old 128 cap silently dropped the rest and every later check
 * (dup / stale-key / run diff) silently omitted them; the caller
 * discloses the honest -2 on the census/flag lines (a drop is
 * possible only in corrupt states: it takes > 448 walked, i.e.
 * a bin deeper than a healthy one). */
#define UML_NT_TCE_MAX 448   /* chunks recorded per snapshot, all bins */
#define UML_NT_TCE_PIECES 12 /* heap VMA pieces snapshot (run watch) */

struct uml_nt_tce_chunk {
	unsigned long long va;   /* the member's chunk-data va */
	unsigned long long key;  /* qword at va+8 (e->key) */
	unsigned long long size;  /* qword at va-8 (chunk size hdr) */
	unsigned long long run;  /* backing run of the CURRENT view */
	int bin, depth;
};

struct uml_nt_tce_bin {
	int walked;   /* members recorded */
	int capped;   /* hit UML_NT_TCE_DEPTH with a legal next */
	int broke;    /* chain broke: unmapped read or illegal next */
	unsigned long long broke_va;   /* member whose next broke */
	unsigned long long broke_next;  /* the illegal DECODED next */
	struct uml_nt_tce_chunk ch[UML_NT_TCE_DEPTH];
};

/* chunk-qword reader: read the 8 bytes at `va` through its OWN
 * translation (BOUNDARY-AWARE: a member whose 24B window
 * [va-8, va+16) straddles a COW-piece/VMA boundary — size hdr in
 * one piece, data/key in the next — is read per qword, so it is
 * still readable; the old single-window reader rejected exactly
 * those members: FALSE break at the head → FALSE COUNT-MISMATCH,
 * no key/run row). Return <0 when the qword is unreadable
 * (unmapped member); fills the qword + the CURRENT backing run
 * OF THIS READ (the walk keeps the one off the chunk's DATA
 * qword). */
struct uml_nt_tce_rd {
	int (*read)(void *ctx, unsigned long long va,
		    unsigned long long *qword, unsigned long long *run);
	void *ctx;
};

/* one snapshot's walked chunks — the dup-detect set and the next
 * park's diff base (STALE-KEY/HEAD-REENTRY/RUN-CHANGE attribution). */
struct uml_nt_tce_snap {
	struct uml_nt_tce_chunk ch[UML_NT_TCE_MAX];
	int n;
};

/* PROTECT_PTR inverse, keyed by the member's own va (map-053). */
unsigned long long uml_nt_tce_reveal(unsigned long long raw,
				     unsigned long long va);

/* member gate: 16-aligned, top-16 clear, inside [heap_start,
 * heap_end). */
int uml_nt_tce_member_ok(unsigned long long va,
			 unsigned long long heap_start,
			 unsigned long long heap_end);

/* Walk bin `bin` from `head`. Empty/illegal heads report walked=0
 * with broke=1 (the caller's counts predicate flags the pair); a
 * clean chain reports the recorded members and no break. */
int uml_nt_tce_walk_bin(const struct uml_nt_tce_rd *rd,
			unsigned long long head,
			unsigned long long heap_start,
			unsigned long long heap_end, int bin,
			struct uml_nt_tce_bin *out);

/* record one walked chunk; returns the EXISTING index when the va
 * was already recorded this snapshot (dup — the double-free
 * shape), -1 when recorded fresh, -2 when the snapshot is full. */
int uml_nt_tce_record(struct uml_nt_tce_snap *s,
		      const struct uml_nt_tce_chunk *ch);

/* find va in a snapshot: index or -1 (the prev-park diff base). */
int uml_nt_tce_find(const struct uml_nt_tce_snap *s,
		    unsigned long long va);

/* The (a) comparator's learned value: the MODAL key over the
 * walked chunks (glibc 2.34+ stores a RANDOM per-boot tcache_key in
 * e->key; older glibc stores the tcache ptr — the modal key names
 * either scheme). NULL keys never vote (the pop marker / the
 * missing key store). Returns the modal key; *best = its vote
 * count (0 when no chunk carries a non-NULL key). */
unsigned long long uml_nt_tce_modal_key(const struct uml_nt_tce_snap *s,
					int *best);

/* fire predicates (all unit-tested):
 *   key_stale:   listed chunk with e->key != the tcache ptr
 *   counts_bad:  counts[i] != walked length at a quiescent park
 *                (capped always fires: a healthy bin holds <= 7
 *                but the cap is 8)
 *   reentry_bad: entries[i] changed to a va ALREADY listed at the
 *                previous park while counts ROSE — a legit pop+
 *                re-push cycle cannot raise the count; only a dup
 *                insert (nothing was popped) can. */
int uml_nt_tce_key_stale(unsigned long long key,
			 unsigned long long want);
int uml_nt_tce_counts_bad(unsigned int counts, int walked, int capped);
int uml_nt_tce_reentry_bad(int head_changed, int head_in_prev,
			   unsigned int counts, unsigned int prev_counts);

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

/* ---- K6 [cowrace] (M5.6a, feature cowcopy-race-witness) — the
 * copy-vs-in-flight-store witness's PURE logic. Unit-tested
 * standalone (test_uaccess.c drives the REAL functions stub_ctl.c's
 * armer/checker call); this file stays log-free (stub_ctl.c owns
 * os_info and the watch table).
 *
 * The hunt state (dl24/dl25): the tear survived 6d3c932/fc4381a —
 * chunk-side stores (e->next/e->key) lost at RUN granularity while
 * the tcache-struct-side stores land, [cowcopy] activity on runs
 * ADJACENT to the torn chunks' run at the fire round, 0 [viewswap]
 * lines (the plan-op guard class is not the vector). Hypothesis: a
 * run copy+re-home races an in-flight guest store — the store lands
 * in the SOURCE run after/while the copy, the view swaps to the
 * copy, and the store is lost canonically.
 *
 * Protocol: at every run copy ([cowcopy] fault-path COW copy, the
 * brk re-home) the kernel side records src/dst run, va range, the
 * copying conn/pid, the source's t0 hash (src == dst byte-for-byte
 * AT the copy — uml_nt_copy_verify memcpys AND memcmps), the
 * source's phys gen/refs, and the RUNNING-vs-PARKED snapshot of
 * every other conn sharing that mm or mapping that src run. At the
 * NEXT SYSCALL PARKS (the witness placement rule) the src range is
 * re-hashed: src != t0 with the lifecycle gates intact means a
 * store landed in the SOURCE after the copy — a lost update. */
#define UML_NT_COWRACE_N       64  /* watch ring (kernel side owns it) —
				    * widened 16->64 (dlV: 129 arms under a
				    * 16-slot ring evicted most watches before
				    * any check could land) */
#define UML_NT_COWRACE_CHECKS  4   /* syscall-park HASH checks per arm for
				    * non-watched sources and big spans */
#define UML_NT_COWRACE_CHECKS_LONG 32 /* hash checks for watched-heap
				    * sources of <= 2 runs: the lost store
				    * can land several parks after the copy
				    * (dlV's t0-window expiry was silent) */
#define UML_NT_COWRACE_LONG_LEN (2 * UML_NT_PHYS_RUN_SIZE) /* the len
				    * ceiling for the long window (the
				    * 512MB hash budget stays bounded) */
#define UML_NT_COWRACE_PIDS    4   /* RUNNING sharers recorded per arm */
#define UML_NT_COWRACE_DIFFS   4   /* differing qwords reported per fire */

/* verdicts (gate + verdict + spend compose the check round) */
#define UML_NT_COWRACE_QUIET    0 /* src unchanged since the copy */
#define UML_NT_COWRACE_LOST     1 /* src moved, dst untouched: the
				   * pure lost update — a store landed in
				   * the abandoned source */
#define UML_NT_COWRACE_MIXED    2 /* both ends moved: decode the
				   * qword diffs (src-side writes are
				   * still lost) */
#define UML_NT_COWRACE_RECYCLE  3 /* src re-handed (gen moved): the
				   * run's bytes are a new generation's,
				   * not a lost update */
#define UML_NT_COWRACE_RELEASE  4 /* src unclaimed (refs==0): dead
				   * backing, retire */
#define UML_NT_COWRACE_SHARED  5 /* fire class (cowrace_class): the
				   * remaining owner wrote on after
				   * re-privatizing — benign, the
				   * decode correlates it */
#define UML_NT_COWRACE_RETIRE_LOST 6 /* RETIRE-LOST (feature
				   * flatwrite-retire-witness): src != t0
				   * AT RELEASE (refs==0, gen intact) — a
				   * store landed in the abandoned source
				   * between the copy and its release and
				   * retired silently as "dead backing"
				   * (dlV's blind spot: all 16 retires
				   * went out with no content check) */

/* One armed copy watch. `ph` is kernel-side only (the table the
 * gates read); host tests leave it NULL and never reach it. */
struct uml_nt_cowrace_watch {
	struct uml_nt_phys *ph;
	unsigned long long src_off;   /* the copied range in the source */
	unsigned long long dst_off;  /* the fresh copy (canonical now) */
	unsigned long long len;       /* copied bytes */
	unsigned long long va_base;  /* the range's guest VA in the
				      * COPYING mm */
	unsigned long long gen_src;  /* phys gen of src at the copy */
	unsigned long long h0;       /* fnv(src range) at the copy — the
				      * t0 both ends shared */
	unsigned long long pid;      /* the copying conn */
	unsigned long run_pids[UML_NT_COWRACE_PIDS]; /* RUNNING sharers
						 * of the src run */
	int n_run, n_park, n_samm, trunc;
	unsigned char checks;        /* hash checks left in the window */
	unsigned char watched;       /* the arm's src belongs to a watched
				      * glibc heap (the 0x291 shape): long
				      * window + eviction preference */
	unsigned char quiet;         /* the hash window is spent: the
				       * lifecycle gate keeps running at
				       * every park until the run retires
				       * (the RETIRE-LOST diff decides
				       * lost store vs dead backing) */
	unsigned char armed;
};

/* The park-protocol classifier (stub_nt.h): the stub bumps req_seq
 * when it PUBLISHES a park and done_seq when it consumes the answer
 * and resumes, so req==done is RUNNING (answer consumed, no park
 * published since) and req==done+1 is PARKED — exactly the pump's
 * own desync invariant. Cross-process coherent through the shared
 * section (Interlocked, S2). The caller gates the never-resumed
 * shape (req==done==0 = a conn that never ran guest code) on
 * conn->resumed. 1 RUNNING, 0 PARKED, -1 desync. */
int uml_nt_cowrace_run_state(unsigned long long req,
			     unsigned long long done);

/* Arm a watch (fill the slot the kernel side picked): a re-arm of
 * the SAME src refreshes in place (checks reset, dst/h0/pids
 * updated — the src content may have changed between copies, so h0
 * is always the caller's fresh hash); a free slot is taken; a full
 * ring evicts KEEPING watched-heap sources (the first non-watched
 * watch from the cursor; only an all-watched ring falls back to
 * the cursor slot). `watched` also widens the hash window: a
 * watched src of <= UML_NT_COWRACE_LONG_LEN gets
 * UML_NT_COWRACE_CHECKS_LONG parks. Returns the slot index. */
int uml_nt_cowrace_slot_arm(struct uml_nt_cowrace_watch *w, int n,
			    unsigned int *cursor,
			    unsigned long long src_off,
			    unsigned long long dst_off,
			    unsigned long long len,
			    unsigned long long va_base,
			    unsigned long long gen_src,
			    unsigned long long h0,
			    unsigned long pid,
			    const unsigned long *run_pids, int n_run,
			    int n_park, int n_samm, int trunc,
			    int watched);

/* One check pass over a watch. gate: the run's LIFECYCLE retires
 * before any byte comparison — a re-handed (gen moved) or released
 * (refs==0) source's content changes are recycle class, not lost
 * updates; refs dropping but >0 (a sharer COW'd out) stays live. */
int uml_nt_cowrace_gate(const struct uml_nt_cowrace_watch *w,
			unsigned long long gen_now, int refs_now);

/* The byte verdict (gates passed): src vs dst against the t0 they
 * shared at the copy. */
int uml_nt_cowrace_verdict(const struct uml_nt_cowrace_watch *w,
			   unsigned long long h_src,
			   unsigned long long h_dst);

/* Spend one hash check: 0 while the watch stays armed. When the
 * last check is spent the watch goes QUIET (no more per-park
 * hashing) but STAYS ARMED — the lifecycle gate runs at every
 * syscall park until the run retires (refs==0 / gen move), where
 * the RETIRE-LOST diff decides lost store vs dead backing. The
 * hash window closing is silent; the fire/retire paths print.
 * -1 when not armed (the round skips it). */
int uml_nt_cowrace_spend(struct uml_nt_cowrace_watch *w);

/* Scan two byte ranges qword-wise: returns the TOTAL count of
 * differing qwords (honest — the caller discloses "+N more"),
 * recording the first `max` offsets + both values. */
int uml_nt_cowrace_diff(const unsigned char *src, const unsigned char *dst,
			unsigned long long len,
			unsigned long long *offs,
			unsigned long long *sv,
			unsigned long long *dv, int max);

/* The fire classifier: a store landed in the SOURCE after the
 * copy (gates intact) — who can still legitimately write it? A
 * run with refs >= 2 is mapped READ-ONLY by every sharer (the COW
 * contract), so ANY write into it bypassed the fault path; a run
 * no live mm maps is nobody's canonical bytes. Both are the LOST
 * shape. refs == 1 with a live mapper is the remaining owner
 * writing on after re-privatizing (the benign class — the decode
 * correlates it against the tear). */
int uml_nt_cowrace_class(int refs_now, int n_mappers);

/* Does this mm map the run at src_off anywhere? (the vma's backing
 * span is [run_off, run_off + end - start) — the same predicate
 * the claim audit walks.) */
int uml_nt_cowrace_maps_run(const struct uml_nt_mm *mm,
			    unsigned long long src_off);

/* K6 (M5.6a, feature cowcopy-race-class-fix, dlW/dlX RETIRE-LOST):
 * the release gate's backing-intersection predicate — 1 when the
 * stub view [view_off, view_off+view_len) maps any byte of the run
 * range [run_off, run_off+nruns*RUN), 0 otherwise (adjacency is
 * not coverage). Pure logic, host-tested in test_uaccess.c. */
int uml_nt_view_maps_span(unsigned long long view_off,
			  unsigned long long view_len,
			  long long run_off, int nruns);

/* ---- K6 [viewprobe] (M5.6a, feature viewprobe-witness) — the
 * stub-view-vs-table witness's pure diff/classify logic. stub_ctl.c
 * owns the reads (ReadProcessMemory on the parked stub + the flat
 * translate), the budgets and every log line; this file stays
 * log-free. See stub_ctl.c's block comment for the conviction
 * context (dl26 + the two 9a56286 referees: the lost tcache_put
 * pair lands in a backing the table does not own, invisible to a
 * released-range census). Host-tested in test_uaccess.c
 * (test_viewprobe_helpers). */

/* the per-conn drain record's op-summary cap (syscall.h's
 * vp_drain_ops): the [fork-sync] formation-window stream was 2
 * ops; 16 covers every real repair/re-protect plan, with the
 * honest trunc disclosure on the record's lines. */
#define UML_NT_VP_DRAIN_OPS 16

/* read-outcome classes: which sides of the comparison are readable.
 * A read failure is never guessed at: either side's failure is its
 * own class (a stub view missing over a table-owned range, or a
 * stub view over a range the table no longer owns — the stray-view
 * shape), and both failing is the gone-everywhere shape. */
#define UML_NT_VP_CLS_OK          0 /* both readable, identical */
#define UML_NT_VP_CLS_CMP          1 /* both readable — compare */
#define UML_NT_VP_CLS_STUB_UNREAD  2 /* stub read failed, table ok */
#define UML_NT_VP_CLS_TBL_UNREAD   3 /* table translate failed, stub ok */
#define UML_NT_VP_CLS_BOTH_UNREAD  4 /* the range is gone everywhere */

/* the double-read confirm verdict: a REAL view divergence is STABLE
 * across both reads (the two sides map different backings —
 * re-reading changes nothing), while a shared-run writer racing
 * between the stub read and the table read moves bytes between
 * the rounds (a raced pair is never a fire; the census counts it). */
#define UML_NT_VP_OK        0
#define UML_NT_VP_DIVERGED  1
#define UML_NT_VP_RACED     2

int uml_nt_vp_classify(int stub_ok, int tbl_ok);
int uml_nt_vp_confirm(const unsigned char *stub1,
		      const unsigned char *tbl1,
		      const unsigned char *stub2,
		      const unsigned char *tbl2,
		      unsigned long long len);

/* the 9a56286 view ledger lookup: the issued view containing `va`
 * (containment [va, va+len) — a va between two views belongs to
 * neither), or -1. Pure. */
int uml_nt_vp_view_find(const struct uml_nt_view *vs, int n,
			unsigned long long va);

/* the section offset a watched va maps through a ledger view:
 * view->off + (va - view->va) — the view's BACKING, run-granular
 * (the 64K granule, physalloc.h). The ledger-vs-table check fires
 * exactly when this differs from the table's own translate of the
 * same va: a view mapped at a wrong/stale section offset names
 * itself with zero stub reads. */
unsigned long long uml_nt_vp_view_off(const struct uml_nt_view *v,
				      unsigned long long va);

/* the watched page set, in probe order: page(tva) FIRST, then the
 * last drained plan's PROTECT/MAP op pages (UNMAP releases nothing
 * to compare — the drain census owns that class), then every
 * chunk's page — deduped. Writes at most `max` pages; returns the
 * TOTAL distinct count found (a return > max is the honest trunc
 * the caller discloses); *nplan = the plan-op page count. */
int uml_nt_vp_pageset(const unsigned long long *chunks, int nchunks,
		      unsigned long long tva,
		      const struct uml_nt_fault_op *ops, int nops,
		      unsigned long long *pages, int max, int *nplan);

/* the rotation picker: `max` consecutive chunk pages starting at
 * *cursor (wrapping), cursor advances by the picked count — the
 * steady-state probe stays bounded while every watched page is
 * covered within ceil(n/max) parks; escalation (the counts-mismatch
 * fingerprint) bypasses the rotation with the FULL set. */
int uml_nt_vp_rr_pick(const unsigned long long *pages, int npages,
		      unsigned int *cursor, unsigned long long *out,
		      int max);

/* attribution classes for a diverged qword (the fire's naming):
 * which watched item does the differing qword belong to? */
#define UML_NT_VP_ATTR_OTHER      0
#define UML_NT_VP_ATTR_CHUNK_NEXT 1 /* a listed chunk's e->next */
#define UML_NT_VP_ATTR_CHUNK_KEY  2 /* a listed chunk's e->key */
#define UML_NT_VP_ATTR_TCACHE     3 /* the tcache struct's fields */
#define UML_NT_VP_ATTR_PLANOP     4 /* a drained plan op's range */

int uml_nt_vp_attr(unsigned long long va,
		   const unsigned long long *chunks, int nchunks,
		   unsigned long long tva, unsigned long long tlen,
		   const struct uml_nt_fault_op *ops, int nops);

/* ---- K6 [flatwr] (M5.6a, feature flatwrite-retire-witness) ----
 * The kernel-flat-write staleness witness's PURE logic. Context
 * (dlV 37553645227 + 139a): the lost tcache_put pair reaches a
 * backing NO park-visible view shows; surviving candidate (b) is a
 * kernel-side flat write of guest content through a translation
 * OLDER than the current table — the store lands in an abandoned
 * source run (the dl26 content shape). Protocol: every kernel flat
 * -write site of guest content captures the (run, gen) at
 * TRANSLATE time, and at WRITE time compares the phys gen of the
 * offset being written AND the CURRENT table translate of the
 * guest va — a mismatch is recorded into a small ring AT the site
 * (bookkeeping only, no hashing/printing at fault parks) and
 * printed at the next syscall park. stub_ctl.c owns the ring, the
 * reads and every log line; this file stays log-free. Host-tested
 * in test_uaccess.c (test_flatwr_helpers). */

/* the record ring (kernel side owns it) */
#define UML_NT_FLATWR_N 32

/* what the write sites are (the site label of a record) */
#define UML_NT_FLATWR_SITE_COWCOPY_SRC 0  /* fault-path COW copy: src read */
#define UML_NT_FLATWR_SITE_COWCOPY_DST 1  /* fault-path COW copy: dst write */
#define UML_NT_FLATWR_SITE_UACC_FIXUP  2  /* the walker's inline fixup copy */
#define UML_NT_FLATWR_SITE_BRK_FILL     3  /* brk re-home span copy */
#define UML_NT_FLATWR_SITE_MMAP_FILL    4  /* mmap fill: memset + file read */
#define UML_NT_FLATWR_SITE_MMAP_SWEEP   5  /* the syscall sweep patch */
#define UML_NT_FLATWR_SITE_MC_PLANT     6  /* mapcanary nonce plant */
#define UML_NT_FLATWR_SITE_MC_RESTORE   7  /* mapcanary pushback (round-trip
					    * window: op issue -> PROT_DONE) */
#define UML_NT_FLATWR_SITE_TCTRIP_EMU   8  /* the tctrip emulated struct store */
#define UML_NT_FLATWR_SITE_FORK_EAGER   9  /* fork eager seed copy (either end) */
#define UML_NT_FLATWR_SITE_FORK_ZERO   10  /* fork below-rsp residue zeroing */

/* staleness classes */
#define UML_NT_FLATWR_OK          0
#define UML_NT_FLATWR_STALE_GEN   1 /* the run re-handed between capture and
				     * write (or gen==0 at capture: a
				     * never-handed offset) */
#define UML_NT_FLATWR_STALE_TBL   2 /* the va translates elsewhere (or not at
				     * all) at write time — the write went
				     * through a stale translation */
#define UML_NT_FLATWR_STALE_BOTH  3

struct uml_nt_flatwr_rec {
	unsigned char site;  /* UML_NT_FLATWR_SITE_* */
	unsigned char what;   /* UML_NT_FLATWR_STALE_* */
	unsigned long long va;  /* the guest va the write belongs to (0 =
				 * gen-only site) */
	unsigned long long len;
	unsigned long long off;      /* the byte offset written (captured run) */
	unsigned long long gen_old; /* phys gen at capture */
	unsigned long long gen_now; /* phys gen at write */
	unsigned long long tbl_old; /* the run the table was expected to
				     * translate va to (run-aligned) */
	unsigned long long tbl_new; /* the run the table translates va to at
				     * write time (~0ull = untranslatable) */
	unsigned long pid;
	unsigned long long nr, ret;
};

/* The classifier: gen identity (gen_now == gen_old, both nonzero)
 * + run-granular table identity (all backing offsets are
 * run-aligned, so the table compare is the RUN compare; a translate
 * of -1 with an expected run is stale; tbl_expect < 0 = no table
 * check requested). */
int uml_nt_flatwr_class(unsigned long long gen_old,
			unsigned long long gen_now,
			long long tbl_now, long long tbl_expect);

/* Ring insert (append while free, overwrite by cursor when full —
 * the newest record wins; the park printer drains the ring).
 * Returns the slot index written. */
int uml_nt_flatwr_push(struct uml_nt_flatwr_rec *r, int n, int *count,
		       unsigned int *cursor,
		       const struct uml_nt_flatwr_rec *rec);

/* The uacc walker's inline fixup copy is a kernel flat write of
 * guest content INSIDE this pure file — the [flatwr] check runs
 * through this hook (pinned by the kernel like physalloc's
 * zero/alias hooks; NULL in the host unit tests). The hook owns
 * both ends: src (read) and dst (write). */
typedef void (*uml_nt_flatwr_uacc_fn)(const struct uml_nt_mm *mm,
				      struct uml_nt_phys *ph,
				      unsigned long long va,
				      unsigned long long src_off,
				      unsigned long long gen_src,
				      unsigned long long dst_off,
				      unsigned long long gen_dst);
extern uml_nt_flatwr_uacc_fn uml_nt_flatwr_uacc_hook;

#endif /* __UM_OS_WINDOWS_UACCESS_WALK_H */
