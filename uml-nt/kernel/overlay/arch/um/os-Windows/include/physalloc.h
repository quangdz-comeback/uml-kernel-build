/* SPDX-License-Identifier: GPL-2.0 */
/*
 * physalloc.h — guest physical run REFCOUNT layer (M3.2, backend M3.3).
 *
 * Upstream analogue: guest user pages come from the kernel page
 * allocator (alloc_pages) — upstream UML's "physical memory" IS the
 * kernel's own memory. On NT the same holds: the whole guest physmem
 * is ONE pagefile-backed section whose pages the kernel buddy manages
 * past the loaded image (min_low_pfn excludes the head). The M3.3
 * lesson (D11): a PRIVATE allocator over the section double-allocated
 * against the kernel's buddy/slab — guest writes to "its" runs trashed
 * live SLUB/maple data and the kernel died after the fork probe. So
 * the run allocator is now a thin REFCOUNT layer over the page
 * allocator backend (skas/physbackend.c kernel-side, mocked in unit
 * tests): alloc = alloc_pages(order 4 = 64 KiB — MapViewOfFile offset
 * granularity), unref-to-zero = __free_pages. Run offsets are DYNAMIC
 * (pfn << PAGE_SHIFT) — nothing may assume a fixed layout above the
 * image.
 *
 * The stub still maps per-VMA VIEWS of the section at run offsets:
 * a VMA's backing must be CONTIGUOUS runs (one MapViewOfFileEx covers
 * it). Single-run VMAs are trivially contiguous; multi-run spans need
 * a contiguous backend allocation (open design point, M4).
 *
 * Pure logic, no kernel includes: unit-tested standalone on Linux CI
 * (the backend is mocked).
 */
#ifndef __UM_OS_WINDOWS_PHYSALLOC_H
#define __UM_OS_WINDOWS_PHYSALLOC_H

#define UML_NT_PHYS_RUN_SHIFT  16ull /* 64 KiB — MapViewOfFile offset granularity */
#define UML_NT_PHYS_RUN_SIZE   (1ull << UML_NT_PHYS_RUN_SHIFT)
#define UML_NT_PHYS_MAX_RUNS   4096  /* 4096 * 64K = 256 MiB POC ceiling */

/* D22 (Shelley phê 2026-10-01): the recycle quarantine — a dropped
 * block does NOT return to the backend while the dropping view's
 * stub may still have it mapped (the plan UNMAP rides the NEXT reply;
 * between the kernel-side drop and the stub applying it, another
 * conn's alloc could hand the SAME block out and map it — the
 * free-while-mapped alias that landed guest env strings
 * (STREAM=7 / a%UTEMD_S$UTEMD_ / EXEC_PID) inside PID 1's malloc
 * metadata). Parked blocks release at the owner's NEXT serve round
 * (uml_nt_phys_settle — a new request proves the previous plan's ops
 * applied); a conn that dies releases everything it parked at destroy
 * (its views die with the process). */
#define UML_NT_PHYS_PARK_MAX  128

struct uml_nt_phys_park {
	long long off;      /* block owner-run byte offset */
	int nruns;
	const void *owner;  /* view tag (conn pointer) at drop time */
};

/* Guest VA span base (stub_nt.h UML_STUB_RAM_BASE — the unit tests
 * assert the two agree; single physmem-geometry source lives here). */
#define UML_NT_GUEST_VA_BASE   0x60000000ull

struct uml_nt_phys {
	unsigned long long size;      /* section bytes (rounded to runs) */
	unsigned short refs[UML_NT_PHYS_MAX_RUNS]; /* 0 = run not in use */
	/* Block bookkeeping (D12): a span of n runs is ONE backend
	 * allocation; the owner run (span_back == 0) holds the handle.
	 * Every used run records its block's extent so the block is
	 * freed exactly once — when ALL its runs drop to 0 (a COW
	 * split leaves flank pieces referencing the old block: freeing
	 * on the owner alone would pull live backing out from under
	 * them). */
	void *pages[UML_NT_PHYS_MAX_RUNS];        /* owner run only */
	unsigned short span_len[UML_NT_PHYS_MAX_RUNS];  /* 0 = free run */
	unsigned short span_back[UML_NT_PHYS_MAX_RUNS]; /* dist to owner */
	/* [gen] (M5.6a map 121, đáp 122; epoch model after referee
	 * 37109883909): the EPOCH of each run's LAST handout — one
	 * table-global counter, bumped ONCE per handout event and
	 * stamped on EVERY run of the span (a span's runs share one
	 * epoch — the earlier per-run bump diverged runs with
	 * different recycle histories and false-positived on the
	 * span's own tail runs). A claim (VMA gen) recorded at its
	 * own handout must still match: a mismatch = the run was
	 * freed + re-handed under the claim (STALE TRANSLATION — the
	 * tcache-entries poison writer, referee 37105483388). A run
	 * released but NOT re-handed keeps its epoch: the refs==0
	 * guard owns the free state, the epoch owns the re-hand. */
	unsigned long long gen[UML_NT_PHYS_MAX_RUNS];
	unsigned long long epoch;     /* [gen] handout counter */
	/* D22 quarantine (see UML_NT_PHYS_PARK_MAX): blocks dropped to
	 * 0 while a view owner is tagged wait here instead of going
	 * straight back to the backend. NULL drop-owner (drops outside
	 * any conn dispatch — no plan ops can be pending) frees
	 * immediately, the pre-D22 behavior. */
	struct uml_nt_phys_park park[UML_NT_PHYS_PARK_MAX];
	int npark;
	const void *drop_owner; /* the view performing current drops */
};

/* Initialize the refcount layer over a section of `size` bytes.
 * Returns 0, or -1 if size exceeds UML_NT_PHYS_MAX_RUNS runs. */
int uml_nt_phys_init(struct uml_nt_phys *p, unsigned long long size);

/* Backend hooks (skas/physbackend.c kernel-side, mocked in tests):
 * hand out ONE CONTIGUOUS block of `nruns` 64 KiB runs (kernel-side:
 * alloc_pages(order 4 + ceil_log2(nruns)) — a buddy block is
 * contiguous by construction) — returns the section offset of the
 * first run (64K-aligned) or -1; *page_out receives the opaque
 * handle for the matching free. */
long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns);
void uml_nt_phys_backend_free(void *page, int nruns);

/* Allocate one run: section offset in bytes, or -1 when the backend
 * is exhausted. The run enters with refcount 1. */
long long uml_nt_phys_alloc(struct uml_nt_phys *p);

/* Allocate a CONTIGUOUS span of nruns (>= 1): section offset of the
 * first run, or -1 when the backend is exhausted / hands garbage.
 * Every run of the span enters with refcount 1. This is what
 * multi-run VMAs (ELF segments, stacks) need — one MapViewOfFileEx
 * must cover the whole VMA (vma.h geometry). */
long long uml_nt_phys_alloc_span(struct uml_nt_phys *p, int nruns);

/* refcount helpers. unref returns the refcount AFTER the drop; when
 * it reaches 0 the backend frees the run's pages — for a span block,
 * only when EVERY run of the block is at 0 (D12: COW pieces may
 * outlive the owner run; the block is one allocation). The content
 * was copied out before the drop — the COW copy is kernel-side memcpy
 * through the flat view. -1 on bad offsets. */
int uml_nt_phys_ref(struct uml_nt_phys *p, long long off);
int uml_nt_phys_unref(struct uml_nt_phys *p, long long off);

/* WRITER-HUNT (M5.6a, run 36987612985): the per-drop owner. The D22
 * table-global drop_owner tag LEAKS across a SHARED table (forked
 * conns share ph): a dying conn's teardown window mis-tags every
 * sharer's unref-to-0, and its settle frees their blocks while the
 * live conn's UNMAP ops are still pending — the free-while-mapped
 * alias reborn through table sharing (the heap-trasher ABRT family:
 * PID 1's heap run recycled under a foreign tag, another conn's
 * legit writes land inside PID 1's malloc metadata).
 *
 * unref_for names the dropping conn AT THE CALL: conn != NULL → the
 * dropped block parks under THAT conn (its own serve-round settle
 * releases it after its plan ops applied); conn == NULL → the drop
 * is outside any dispatch (no plan ops can be pending) → release
 * immediately (pre-D22 behavior). The table-global tag dies with
 * this call: unref() stays as the NULL-owner shorthand and the
 * drop_owner field/setter become unused legacy. */
int uml_nt_phys_unref_for(struct uml_nt_phys *p, long long off,
			  const void *conn);
int uml_nt_phys_refs(struct uml_nt_phys *p, long long off);

/* [gen] (M5.6a map 121, đáp 122): the epoch of the run at off's
 * LAST handout — what a VMA claim recorded at its own handout must
 * still carry (the stale-translation guard in the uacc walker/
 * funnel). 0 = never handed / bad offset (and the VMA-claim
 * "unchecked" sentinel); a released-but-not-re-handed run KEEPS
 * its epoch (the refs==0 guard owns the free state). A live run's
 * epoch is never 0 (the first handout stamps 1). */
unsigned long long uml_nt_phys_gen(struct uml_nt_phys *p, long long off);

/* Refcount event hook (map 049: the run 0x28b0000 double-claim — a
 * live TLS block whose refs reached 0 through SOME path that unref'd
 * without a matching ref; the buddy re-listed the block and the next
 * anon mmap got the TCB's pages). Pure-file neutrality: the pointer
 * stays NULL in unit tests; the kernel pins it at boot (main.c →
 * stub_ctl.c os_info). Fires for:
 *   "park"          — a block dropped to 0 under a tagged owner went
 *                     to the D22 quarantine (off = base; frees at
 *                     the owner's settle)
 *   "park-spill"    — the quarantine ring overflowed; the OLDEST
 *                     parked block released early (bounded memory —
 *                     a degenerate alias window, loud)
 *   "free"          — a block returned to the backend (at settle/
 *                     spill/untagged-drop time; off = base)
 *   "unref-refused" — an unref on a 0-ref run: an unbalanced claim
 *                     drop (THEFT signal — somebody dropped a claim
 *                     they never held; the surviving owner loses the
 *                     block on the NEXT drop)
 *   "alloc-reject"  — the backend handed runs this table still counts
 *                     (double-__free_pages signature)
 * `owner` = the drop/settle tag (the conn view performing the drop),
 * NULL for untagged drops and for the unit-test/other neutral calls —
 * the conn layer's release-under-vma tripwire (M5.6a) needs it to
 * exempt the dropping view's OWN dying mm. */
typedef void (*uml_nt_phys_event_fn)(const char *kind, long long off,
				     int nruns, int refs,
				     const void *owner);
extern uml_nt_phys_event_fn uml_nt_phys_event;

/* [alloc-alias] (M5.6a map 121, to-shelley 119): fired on EVERY
 * successful uml_nt_phys_alloc_span handout — the refs table just
 * claimed [off, off+nruns) as free. The conn layer answers with the
 * live-VMA scan: a mm still translating into the fresh range = a
 * stale translation pointing at re-allocated phys (the "alloc over
 * a live run" writer, R25 decode of 37003166709). Pure layer knows
 * nothing about conns: NULL in the Linux unit-test build, pinned by
 * main.c. */
typedef void (*uml_nt_alloc_alias_fn)(long long off, int nruns);
extern uml_nt_alloc_alias_fn uml_nt_alloc_alias_probe;

/* D22 view-owner tagging: the conn layer sets THIS dispatch's owner
 * (the conn) at serve entry and at mmctx destroy's mm_drop; drops
 * made under a tag park their blocks instead of freeing them (see
 * UML_NT_PHYS_PARK_MAX). NULL (the init/default) restores the
 * immediate-free behavior — nothing outside a dispatch can have
 * pending plan ops. */
void uml_nt_phys_set_drop_owner(struct uml_nt_phys *p, const void *owner);

/* D22 settle: the owner's previous plan ops have applied (a new
 * request arrived, or the conn died at destroy) — release every
 * block it parked. */
void uml_nt_phys_settle(struct uml_nt_phys *p, const void *owner);

/* Quarantine depth (telemetry/tests). */
int uml_nt_phys_parked(const struct uml_nt_phys *p);

/* WRITER-HUNT (M5.6a): bulk-fill boundary guard — the direct-write
 * tripwire. A kernel-side byte fill (mmap_fill/refill, brk re-home,
 * fork eager copy, COW run copy, elf loader) must never touch a run
 * outside the ONE allocated span it targets: a fill that spills past
 * the span end (or into a dead run) is the heap-trasher class caught
 * before the write lands. Every run covering [off, off+len) — off is
 * byte-ranged, fills are not run-aligned — must be live (refs > 0)
 * and owned by the same span as the first run. Returns 0 = the write
 * may proceed, -1 = refuse (the caller logs loud and fails the op —
 * it never writes). Pure: unit-tested against the mock backend. */
int uml_nt_phys_block_check(const struct uml_nt_phys *p, long long off,
			    unsigned long long len);

#endif /* __UM_OS_WINDOWS_PHYSALLOC_H */
