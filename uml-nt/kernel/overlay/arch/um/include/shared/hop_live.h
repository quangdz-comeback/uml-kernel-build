/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hop_live.h — the plain-hop witness (S13).
 *
 * The two plain trampolines (fs_trampoline_sys, fs_trampoline_fault) end in an
 * indirect jmp, and until now nothing recorded what that jmp was about to
 * deliver: the old stage byte proves a pre-jump point was reached for a named
 * round, and the pre/post counters prove the body ran, but neither says which
 * target and which RAX the guest was handed.
 *
 * So the trampoline itself writes a small record into the shared stub page:
 * the C side arms it from the final resume choice (expected target/RAX, kind,
 * and a per-return arm id), the entry of each trampoline copies the arm id into
 * `entered`, and immediately before the final restore+jmp the same code stores
 * the observed kind/target/RAX/RSP and publishes the arm id into `commit` LAST.
 * A reader at death reports what it finds — including "absent", "armed only",
 * "entered but never committed" and "stale" — and never calls a sample valid
 * unless the arm id, request seq and path all match.
 *
 * Validity rules (enforced by uml_nt_hop_live_read()):
 *   - commit == arm && arm != 0        → committed (a pre-jmp observation)
 *   - entered == arm && commit == 0    → entered only
 *   - arm != 0 && entered == 0         → armed only (death before entry)
 *   - commit != 0 && commit != arm     → stale (a previous return's record)
 *   - seq mismatch                     → stale
 *   - no arm at all                    → absent
 *
 * A zero RAX is a NORMAL observed value (a syscall returning 0), not evidence
 * that nothing was sampled, and `entry_id` is the VEH-entry counter of this
 * attempt — it is not `fs_tramp_snap_id` and must not be read as one.
 *
 * A valid sample means "the trampoline reached its pre-jmp snapshot". It does
 * NOT mean the jmp executed, the guest instruction ran, or the kernel is
 * innocent. Nothing here is a fix; it is an observation.
 */
#ifndef UML_NT_HOP_LIVE_H
#define UML_NT_HOP_LIVE_H

/* No string.h here: including it from a kernel TU reorders <linux/string.h>
 * against user.h and collides on sized_strscpy. The reader zeroes the view
 * field by field instead. */
#include "diag_record.h"

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t __u64;
#endif

/* Kinds. 0 is reserved for "absent". */
#define UML_NT_HOP_KIND_NONE	0u
#define UML_NT_HOP_KIND_SYS	1u	/* fs_trampoline_sys */
#define UML_NT_HOP_KIND_FAULT	2u	/* fs_trampoline_fault */
#define UML_NT_HOP_KIND_TF	3u	/* the TF trampoline: never sampled */

/* Reader verdicts. */
#define UML_NT_HOP_LIVE_ABSENT		0
#define UML_NT_HOP_LIVE_ARMED_ONLY	1
#define UML_NT_HOP_LIVE_ENTERED_ONLY	2
#define UML_NT_HOP_LIVE_COMMITTED	3
#define UML_NT_HOP_LIVE_STALE		4

/*
 * Fixed field offsets — the assembly writes through these numbers, so they are
 * part of the ABI and are asserted (static asserts below, plus the host ABI
 * test). The record is 8-byte aligned and every field is 8 bytes, so a MOV
 * with a literal offset is all the trampoline needs.
 */
struct uml_nt_hop_live {
	__u64 arm_id;		/* 0x00 nonzero per-return identity */
	__u64 req_seq;		/* 0x08 request sequence at the resume choice */
	__u64 done_seq;		/* 0x10 done sequence at the resume choice */
	__u64 entry_id;		/* 0x18 the fs_tramp_snap_id at entry */
	__u64 kind_exp;		/* 0x20 which plain trampoline was selected */
	__u64 target_exp;	/* 0x28 the Rip the resume choice set */
	__u64 rax_exp;		/* 0x30 the Rax the resume choice set */
	__u64 entered;		/* 0x38 arm id copied at trampoline entry */
	__u64 commit;		/* 0x40 arm id, published last before the jmp */
	__u64 kind_obs;		/* 0x48 kind observed in the trampoline */
	__u64 target_obs;	/* 0x50 target about to be jumped to */
	__u64 rax_obs;		/* 0x58 RAX about to be delivered */
	__u64 rsp_obs;		/* 0x60 RSP at the snapshot */
	__u64 pad;		/* 0x68 keep the record 16-byte sized */
};

#define UML_NT_HOP_LIVE_OFF_ARM 0x00
#define UML_NT_HOP_LIVE_OFF_REQ 0x08
#define UML_NT_HOP_LIVE_OFF_DONE 0x10
#define UML_NT_HOP_LIVE_OFF_ENTRY 0x18
#define UML_NT_HOP_LIVE_OFF_KIND_EXP 0x20
#define UML_NT_HOP_LIVE_OFF_TARGET_EXP 0x28
#define UML_NT_HOP_LIVE_OFF_RAX_EXP 0x30
#define UML_NT_HOP_LIVE_OFF_ENTERED 0x38
#define UML_NT_HOP_LIVE_OFF_COMMIT 0x40
#define UML_NT_HOP_LIVE_OFF_KIND_OBS 0x48
#define UML_NT_HOP_LIVE_OFF_TARGET_OBS 0x50
#define UML_NT_HOP_LIVE_OFF_RAX_OBS 0x58
#define UML_NT_HOP_LIVE_OFF_RSP_OBS 0x60

#define UML_NT_HOP_LIVE_SIZE		0x70

/* What the death reader prints. */
struct uml_nt_hop_live_view {
	int verdict;		/* UML_NT_HOP_LIVE_* */
	int comparable;		/* 1 only for a fully committed matching arm */
	__u64 arm_id, entered, commit;
	__u64 req_seq, done_seq, entry_id, entry_now;
	__u64 kind_exp, kind_obs;
	__u64 target_exp, target_obs;
	__u64 rax_exp, rax_obs, rsp_obs;
};

/*
 * Arm the witness from the final resume choice. `l` may be NULL (nothing is
 * sampled); the caller passes the shared record once it exists. Returns the
 * new arm id (0 when nothing was armed), so a caller can compare later.
 */
static inline __u64 uml_nt_hop_live_arm(struct uml_nt_hop_live *l, __u64 arm_id,
					__u64 kind, __u64 target, __u64 rax,
					__u64 req_seq, __u64 done_seq,
					__u64 entry_id)
{
	if (l == 0 || arm_id == 0 || kind == UML_NT_HOP_KIND_NONE)
		return 0;
	/* The marks are cleared FIRST so a reader can never see this return's
	 * expected values beside the previous return's commit. `entry_id` is
	 * set by the caller from the CURRENT VEH entry — it is not the
	 * fs_tramp_snap_id domain, and zero is not "absent". */
	l->entered = 0;
	l->commit = 0;
	l->kind_obs = 0;
	l->target_obs = 0;
	l->rax_obs = 0;
	l->rsp_obs = 0;
	l->entry_id = entry_id;	/* the VEH-entry identity at preparation */
	l->kind_exp = kind;
	l->target_exp = target;
	l->rax_exp = rax;
	l->req_seq = req_seq;
	l->done_seq = done_seq;
	l->arm_id = arm_id;	/* the arm id is published last */
	return arm_id;
}

/* A return that must not be sampled (TF path, hop disabled, plain resume). */
static inline void uml_nt_hop_live_invalidate(struct uml_nt_hop_live *l)
{
	if (l == 0)
		return;
	l->entered = 0;
	l->commit = 0;
	l->kind_exp = 0;
	l->target_exp = 0;
	l->rax_exp = 0;
	l->entry_id = 0;
	l->kind_obs = 0;
	l->target_obs = 0;
	l->rax_obs = 0;
	l->rsp_obs = 0;
	l->arm_id = 0;
}

/*
 * Read the record and classify it. A sample is only comparable when the arm id
 * matches the entered and committed ids AND the request sequence matches the
 * reader's own request — a fast-path return can repeat the same done_seq, so
 * the arm id (not the done seq) is the identity.
 */
/* A view with nothing in it, for callers that have no record at all. Kept
 * separate so uml_nt_hop_live_read() can document that it requires a real
 * record and needs no NULL branch of its own. */
static inline void uml_nt_hop_live_view_absent(struct uml_nt_hop_live_view *v)
{
	if (v == 0)
		return;
	v->verdict = UML_NT_HOP_LIVE_ABSENT;
	v->comparable = 0;
	v->arm_id = 0;
	v->entered = 0;
	v->commit = 0;
	v->req_seq = 0;
	v->done_seq = 0;
	v->entry_id = 0;
	v->entry_now = 0;
	v->kind_exp = 0;
	v->kind_obs = 0;
	v->target_exp = 0;
	v->target_obs = 0;
	v->rax_exp = 0;
	v->rax_obs = 0;
	v->rsp_obs = 0;
}

/* Requires a non-NULL record (see above). */
static inline void uml_nt_hop_live_read(const struct uml_nt_hop_live *l,
					__u64 req_seq, __u64 done_seq,
					__u64 entry_now,
					struct uml_nt_hop_live_view *v)
{
	if (v == 0)
		return;
	v->verdict = UML_NT_HOP_LIVE_ABSENT;
	v->comparable = 0;
	v->arm_id = l->arm_id;
	v->entered = l->entered;
	v->commit = l->commit;
	v->req_seq = l->req_seq;
	v->done_seq = l->done_seq;
	v->entry_id = l->entry_id;
	v->entry_now = entry_now;
	v->kind_exp = l->kind_exp;
	v->kind_obs = l->kind_obs;
	v->target_exp = l->target_exp;
	v->target_obs = l->target_obs;
	v->rax_exp = l->rax_exp;
	v->rax_obs = l->rax_obs;
	v->rsp_obs = l->rsp_obs;

	if (l->arm_id == 0 && l->commit == 0 && l->entered == 0) {
		v->verdict = UML_NT_HOP_LIVE_ABSENT;
		return;
	}
	if (l->arm_id != 0 && req_seq != 0 && l->req_seq != req_seq) {
		v->verdict = UML_NT_HOP_LIVE_STALE;
		return;
	}
	/*
	 * The witness is armed AFTER the body ran, so the recorded sequences are
	 * the ones the reader will see. Exact equality only — no tolerance.
	 * (Both numbers are printed, so a mismatch is inspectable.)
	 */
	if (l->arm_id != 0 && done_seq != 0 && l->done_seq != done_seq) {
		v->verdict = UML_NT_HOP_LIVE_STALE;
		return;
	}
	/* The same for the VEH entry: a newer attempt must not read an older
	 * attempt's record as its own, even when req/done did not move. */
	if (l->arm_id != 0 && entry_now != 0 && l->entry_id != entry_now) {
		v->verdict = UML_NT_HOP_LIVE_STALE;
		return;
	}
	if (l->arm_id == 0) {
		v->verdict = UML_NT_HOP_LIVE_STALE;
		return;
	}
	if (l->entered != l->arm_id && l->entered != 0) {
		v->verdict = UML_NT_HOP_LIVE_STALE;
		return;
	}
	if (l->commit != 0 && l->commit != l->arm_id) {
		v->verdict = UML_NT_HOP_LIVE_STALE;
		return;
	}
	if (l->commit == l->arm_id) {
		/* A committed sample is only usable when EVERY identity agrees:
		 * the trampoline recorded the entry (entered == arm), the commit
		 * matches that same arm, the arm recorded a real VEH-entry id,
		 * and the kind is one this witness supports. Anything less is
		 * reported as incomplete rather than promoted. */
		if (l->entered != l->arm_id || l->entry_id == 0) {
			v->verdict = UML_NT_HOP_LIVE_ENTERED_ONLY;
			v->comparable = 0;
			return;
		}
		if (l->kind_exp != UML_NT_HOP_KIND_SYS &&
		    l->kind_exp != UML_NT_HOP_KIND_FAULT) {
			v->verdict = UML_NT_HOP_LIVE_STALE;
			v->comparable = 0;
			return;
		}
		v->verdict = UML_NT_HOP_LIVE_COMMITTED;
		/* comparable: the observed path matches the armed path */
		v->comparable = (l->kind_obs == l->kind_exp);
		return;
	}
	if (l->entered == l->arm_id)
		v->verdict = UML_NT_HOP_LIVE_ENTERED_ONLY;
	else
		v->verdict = UML_NT_HOP_LIVE_ARMED_ONLY;
}

/* The assembly writes through these numbers; if the struct ever moves, this
 * must fail to compile rather than silently write the wrong field. */
/* File-scope assertion: _Static_assert works in both the kernel build and the
 * host/PE builds, unlike BUILD_BUG_ON which is a statement. */
#define HOP_STATIC_ASSERT(c, m) _Static_assert(c, m)

HOP_STATIC_ASSERT(sizeof(struct uml_nt_hop_live) == UML_NT_HOP_LIVE_SIZE,
		  "hop_live record size");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, arm_id) ==
		  UML_NT_HOP_LIVE_OFF_ARM, "arm_id offset");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, entered) ==
		  UML_NT_HOP_LIVE_OFF_ENTERED, "entered offset");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, commit) ==
		  UML_NT_HOP_LIVE_OFF_COMMIT, "commit offset");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, kind_obs) ==
		  UML_NT_HOP_LIVE_OFF_KIND_OBS, "kind_obs offset");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, target_obs) ==
		  UML_NT_HOP_LIVE_OFF_TARGET_OBS, "target_obs offset");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, rax_obs) ==
		  UML_NT_HOP_LIVE_OFF_RAX_OBS, "rax_obs offset");
HOP_STATIC_ASSERT(__builtin_offsetof(struct uml_nt_hop_live, rsp_obs) ==
		  UML_NT_HOP_LIVE_OFF_RSP_OBS, "rsp_obs offset");

/*
 * The death line, formatted by production code so the host test can drive it
 * through a recording sink. One record, one write (the S8 framing).
 */
static inline int uml_nt_hop_live_format(char *buf,
							     unsigned int cap,
					 const struct uml_nt_diag_ops *ops,
					 const struct uml_nt_hop_live *l,
					 __u64 req_seq, __u64 done_seq,
					 __u64 entry_now, int pid)
{
	static const char *const name[] = {
		"absent", "armed-only", "entered-only", "committed", "stale"
	};
	struct uml_nt_hop_live_view v;

	if (l == 0)
		uml_nt_hop_live_view_absent(&v);
	else
		uml_nt_hop_live_read(l, req_seq, done_seq, entry_now, &v);
	return uml_nt_diag_record(buf, cap, ops,
				  "[hop-live] pid=%d req=%llu done=%llu "
				  "arm=0x%llx entered=0x%llx commit=0x%llx "
				  "entry=0x%llx kind_exp=%llu kind_obs=%llu "
				  "target_exp=0x%llx target_obs=0x%llx "
				  "rax_exp=0x%llx rax_obs=0x%llx rsp_obs=0x%llx "
				  "verdict=%s comparable=%d rec_req=%llu "
				  "rec_done=%llu cur_req=%llu cur_done=%llu "
				  "rec_entry=%llu cur_entry=%llu note=%s",
				  pid, (unsigned long long)req_seq,
				  (unsigned long long)done_seq,
				  (unsigned long long)v.arm_id,
				  (unsigned long long)v.entered,
				  (unsigned long long)v.commit,
				  (unsigned long long)v.entry_id,
				  (unsigned long long)v.kind_exp,
				  (unsigned long long)v.kind_obs,
				  (unsigned long long)v.target_exp,
				  (unsigned long long)v.target_obs,
				  (unsigned long long)v.rax_exp,
				  (unsigned long long)v.rax_obs,
				  (unsigned long long)v.rsp_obs,
				  name[(v.verdict >= 0 && v.verdict <= 4) ?
				       v.verdict : 0],
				  v.comparable,
				  (unsigned long long)v.req_seq,
				  (unsigned long long)v.done_seq,
				  (unsigned long long)req_seq,
				  (unsigned long long)done_seq,
				  (unsigned long long)v.entry_id,
				  (unsigned long long)entry_now,
				  v.verdict == UML_NT_HOP_LIVE_COMMITTED ?
				  "a pre-jmp snapshot of this return; not a "
				  "jump, not guest execution" :
				  "no pre-jmp sample for the current return");
}

/*
 * Full-block ABI, pinned. These are compile-time assertions in the shared
 * header, so they are enforced by BOTH the ELF and the PE compilation — a
 * change that only shifts the PE layout (or pushes the block past the shared
 * section) fails to compile instead of passing a host-only runtime check.
 */
#define UML_NT_STUB_DATA_HOP_LIVE_OFF	0x3350u	/* append offset */
#define UML_NT_STUB_DATA_SIZE_V7	0x33C0u	/* sizeof the block (v7) */
#define UML_NT_STUB_DATA_SIZE_V8	0x3580u	/* + slots, rbp chain, ring copies */
#define UML_NT_STUB_SECTION_LIMIT	0x10000u /* UML_STUB_SECTION_SIZE */

_Static_assert(sizeof(struct uml_nt_hop_live) == UML_NT_HOP_LIVE_SIZE,
	       "hop_live record size is pinned");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, arm_id) == 0x00,
	       "arm_id at 0x00");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, req_seq) == 0x08,
	       "req_seq at 0x08");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, done_seq) == 0x10,
	       "done_seq at 0x10");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, entry_id) == 0x18,
	       "entry_id at 0x18");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, kind_exp) == 0x20,
	       "kind_exp at 0x20");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, target_exp) == 0x28,
	       "target_exp at 0x28");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, rax_exp) == 0x30,
	       "rax_exp at 0x30");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, entered) == 0x38,
	       "entered at 0x38");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, commit) == 0x40,
	       "commit at 0x40");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, kind_obs) == 0x48,
	       "kind_obs at 0x48");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, target_obs) == 0x50,
	       "target_obs at 0x50");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, rax_obs) == 0x58,
	       "rax_obs at 0x58");
_Static_assert(__builtin_offsetof(struct uml_nt_hop_live, rsp_obs) == 0x60,
	       "rsp_obs at 0x60");

#endif /* UML_NT_HOP_LIVE_H */
