// SPDX-License-Identifier: GPL-2.0
/*
 * tests/test_hop_live.c — the plain-hop witness logic and its death line.
 *
 * Drives the PRODUCTION header (hop_live.h): the arming helper, the validity
 * classifier and the death formatter, through a recording sink. What is under
 * test is exactly the attribution rule the death log relies on — a sample is
 * only comparable when the arm id matches both the entered and the committed
 * id and the request sequence matches; everything else is named as absent,
 * armed-only, entered-only or stale.
 *
 * Host logic only: it says nothing about Windows executing the trampolines.
 */
#include <stdio.h>
#include <string.h>

#include <diag_record.h>
#include <hop_live.h>

static int fails;

#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

/* ---- recording sink ---------------------------------------------------- */
static int calls;
static char got[UML_NT_DIAG_CAP * 2];
static int got_len;
static char line[UML_NT_DIAG_CAP];	/* the producer's own buffer */

static int fmt(char *buf, unsigned int cap, const char *f, va_list ap)
{
	return vsnprintf(buf, cap, f, ap);
}

static int sink(const char *buf, unsigned int len)
{
	calls++;
	got_len = (int)len;
	snprintf(got, sizeof(got), "%s", buf);
	return (int)len;
}

static const struct uml_nt_diag_ops ops = { fmt, sink };

static void arm_sys(struct uml_nt_hop_live *l, __u64 id)
{
	uml_nt_hop_live_arm(l, id, UML_NT_HOP_KIND_SYS, 0x606c9af7ull,
			    0ull /* the syscall's RAX is 0 */, 367, 366,
			    9001 /* the VEH entry this return belongs to */);
}

/* the trampoline's own writes, in the order the asm performs them */
static void trampoline_commit(struct uml_nt_hop_live *l, __u64 kind,
			      __u64 target, __u64 rax, __u64 rsp)
{
	l->entered = l->arm_id;
	l->kind_obs = kind;
	l->target_obs = target;
	l->rax_obs = rax;
	l->rsp_obs = rsp;
	l->commit = l->arm_id;		/* commit last */
}

static void test_absent(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	uml_nt_hop_live_read(&l, 0, 0, 0, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ABSENT);
	CHECK(v.comparable == 0);
	uml_nt_hop_live_view_absent(&v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ABSENT);
}

static void test_armed_only_and_entered_only(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	CHECK(uml_nt_hop_live_arm(&l, 7, UML_NT_HOP_KIND_SYS, 0x1000, 0, 42, 41, 5) == 7);
	uml_nt_hop_live_read(&l, 42, 41, 5, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ARMED_ONLY);	/* death before entry */
	CHECK(v.comparable == 0);

	l.entered = 7;					/* entry ran, no commit */
	uml_nt_hop_live_read(&l, 42, 41, 5, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ENTERED_ONLY);
	CHECK(v.comparable == 0);
}

static void test_committed_sys(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	arm_sys(&l, 11);
	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x606c9af7ull, 0ull,
			  0x6086eaa8ull);
	uml_nt_hop_live_read(&l, 367, 366, 9001, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 1);
	CHECK(v.rax_obs == 0);			/* a legitimate zero sample */
	CHECK(v.target_obs == 0x606c9af7ull);	/* trap+2 */
	CHECK(v.rax_exp == 0);
}

static void test_committed_fault_nonzero_rax(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	uml_nt_hop_live_arm(&l, 12, UML_NT_HOP_KIND_FAULT, 0x606c9af5ull,
			    0x7dull, 367, 366, 9002);
	trampoline_commit(&l, UML_NT_HOP_KIND_FAULT, 0x606c9af5ull, 0x7dull,
			  0x6086ea88ull);
	uml_nt_hop_live_read(&l, 367, 366, 9002, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 1);
	CHECK(v.rax_obs == 0x7d);
	CHECK(v.target_obs == 0x606c9af5ull);	/* unchanged, replayed */
}

static void test_two_arms_same_done_seq(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	/* fast-path returns can repeat done_seq: the arm id, not the done
	 * sequence, is the identity. */
	memset(&l, 0, sizeof(l));
	uml_nt_hop_live_arm(&l, 21, UML_NT_HOP_KIND_SYS, 0x2000, 0, 50, 49, 6);
	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x2000, 0, 0x1111);
	uml_nt_hop_live_read(&l, 50, 49, 6, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.arm_id == 21);

	uml_nt_hop_live_arm(&l, 22, UML_NT_HOP_KIND_SYS, 0x3000, 0, 50, 49, 7);
	uml_nt_hop_live_read(&l, 50, 49, 7, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ARMED_ONLY);
	CHECK(v.arm_id == 22);
	CHECK(v.commit == 0);		/* the previous return's record is gone */

	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x3000, 0, 0x2222);
	uml_nt_hop_live_read(&l, 50, 49, 7, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.arm_id == 22 && v.commit == 22);
	CHECK(v.target_obs == 0x3000);
}

/* Astra's counterexample: arm=7, entered=0, commit=7, matching kind and
 * request. A commit alone is not an identity — entered must agree too. */
static void test_incomplete_identity(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	arm_sys(&l, 7);
	l.entered = 0;			/* the entry mark was never written */
	l.kind_obs = UML_NT_HOP_KIND_SYS;
	l.target_obs = 0x606c9af7ull;
	l.rax_obs = 0;
	l.commit = 7;			/* but the tail committed */
	uml_nt_hop_live_read(&l, 367, 366, 9001, &v);
	CHECK(v.verdict != UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 0);

	/* and an arm with no VEH-entry identity is incomplete as well */
	memset(&l, 0, sizeof(l));
	uml_nt_hop_live_arm(&l, 8, UML_NT_HOP_KIND_SYS, 0x1000, 0, 367, 366, 0);
	l.entered = 8;
	l.commit = 8;
	uml_nt_hop_live_read(&l, 367, 366, 9001, &v);
	CHECK(v.verdict != UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 0);
}

static void test_stale(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	arm_sys(&l, 31);
	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x606c9af7ull, 0, 0x1234);
	/* the reader's request has moved on: the record is from an older
	 * return and must not be compared */
	uml_nt_hop_live_read(&l, 999, 366, 9001, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_STALE);
	CHECK(v.comparable == 0);

	/* a commit that belongs to a different arm is stale even when the
	 * sequence matches */
	memset(&l, 0, sizeof(l));
	arm_sys(&l, 32);
	l.entered = 32;
	l.commit = 31;
	uml_nt_hop_live_read(&l, 367, 366, 9001, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_STALE);
	CHECK(v.comparable == 0);
}

/* Astra's SS_STRAY counterexample: a newer unsampled return with identical
 * req/done must not inherit the previous entry's comparable record. */
static void test_newer_entry_is_not_comparable(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	arm_sys(&l, 61);
	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x606c9af7ull, 0, 0x1111);
	uml_nt_hop_live_read(&l, 367, 366, 9001, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
	CHECK(v.comparable == 1);

	/* the next attempt never armed: same sequences, newer entry */
	uml_nt_hop_live_read(&l, 367, 366, 9002, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_STALE);
	CHECK(v.comparable == 0);
}

static void test_invalidate(void)
{
	struct uml_nt_hop_live l;
	struct uml_nt_hop_live_view v;

	memset(&l, 0, sizeof(l));
	arm_sys(&l, 41);
	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x606c9af7ull, 0, 0x99);
	uml_nt_hop_live_invalidate(&l);
	uml_nt_hop_live_read(&l, 367, 366, 9001, &v);
	CHECK(v.verdict == UML_NT_HOP_LIVE_ABSENT);
	CHECK(v.comparable == 0);
}

static void test_death_line(void)
{
	struct uml_nt_hop_live l;
	int rc;

	memset(&l, 0, sizeof(l));
	arm_sys(&l, 51);
	trampoline_commit(&l, UML_NT_HOP_KIND_SYS, 0x606c9af7ull, 0, 0x6086eaa8ull);

	calls = 0;
	rc = uml_nt_hop_live_format(line, sizeof(line), &ops, &l, 367, 366, 9001, 8100);
	CHECK(calls == 1);			/* one record, one write */
	CHECK(rc == UML_NT_DIAG_OK);
	CHECK(got_len > 0 && got[got_len - 1] == '\n');
	CHECK(strstr(got, "[hop-live] pid=8100") != NULL);
	CHECK(strstr(got, "req=367 done=366") != NULL);
	CHECK(strstr(got, "arm=0x33") != NULL);		/* 51 decimal */
	CHECK(strstr(got, "verdict=committed") != NULL);
	CHECK(strstr(got, "comparable=1") != NULL);
	CHECK(strstr(got, "target_obs=0x606c9af7") != NULL);
	CHECK(strstr(got, "rax_obs=0x0") != NULL);
	/* the wording must not claim more than a pre-jmp snapshot */
	CHECK(strstr(got, "not a jump, not guest execution") != NULL);

	/* absent: the line still says so, and never claims comparable */
	calls = 0;
	rc = uml_nt_hop_live_format(line, sizeof(line), &ops, 0, 367, 366, 0, 2);
	CHECK(calls == 1);
	CHECK(rc == UML_NT_DIAG_OK);
	CHECK(strstr(got, "verdict=absent") != NULL);
	CHECK(strstr(got, "comparable=0") != NULL);
	CHECK(strstr(got, "no pre-jmp sample for the current return") != NULL);

	/* stale */
	calls = 0;
	rc = uml_nt_hop_live_format(line, sizeof(line), &ops, &l, 5, 4, 9001, 3);
	CHECK(calls == 1);
	CHECK(strstr(got, "verdict=stale") != NULL);
	CHECK(strstr(got, "comparable=0") != NULL);
}

int main(void)
{
	test_absent();
	test_armed_only_and_entered_only();
	test_committed_sys();
	test_committed_fault_nonzero_rax();
	test_two_arms_same_done_seq();
	test_incomplete_identity();
	test_stale();
	test_newer_entry_is_not_comparable();
	test_invalidate();
	test_death_line();

	if (fails) {
		printf("test_hop_live: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_hop_live: all ok\n");
	return 0;
}
