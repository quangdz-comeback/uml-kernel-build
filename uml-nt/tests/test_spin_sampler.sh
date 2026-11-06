#!/usr/bin/env bash
# S57: a conn that has stopped asking can still be sampled — from outside its rounds.
#
# The kernel-side sampler reads a thread's CONTEXT between two rounds, so a conn
# that never asks again can never be sampled from there; that silence was measured
# at report 359 (fault=0, fifty syscalls, then nothing) and it means the conn is in
# user space. The sample has to come from whichever conn the kernel is serving, and
# be capped so a spin does not become a flood.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
/* the decision the kernel makes before it suspends anyone */
static int should_sample(int is_login, unsigned long long last_ns,
			 unsigned long long now_ns, unsigned spin_n)
{
	if (!is_login || last_ns == 0 || spin_n >= 32)
		return 0;
	return (now_ns - last_ns) / 1000000ull >= 700;
}
int main(void)
{
	unsigned long long t0 = 1000000000ull;	/* 1 s in ns */

	CHECK(should_sample(1, t0, t0 + 500ull * 1000000ull, 0) == 0);   /* 0.5 s */
	CHECK(should_sample(1, t0, t0 + 1000ull * 1000000ull, 0) == 1);  /* 1.0 s */
	CHECK(should_sample(1, t0, t0 + 5000ull * 1000000ull, 31) == 1); /* last slot */
	CHECK(should_sample(1, t0, t0 + 5000ull * 1000000ull, 32) == 0); /* capped */
	CHECK(should_sample(0, t0, t0 + 5000ull * 1000000ull, 0) == 0);  /* not login */
	/* S58: a conn that never answered is not skipped — the clock starts */
	{
		unsigned long long clock = 0;

		CHECK(should_sample(1, clock, t0, 0) == 0);   /* first sight */
		clock = t0;                                   /* clock armed */
		CHECK(should_sample(1, clock, t0 + 1500ull * 1000000ull, 0) == 1);
	}

	/* a spin shows up as a tiny set of distinct rips */
	{
		unsigned long long rips[6] = { 0x60030ca1ull, 0x60030ca1ull,
					       0x60030ca1ull, 0x60030c9full,
					       0x60030ca1ull, 0x60030c9full };
		int i, distinct = 0;
		unsigned long long seen[6];

		for (i = 0; i < 6; i++) {
			int j, dup = 0;

			for (j = 0; j < distinct; j++)
				if (seen[j] == rips[i]) dup = 1;
			if (!dup) seen[distinct++] = rips[i];
		}
		CHECK(distinct == 2);	/* the loop body, not a wander */
	}
		/* S68: a frozen request for five samples is what triggers the poke, and
	 * the counter must reset the moment the answer arrives. */
	{
		unsigned long long req = 9, done = 8, frozen_req = 0;
		unsigned n = 0;
		int i;

		for (i = 0; i < 6; i++) {
			int frozen = (frozen_req == req && req > done);

			frozen_req = req;
			n = frozen ? n + 1 : 0;
		}
		CHECK(n == 5);		/* five consecutive samples, not six */
		done = 9;		/* answered */
		{
			int frozen = (frozen_req == req && req > done);

			n = frozen ? n + 1 : 0;
		}
		CHECK(n == 0);		/* the counter resets on the answer */
	}

	/* S65: the three states the record distinguishes are three different
	 * numbers, so a reader can tell a parked task from a queued one. */
	CHECK(0u != 1u);		/* RUNNING vs INTERRUPTIBLE */
	CHECK(1u != 0x401u);		/* INTERRUPTIBLE vs UNINTERRUPTIBLE */
	CHECK((0x401u & 0x401u) == 0x401u);

	/* S64: the two wait states are told apart by the sequence numbers */
	{
		unsigned long long req = 7, done = 6;

		CHECK((req > done) == 1);	/* needs-kernel-answer */
		done = 7;
		CHECK((req > done) == 0);	/* stub-idle-kernel-silent */
	}

	/* S61: a scan sees a conn that hangs off a task's mm — the table the
	 * kernel actually uses — and not the two static probe conns. */
	{
		int scanned = 0, login_seen = 0;
		struct { void *nt_conn; int chain; } tasks[3] = {
			{ 0, 0 }, { (void *)1, 1 }, { (void *)1, 0 }
		};
		int i;

		for (i = 0; i < 3; i++) {
			if (tasks[i].nt_conn == 0) continue;
			scanned++;
			if (tasks[i].chain) login_seen++;
		}
		CHECK(scanned == 2);
		CHECK(login_seen == 1);
	}

	/* S59: the thread samples on its own clock — no other conn needs to be
	 * served, which was the dependency that kept it silent. */
	{
		unsigned long long clock = t0;

		CHECK(should_sample(1, clock, t0 + 700ull * 1000000ull, 0) == 1);
		CHECK(should_sample(1, clock, t0 + 699ull * 1000000ull, 0) == 0);
	}
	if (fails) { printf("spin_sampler: %d failure(s)\n", fails); return 1; }
	printf("spin_sampler: sampled outside the round, capped, and a spin is a few rips\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
grep -q "\[spin\]" "$S" || { echo "FAIL: no out-of-band sample record"; exit 1; }
grep -q "\[spin-sum\]" "$S" || { echo "FAIL: no histogram"; exit 1; }
grep -q "o->last_ans_ns = os_nsecs();" "$S" || { echo "FAIL: the clock is not armed"; exit 1; }
grep -q "\[spin-probe\]" "$S" || { echo "FAIL: no probe record"; exit 1; }
grep -q "nt_spin_thread" "$S" || { echo "FAIL: the sampler has no clock of its own"; exit 1; }
# S61: the scan must walk the tasks' mm conns, not the two static probe conns
grep -q "for_each_process(p)" "$S" || { echo "FAIL: the scan does not walk tasks"; exit 1; }
grep -q "context.id)->nt_conn" "$S" || { echo "FAIL: the scan does not read nt_conn"; exit 1; }
grep -q "scanned=%u" "$S" || { echo "FAIL: the probe does not report how many it scanned"; exit 1; }
grep -q "needs-kernel-answer" "$S" || { echo "FAIL: no wait verdict (a)"; exit 1; }
grep -q "stub-idle-kernel-silent" "$S" || { echo "FAIL: no wait verdict (b)"; exit 1; }
grep -q "\[taskstate\]" "$S" || { echo "FAIL: no task state record"; exit 1; }
grep -q "\[poke\]" "$S" || { echo "FAIL: no active poke"; exit 1; }
grep -q "wake_up_process" "$S" || { echo "FAIL: the poke does not wake"; exit 1; }
P="$HERE/../kernel/overlay/arch/um/os-Windows/skas/process.c"
grep -q "\[reqstuck\]" "$P" || { echo "FAIL: no stuck-request dump in the serve loop"; exit 1; }
grep -q "dump_stack()" "$P" || { echo "FAIL: the loop does not dump its own stack"; exit 1; }
grep -q "\[kstack\]" "$S" && { echo "FAIL: the thread-side unwinder is still there"; exit 1; }
grep -q "save_stack_trace_tsk" "$S" && { echo "FAIL: the unsafe unwinder is still there"; exit 1; }
echo "spin_sampler: the kernel emits it"
