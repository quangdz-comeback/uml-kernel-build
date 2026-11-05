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
	return (now_ns - last_ns) / 1000000ull >= 1000;
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
echo "spin_sampler: the kernel emits it"
