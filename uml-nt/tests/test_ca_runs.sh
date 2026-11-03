#!/usr/bin/env bash
# S22: how many runs the answer-time reserve asks for.
#
# The third link of the stack trio: a fork child with correct bounds and an
# allocator that avoids its reservation still needs something COMMITTED below
# its stack. That reserve is asked for per answer, and the policy used to be
# "8 MiB or nothing" — nothing by default.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <stackreserve_model.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
int main(void)
{
	/* an ordinary answer that carries the guest's registers: a small,
	 * bounded reserve (4 runs = 256 KiB) */
	CHECK(uml_nt_ca_runs(0, 1) == UML_NT_CA_DEFAULT_RUNS);
	CHECK(UML_NT_CA_DEFAULT_RUNS == 4);
	/* no registers: nothing to anchor a reserve on */
	CHECK(uml_nt_ca_runs(0, 0) == 0);
	/* the deliberate experiment still asks for the whole reservation */
	CHECK(uml_nt_ca_runs(1, 1) == 128);
	CHECK(uml_nt_ca_runs(1, 0) == 128);
	/* S22b: the policy is per answer. An answer without registers (the
	 * first one a process may see) must not latch zero for every answer
	 * that follows — that is what kept the reserve from ever running. */
	{
		int latched = uml_nt_ca_runs(0, 0);	/* first answer: no regs */

		CHECK(latched == 0);
		CHECK(uml_nt_ca_runs(0, 1) == UML_NT_CA_DEFAULT_RUNS);
	}
	/* S22d: the target predicate. rsp inside the reservation, the run just
	 * below it free -> reserve; that run overlapping an existing view ->
	 * skip; rsp outside the reservation -> skip. */
	{
		struct uml_nt_ca_view v[2];
		unsigned long long lo = 0x60000000ull, hi = 0x60800000ull;
		unsigned long long rsp = 0x607ff000ull, t = 0;

		v[0].va = 0x1000; v[0].len = 0x1000;
		v[1].va = 0; v[1].len = 0;

		/* free target inside the reservation */
		CHECK(uml_nt_ca_target(rsp, lo, hi, 1, 0, v, 1, &t) == 1);
		CHECK(t == 0x607e0000ull);	/* run below the one holding rsp */

		/* the same target, now overlapping an existing view */
		v[0].va = 0x607d8000ull; v[0].len = 0x10000ull;
		CHECK(uml_nt_ca_target(rsp, lo, hi, 1, 0, v, 1, &t) == 0);

		/* rsp outside the reservation */
		CHECK(uml_nt_ca_target(0x1000ull, lo, hi, 1, 0, v, 1, &t) == 0);

		/* no registers to anchor on */
		CHECK(uml_nt_ca_target(rsp, lo, hi, 0, 0, v, 0, &t) == 0);

		/* no reservation at all */
		CHECK(uml_nt_ca_target(rsp, 0, 0, 1, 0, v, 0, &t) == 0);
	}
	if (fails) { printf("ca_runs: %d failure(s)\n", fails); return 1; }
	printf("ca_runs: 4 runs per ordinary answer, 128 only by experiment\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
