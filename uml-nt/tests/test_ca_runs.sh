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
	if (fails) { printf("ca_runs: %d failure(s)\n", fails); return 1; }
	printf("ca_runs: 4 runs per ordinary answer, 128 only by experiment\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
