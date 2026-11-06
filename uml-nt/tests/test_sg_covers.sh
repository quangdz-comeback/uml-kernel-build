#!/usr/bin/env bash
# S87 (report 386 §3): "already mapped" must be an answer, and the same rsp must
# not be asked twice.
#
# The guest's rsp sat exactly on the committed boundary (rsp == committed ==
# 0x60800000), so the model asked for one more run below it; the kernel refused
# because that run fell inside an existing VMA, remembered nothing, and the next
# round asked the identical question — 12.7k times, nothing learned.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cat > "$T/t.c" <<'C'
#include <stdio.h>
#include <assert.h>
#include "stackgrow_model.h"
int main(void)
{
	/* the VMA covers the whole requested run: the reserve is already there */
	assert(uml_nt_sg_covers(0x607F0000ull, 0x60800000ull, 0x607F0000ull,
				UML_NT_SG_RUN) == 1);
	/* covers it with room to spare */
	assert(uml_nt_sg_covers(0x60000000ull, 0x60800000ull, 0x607F0000ull,
				UML_NT_SG_RUN) == 1);
	/* partial: starts above the target, or ends inside it — not covered */
	assert(uml_nt_sg_covers(0x607F8000ull, 0x60800000ull, 0x607F0000ull,
				UML_NT_SG_RUN) == 0);
	assert(uml_nt_sg_covers(0x60000000ull, 0x607F8000ull, 0x607F0000ull,
				UML_NT_SG_RUN) == 0);
	/* the memo: the rsp that was answered "already covered" is not asked again */
	assert(uml_nt_sg_ask_again(0x60800000ull, 0x60800000ull) == 0);
	assert(uml_nt_sg_ask_again(0x60800000ull, 0x607ffff8ull) == 1);
	assert(uml_nt_sg_ask_again(0, 0x60800000ull) == 1);	/* nothing memoised */
	puts("ok");
	return 0;
}
C
D="$HERE/../kernel/overlay/arch/um/include/shared"
cc -I"$D" -o "$T/t" "$T/t.c" -Wall -Werror
out="$("$T/t")"
[ "$out" = "ok" ] || { echo "FAIL: $out"; exit 1; }
# the kernel actually uses both: an answer of 2, and the memo at the top
F="$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c"
grep -q 'uml_nt_sg_covers' "$F" || { echo "FAIL: fault.c never says 'already covered'"; exit 1; }
grep -q 'uml_nt_sg_ask_again' "$F" || { echo "FAIL: fault.c re-asks the settled rsp"; exit 1; }
grep -q 'ca_stop_rsp = rsp' "$F" || { echo "FAIL: the answered rsp is not remembered"; exit 1; }
echo "sg_covers: a covered reserve is an answer, and the question is asked once"
