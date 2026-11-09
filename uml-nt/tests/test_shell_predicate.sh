#!/usr/bin/env bash
# S471: check the predicate by RUNNING it, not by grepping it.
#
# The 470 version looped while i + 5 <= len, but "bash" is four bytes: for
# '/bin/bash' the match sits at i = 5 and 5 + 5 > 9, so the tail was never
# examined, is_shell answered 0, stage 3 never armed, and the marker was never
# delivered. The guard only asserted that agetty does not arm — it never asserted
# that bash DOES, which is why the bug shipped.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'int uml_nt_exec_path_is_shell(const char \*p)' "$K" \
	|| { echo "FAIL: no shell predicate"; exit 1; }
grep -q 'i + 4 <= len' "$K" || { echo "FAIL: the 4-byte bound is not used"; exit 1; }
if grep -qE 'for \(i = 0; i \+ 5 <= len' "$K"; then
	echo "FAIL: the off-by-one bound is back"; exit 1
fi

# extract the real function and run it
awk '/^int uml_nt_exec_path_is_shell\(const char \*p\)/,/^}/' "$K" > /tmp/pred_body.c
[ -s /tmp/pred_body.c ] || { echo "FAIL: could not extract the predicate"; exit 1; }
cat > /tmp/pred_test.c <<'C'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pred_body.c"
int main(void)
{
	struct { const char *p; int want; } c[] = {
		{ "/bin/bash", 1 }, { "/bin/sh", 1 }, { "bash", 1 },
		{ "/sbin/agetty", 0 }, { "/bin/login", 0 }, { "", 0 },
	};
	int i, bad = 0;
	for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++) {
		int got = uml_nt_exec_path_is_shell(c[i].p);
		if (got != c[i].want) {
			printf("FAIL: is_shell(\"%s\") = %d, want %d\n",
			       c[i].p, got, c[i].want);
			bad = 1;
		}
	}
	if (!bad)
		printf("shell_predicate: bash/sh arm, agetty/login do not\n");
	return bad;
}
C
cc -I /tmp -o /tmp/pred_test /tmp/pred_test.c 2>&1 | head -3
/tmp/pred_test

n=$(grep -n "login chain armed by exec" "$K" | head -1 | cut -d: -f1)
blk=$(sed -n "${n},$((n + 18))p" "$K")
case "$blk" in *'uml_nt_exec_path_is_shell(g_exec_path)'*) ;; *) echo "FAIL: arm does not test the path"; exit 1;; esac
grep -q 'g_marker_refeed < 12' "$K" || { echo "FAIL: refeed cap removed"; exit 1; }
