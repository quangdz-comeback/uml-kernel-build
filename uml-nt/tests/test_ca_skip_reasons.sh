#!/usr/bin/env bash
# S32: every way the reserve can be skipped must name itself.
#
# Referee 41705346365 left a conn that died at the PAM dip with no [stack-reserve]
# and no [ca-src] line at all — the reserve block was reached ([grow] calls=597)
# yet nothing described the decision, because the record's counter lived on the
# shared answer block and had already been spent by earlier conns. A counter keyed
# to the log is rule #23's mistake; it now lives on the mm.
#
# This test is source-level on purpose: the gates are three early-outs inside one
# kernel-side function, and the contract is that each of them SPEAKS.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/vma.h"
fail=0
for r in reason=no-mm reason=round reason=plan; do
	grep -q "$r" "$S" || { echo "FAIL: no [ca-skip] for $r"; fail=1; }
done
# the counters belong to the object under investigation, not the shared block
grep -q "ca_src_n, ca_src_v" "$H" || { echo "FAIL: ca-src counters are not on the mm"; fail=1; }
grep -q "c->d->ca_src_n" "$S" && { echo "FAIL: ca-src counter still on the shared block"; fail=1; }
[ $fail -eq 0 ] || exit 1
echo "ca_skip_reasons: every skip speaks, counters live on the mm"
