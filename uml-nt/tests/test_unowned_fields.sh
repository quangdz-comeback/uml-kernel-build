#!/usr/bin/env bash
# S119: the measurements the kernel needs must live in the shared block, not only
# on the stub's torn stderr copy.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H="$HERE/../kernel/overlay/arch/um/include/shared/stub_nt.h"
S="$HERE/../stub/stub.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

for f in unowned_slack unowned_stackbase unowned_stacksize tid; do
	grep -q "unsigned long long $f;" "$H" \
		|| { echo "FAIL: $f missing from the shared block"; exit 1; }
done
grep -q 'd->unowned_slack = (unsigned long long)slack;' "$S" \
	|| { echo "FAIL: the stub does not publish slack"; exit 1; }
grep -q '\[unowned\] pid %lu tid=%llu slack=%llu' "$K" \
	|| { echo "FAIL: the kernel record lacks the fields"; exit 1; }
grep -q 'stackbase=0x%llx stacksize=0x%llx' "$K" \
	|| { echo "FAIL: stack extent not printed"; exit 1; }
grep -q 'dead_holder=%s' "$K" || { echo "FAIL: no holder verdict"; exit 1; }
# published before the line is built, so the two copies agree
pub=$(grep -n 'd->unowned_slack =' "$S" | head -1 | cut -d: -f1)
line=$(grep -n 'stub: UNOWNED exception' "$S" | head -1 | cut -d: -f1)
if [ -z "$pub" ] || [ -z "$line" ] || [ "$pub" -ge "$line" ]; then
	echo "FAIL: fields published after the record"; exit 1
fi
echo "unowned_fields: slack/stackbase/stacksize/tid published and printed intact"
