#!/usr/bin/env bash
# S95: no standard clockid may be unanswerable.
#
# Referee 42341779431: login asked clock_gettime(CLOCK_MONOTONIC_RAW == 5) and
# got -EINVAL. A guest asking the time is not asking a question this kernel is
# allowed to refuse; the ABI defines 0..11.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
BODY=$(awk '/^static unsigned long long sys_clock_gettime/,/^}/' "$S")
echo "$BODY" | grep -q 'a\[0\] >= 12' \
	|| { echo "FAIL: clockid range is not the ABI's own"; exit 1; }
echo "$BODY" | grep -q 'SC_EINVAL' || { echo "FAIL: no rejection path left"; exit 1; }
# the old triplet gate must be gone
echo "$BODY" | grep -q 'a\[0\] != 7 /\* CLOCK_BOOTTIME' && \
	{ echo "FAIL: clockid 5 is still refused"; exit 1; }
echo "$BODY" | grep -q 'clock_odd_n' \
	|| { echo "FAIL: an unusual clock is answered silently"; exit 1; }
echo "clock_ids: 0..11 answer, 12+ keep EINVAL, odd ones are counted"
