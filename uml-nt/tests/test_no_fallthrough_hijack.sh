#!/usr/bin/env bash
# S444: a new case must never land inside a fallthrough group.
#
# case 140 was inserted between "case 332: statx" and the shared stat body, so
# newfstatat(262) with a0=AT_FDCWD(-100) fell straight into the setpriority
# handler, tripped its `which > 2` check, and returned -EINVAL. ld.so saw EINVAL,
# exited 127, and the boot died with "Attempted to kill init".
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

c140=$(grep -n 'case 140:' "$S" | cut -d: -f1)
c141=$(grep -n 'case 141:' "$S" | cut -d: -f1)
[ -n "$c140" ] && [ -n "$c141" ] || { echo "FAIL: setpriority/getpriority missing"; exit 1; }
[ "$c140" -lt "$c141" ] || { echo "FAIL: 140 after 141"; exit 1; }

# the stat group runs from case 5/262/332 to its own break; both new cases must
# lie outside that span
stat_first=$(grep -n 'case 5: /\* fstat' "$S" | cut -d: -f1)
stat_break=$(awk -v a="$stat_first" 'NR>a && /^[[:space:]]*break;/ {print NR; exit}' "$S")
[ -n "$stat_break" ] || { echo "FAIL: stat group has no break"; exit 1; }
if [ "$c140" -gt "$stat_first" ] && [ "$c140" -lt "$stat_break" ]; then
	echo "FAIL: case 140 sits inside the stat fallthrough group"; exit 1
fi
if [ "$c141" -gt "$stat_first" ] && [ "$c141" -lt "$stat_break" ]; then
	echo "FAIL: case 141 sits inside the stat fallthrough group"; exit 1
fi

# and each new case must have its own body (a break before the next case)
for c in "$c140" "$c141"; do
	nxt=$(awk -v a="$c" 'NR>a && /case [0-9]+:/ {print NR; exit}' "$S")
	brk=$(awk -v a="$c" 'NR>a && /^[[:space:]]*break;/ {print NR; exit}' "$S")
	[ -n "$brk" ] && [ "$brk" -lt "$nxt" ] || { echo "FAIL: case at $c has no body"; exit 1; }
done
echo "no_fallthrough_hijack: 140/141 stand alone, outside the stat group"
