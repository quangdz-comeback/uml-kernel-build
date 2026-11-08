#!/usr/bin/env bash
# S444: a new case must never land inside a fallthrough group.
#
# case 140 was inserted between "case 332: statx" and the shared stat body, so
# newfstatat(262) with a0=AT_FDCWD(-100) fell into the setpriority handler, tripped
# `which > 2`, and returned -EINVAL where good runs return -2. ld.so exited 127 and
# the boot died with "Attempted to kill init".
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

c140=$(grep -n 'case 140:' "$S" | cut -d: -f1)
c141=$(grep -n 'case 141:' "$S" | cut -d: -f1)
if [ -z "$c140" ] || [ -z "$c141" ]; then echo "FAIL: setpriority/getpriority missing"; exit 1; fi
[ "$c140" -lt "$c141" ] || { echo "FAIL: 140 after 141"; exit 1; }

# The robust rule: the nearest non-blank, non-comment line ABOVE the case must be a
# break — that is what makes a label start its own group instead of joining one.
for c in "$c140" "$c141"; do
	prev=$(awk -v a="$c" 'NR<a && $0 !~ /^[[:space:]]*($|\/\/)/ && $0 !~ /^[[:space:]]*\*/ {last=$0} END{print last}' "$S")
	case "$prev" in
	*break\;*) ;;
	*) printf 'FAIL: case at line %s does not follow a break (prev: %s)\n' "$c" "$prev"; exit 1;;
	esac
done

# and each must reach its own break before the next case label
for c in "$c140" "$c141"; do
	nxt=$(awk -v a="$c" 'NR>a && /case [0-9]+:/ {print NR; exit}' "$S")
	brk=$(awk -v a="$c" 'NR>a && /^[[:space:]]*break;/ {print NR; exit}' "$S")
	if [ -z "$brk" ] || [ "$brk" -ge "$nxt" ]; then echo "FAIL: case at $c has no body"; exit 1; fi
done

# the stat group must NOT contain either label
stat=$(grep -n 'case 262: /\* newfstatat' "$S" | cut -d: -f1)
st137=$(grep -n 'case 137: /\* statfs' "$S" | cut -d: -f1)
if [ "$c140" -gt "$stat" ] && [ "$c140" -lt "$st137" ]; then echo "FAIL: case 140 still inside the stat group"; exit 1; fi
echo "no_fallthrough_hijack: 140/141 each follow a break, outside the stat group"
