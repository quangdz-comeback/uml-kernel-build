#!/usr/bin/env bash
# S96: with heavy off, no capture path may be entered at all.
#
# The 394 diet covered the print block at 4958, but abrt_writev_capture() has a
# second call site (4353) and the 16k-line referee faulted inside it
# (syscall.c:3958). A gate that covers one door is not a gate.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

body_of() { awk -v fn="$1" '$0 ~ "^static void " fn "\\(" {f=1} f {print} f && /^}/ {exit}' "$S"; }

for fn in abrt_msg_capture abrt_writev_capture; do
	b="$(body_of "$fn")"
	[ -n "$b" ] || { echo "FAIL: $fn not found"; exit 1; }
	case "$b" in
	*'if (!uml_nt_heavy_on())'*) ;;
	*) echo "FAIL: $fn has an ungated entry"; exit 1;;
	esac
	# the gate must come before any guest-memory touch: capture is expensive and
	# the uaccess sink must not be driven by a dieted-out diagnostic.
	gate=$(printf '%s\n' "$b" | grep -n 'if (!uml_nt_heavy_on())' | head -1 | cut -d: -f1)
	# comments mention the same calls; only code counts
	touch=$(printf '%s\n' "$b" | grep -vE '^\s*(/\*|\*|\*/)' |
		grep -nE 'abrt_read_str|uml_nt_uacc_walk|memcpy' | head -1 | cut -d: -f1)
	if [ -n "$touch" ] && [ "$gate" -gt "$touch" ]; then
		echo "FAIL: $fn touches guest memory before the gate"; exit 1
	fi
done

# the switch defaults to off
grep -q '^int uml_nt_heavy;' "$S" || { echo "FAIL: no switch"; exit 1; }
grep -q '^int uml_nt_heavy = 1' "$S" && { echo "FAIL: heavy defaults on"; exit 1; }

# both call sites still exist and both are the gated functions above
grep -q 'abrt_writev_capture(c, d, a, ret);' "$S" || { echo "FAIL: second call site gone"; exit 1; }
grep -q 'abrt_msg_capture(c, msg_va);' "$S" || { echo "FAIL: abort call site gone"; exit 1; }

echo "heavy_noop: both capture entries gate before their first guest read"
