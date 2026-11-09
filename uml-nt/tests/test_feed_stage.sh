#!/usr/bin/env bash
# S461: the gate arms only on guest text, and the marker is delivered on con-read.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U="$HERE/../kernel/overlay/arch/um/os-Windows/util.c"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

# (1) kernel text must never arm a stage
grep -q 'if (src != 0) {' "$U" || { echo "FAIL: kernel fragments still reach the matcher"; exit 1; }
grep -q '\[feedgate\] ignore-kernel n=%d' "$U" || { echo "FAIL: ignore is silent"; exit 1; }
grep -q 'g_feed_kernel_ignored++' "$U" || { echo "FAIL: ignore not counted"; exit 1; }
n=$(grep -n 'if (src != 0) {' "$U" | head -1 | cut -d: -f1)
sc=$(grep -n 'uml_nt_feed_gate_scan(&uml_nt_console_gate' "$U" | head -1 | cut -d: -f1)
[ "$n" -lt "$sc" ] || { echo "FAIL: the guard follows the scan"; exit 1; }

# (2) stage 4 on con-read, delivered once
grep -q 'void uml_nt_console_deliver_marker' "$C" || { echo "FAIL: no marker delivery"; exit 1; }
grep -q 'g_marker_delivered' "$C" || { echo "FAIL: marker can repeat"; exit 1; }
grep -q 'to=4 anchor=con-read' "$C" || { echo "FAIL: stage 4 not declared"; exit 1; }
grep -q 'uml_nt_console_deliver_marker((int)c->pid)' "$K" \
	|| { echo "FAIL: con-read does not trigger delivery"; exit 1; }
echo "feed_stage: guest-only anchors, stage 4 on con-read, once"
