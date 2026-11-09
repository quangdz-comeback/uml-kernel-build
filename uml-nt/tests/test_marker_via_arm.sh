#!/usr/bin/env bash
# S478: the marker must ride the pump (arm point), the only path that has ever
# delivered bytes a reader consumed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'uml_nt_console_marker_pending(pid)' "$C" || { echo "FAIL: no pending state"; exit 1; }
grep -q 'marker-via-arm pid=%d port=%d' "$C" || { echo "FAIL: arm delivery not declared"; exit 1; }
# arm_feed must have the marker branch
awk '/^int uml_nt_console_arm_feed/,/^}/' "$C" | grep -q 'uml_nt_console_marker_is_pending' \
	|| { echo "FAIL: arm_feed does not deliver the marker"; exit 1; }
# and the to=4 path must no longer push
n=$(grep -n 'to=4 anchor=con-read' "$K" | head -1 | cut -d: -f1)
blk=$(sed -n "$((n - 8)),$((n + 3))p" "$K")
case "$blk" in *'uml_nt_console_marker_pending'*) ;; *) echo "FAIL: to=4 does not set pending"; exit 1;; esac
if printf '%s\n' "$blk" | grep -q 'nt_con_deliver_stage'; then
	echo "FAIL: to=4 still pushes directly"; exit 1
fi
echo "marker_via_arm: to=4 sets pending, the arm delivers it"
