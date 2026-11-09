#!/usr/bin/env bash
# S479: the pump must run for the marker's own pid, and refusals must say why.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"

grep -q '\[arm-gate\] pid=%d nr=%llu stage=%d pending=%d' "$K" \
	|| { echo "FAIL: refusals are silent"; exit 1; }
grep -q 'why=not-parked' "$K" || { echo "FAIL: no reason for a non-park"; exit 1; }
grep -q '"other-pid" : "marker-done"' "$K" || { echo "FAIL: no pid/done reasons"; exit 1; }
grep -q 'g_arm_gate_n < 64' "$K" || { echo "FAIL: gate log budget wrong"; exit 1; }
# the marker branch must accept a read park too, and not depend on stage
grep -q 'nr == 7 || nr == 23 || nr == 270 || nr == 271 ||' "$K" \
	|| { echo "FAIL: read park not accepted"; exit 1; }
grep -q '\[feed-arm\] pid %d nr=%llu stage=%d marker' "$K" \
	|| { echo "FAIL: marker arm not declared"; exit 1; }
# arm_feed must not force stage 1 while a marker is pending
awk '/^int uml_nt_console_arm_feed/,/^}/' "$C" | grep -q 'marker_is_pending() &&' \
	|| { echo "FAIL: stage still forced while marker pending"; exit 1; }
grep -q "ldisc-flushed pid=%d port=%d" "$C" || { echo "FAIL: no ldisc flush"; exit 1; }
grep -q "MARKER first8=" "$C" || { echo "FAIL: marker delivery not declared"; exit 1; }
echo "arm_gate: marker accepted on poll or read for its own pid; refusals named"
