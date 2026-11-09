#!/usr/bin/env bash
# S467: the console is a shared queue — inject into the asking pid's buffer.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

if grep -q 'S467: inject the marker' "$S"; then echo "FAIL: dead inject code is back"; exit 1; fi
grep -q '\[feed-stage\] refeed n=%d eater_pid=%d' "$K" || { echo "FAIL: no re-feed"; exit 1; }
grep -q 'g_marker_refeed < 12' "$K" || { echo "FAIL: re-feed unbounded"; exit 1; }
grep -q '\[feed-stage\] marker-consumed pid=%d' "$K" || { echo "FAIL: consumption not declared"; exit 1; }



# the marker must be armed on con-read, not pushed into the ring
grep -q 'g_marker_pid = (int)c->pid;' "$K" || { echo "FAIL: readiness not recorded"; exit 1; }
if grep -q 'uml_nt_console_deliver_marker((int)c->pid)' "$K"; then
	echo "FAIL: still pushing the marker into the shared ring"; exit 1
fi
grep -q '\[feed-stage\] to=4 anchor=con-read ' "$K" \
	|| { echo "FAIL: transition not declared"; exit 1; }
# and the destination is taken from the snapshot, not a stale register
grep -q 'c->rd_dst = s->args\[1\];' "$S" || { echo "FAIL: dst still captured from a[]"; exit 1; }
echo "direct_feed: dead inject gone, re-feed bounded, consumption declared"
