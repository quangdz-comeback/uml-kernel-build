#!/usr/bin/env bash
# S467: the console is a shared queue — inject into the asking pid's buffer.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'uml_nt_console_marker_take' "$S" || { echo "FAIL: no direct injection"; exit 1; }
grep -q 'direct=1' "$S" || { echo "FAIL: injection not declared"; exit 1; }
grep -q 'memcpy((char \*)uml_boot.physmem_base + off, mk' "$S" \
	|| { echo "FAIL: payload not written to the buffer"; exit 1; }
grep -q 'd->retval = sizeof(mk) - 1;' "$S" || { echo "FAIL: read does not return the bytes"; exit 1; }
# the marker must be armed on con-read, not pushed into the ring
grep -q 'g_marker_pid = (int)c->pid;' "$K" || { echo "FAIL: readiness not recorded"; exit 1; }
if grep -q 'uml_nt_console_deliver_marker((int)c->pid)' "$K"; then
	echo "FAIL: still pushing the marker into the shared ring"; exit 1
fi
grep -q '\[feed-stage\] to=4 anchor=con-read pid=%d direct' "$K" \
	|| { echo "FAIL: transition not declared"; exit 1; }
# and the destination is taken from the snapshot, not a stale register
grep -q 'c->rd_dst = s->args\[1\];' "$S" || { echo "FAIL: dst still captured from a[]"; exit 1; }
echo "direct_feed: marker injected into the asking pid's read, once"
