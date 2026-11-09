#!/usr/bin/env bash
# S473: the marker must be at the head of the ring, not behind junk.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'tty_driver_flush_buffer(wt)' "$C" || { echo "FAIL: no flush before push"; exit 1; }
grep -q '\[feed-stage\] flush junk at=to4' "$C" || { echo "FAIL: flush not declared"; exit 1; }
# flush must precede the delivery, not follow it
f=$(grep -n 'tty_driver_flush_buffer(wt)' "$C" | cut -d: -f1)
d=$(grep -n 'to=4 anchor=con-read pid=%d' "$C" | cut -d: -f1)
[ -n "$f" ] && [ -n "$d" ] && [ "$f" -lt "$d" ] || { echo "FAIL: flush after the push"; exit 1; }
# the drain cap must leave room for the marker read
grep -q 'c->read_ok_n < 32' "$K" || { echo "FAIL: drain cap still 8"; exit 1; }
echo "flush_push: ring flushed before the marker, drain cap widened"
