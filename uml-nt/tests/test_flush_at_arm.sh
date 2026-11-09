#!/usr/bin/env bash
# S483: delivery needs bash to park; bash never parks while junk arrives; junk was
# only cleared when delivering. Flush at ARM breaks the loop.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'int uml_nt_console_flush_all(int dport)' "$C" || { echo "FAIL: no flush-all"; exit 1; }
awk '/^int uml_nt_console_flush_all/,/^}/' "$C" | grep -q 'tty_ldisc_flush' \
	|| { echo "FAIL: ldisc not flushed at arm"; exit 1; }
awk '/^int uml_nt_console_flush_all/,/^}/' "$C" | grep -q 'uml_nt_con_ring_drop' \
	|| { echo "FAIL: ring not flushed at arm"; exit 1; }
grep -q '\[feed-stage\] flush-at-arm port=%d n=%u' "$C" || { echo "FAIL: flush not declared"; exit 1; }
# the call must sit at the arm point, before marker_pending
n=$(grep -n 'uml_nt_console_flush_all(nt_con_pick_port())' "$K" | head -1 | cut -d: -f1)
m=$(grep -n 'uml_nt_console_marker_pending((int)c->pid)' "$K" | head -1 | cut -d: -f1)
[ -n "$n" ] && [ -n "$m" ] && [ "$n" -lt "$m" ] || { echo "FAIL: flush is not before the arm"; exit 1; }
# the misleading label is gone
if grep -q '"marker-done"' "$K"; then echo "FAIL: misleading marker-done label"; exit 1; fi
grep -q 'not-armed-or-done' "$K" || { echo "FAIL: label not corrected"; exit 1; }
echo "flush_at_arm: both queues cleared when armed, label corrected"
