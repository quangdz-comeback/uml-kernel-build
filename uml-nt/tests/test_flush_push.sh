#!/usr/bin/env bash
# S474: the flush never ran because it lived in a function the push no longer
# calls. It must sit on the push path and it must speak.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'int uml_nt_console_flush_port(int dport)' "$C" || { echo "FAIL: no flush function"; exit 1; }
for why in wt-null no-ops; do
	grep -q "flush unavailable why=$why" "$C" \
		|| { echo "FAIL: silent on $why"; exit 1; }
done
grep -q 'flush manual n=%u port=%d' "$C" || { echo "FAIL: no manual fallback"; exit 1; }
grep -q 'flush driver port=%d' "$C" || { echo "FAIL: driver flush not declared"; exit 1; }
# the call must be on the to=4 push path, before the delivery
n=$(grep -n 'g_marker_pid = (int)c->pid;' "$K" | head -1 | cut -d: -f1)
blk=$(sed -n "${n},$((n + 4))p" "$K")
case "$blk" in *'uml_nt_console_flush_port(nt_con_pick_port())'*) ;; *) echo "FAIL: flush not on the push path"; exit 1;; esac
case "$blk" in *'nt_con_deliver_stage'*) ;; *) echo "FAIL: delivery missing"; exit 1;; esac
f=$(printf '%s\n' "$blk" | grep -n 'uml_nt_console_flush_port' | head -1 | cut -d: -f1)
d=$(printf '%s\n' "$blk" | grep -n 'nt_con_deliver_stage' | head -1 | cut -d: -f1)
[ "$f" -lt "$d" ] || { echo "FAIL: flush after delivery"; exit 1; }
grep -q 'c->read_ok_n < 32' "$K" || { echo "FAIL: drain cap still 8"; exit 1; }
# S475: the reader is fed from g_con_ring; the marker must go there
grep -q 'uml_nt_con_ring_push(&g_con_ring' "$C" \
	|| { echo "FAIL: delivery still bypasses the reader's queue"; exit 1; }
if awk '/int nt_con_deliver_stage/,/^}/' "$C" | grep -q 'tty_insert_flip_string'; then
	echo "FAIL: delivery still pushes into the tty flip buffer"; exit 1
fi
grep -q 'flush confeed n=%u' "$C" || { echo "FAIL: ring flush not reported"; exit 1; }
echo "flush_push: marker enters the ring the reader drains; flush reports it"
