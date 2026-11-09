#!/usr/bin/env bash
# S462: the marker may only be delivered for the armed login conn.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U="$HERE/../kernel/overlay/arch/um/os-Windows/util.c"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"

grep -q 'uml_nt_console_gate.stage != 3' "$C" || { echo "FAIL: marker not gated on stage 3"; exit 1; }
grep -q '\[feed-stage\] ignore-nonlogin' "$C" || { echo "FAIL: refusal is silent"; exit 1; }
grep -q 'nt_con_deliver_stage(nt_con_pick_port())' "$C" \
	|| { echo "FAIL: does not reuse the delivery machinery"; exit 1; }
if grep -q 'tty_insert_flip_string(&g_port\[dport\], &cmd\[i\]' "$C"; then
	echo "FAIL: marker still pokes tty core directly"; exit 1
fi
grep -q 'if (src != 0) {' "$U" || { echo "FAIL: kernel text can still arm"; exit 1; }
echo "feed_stage: marker only for the armed login conn, via the existing machinery"
