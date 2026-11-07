#!/usr/bin/env bash
# S94: the heavy instrument is OFF unless something asks for it.
#
# Report 394 symbolized all three faulting rips into the instrument blocks in
# syscall.c — heapwalk fragscan, capget witness, abort capture. If the camera is
# the culprit, a default boot must never enter them.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

grep -q '^int uml_nt_heavy;' "$S" \
	|| { echo "FAIL: no single heavy switch"; exit 1; }
# default is zero: the definition carries no initialiser that turns it on
awk '/^int uml_nt_heavy;/{print}' "$S" | grep -qv '= 1' \
	|| { echo "FAIL: heavy is on by default"; exit 1; }
# all three blocks are gated
grep -q 'uml_nt_heavy_on() && !heapwalk_done' "$S" \
	|| { echo "FAIL: heapwalk fragscan still runs by default"; exit 1; }
awk '/if \(uml_nt_heavy_on\(\)\)/,/uml_nt_capget_witness/' "$S" | grep -q 'capget_witness' \
	|| { echo "FAIL: capget witness still runs by default"; exit 1; }
awk '/^static void abrt_msg_capture/,/^}/' "$S" | grep -q 'if (!uml_nt_heavy_on())' \
	|| { echo "FAIL: the abort capture still runs by default"; exit 1; }
# and the cheap witnesses survive
grep -q '\[hdl\] in' "$S" || { echo "FAIL: [hdl] was dieted away"; exit 1; }
echo "heavy_off: three heavy blocks gated, cheap witnesses kept"
