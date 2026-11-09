#!/usr/bin/env bash
# S482: ONE marker state machine. Two parallel ones made a stage-0 delivery read
# "marker-done" from the machine nobody had set.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"

if grep -qE 'g_marker_(done|refeed|maybe_seen|pid)' "$K"; then
	echo "FAIL: stub_ctl still owns marker state"; exit 1
fi
grep -q 'static int g_mk_pending;' "$C" || { echo "FAIL: console.c lost the state"; exit 1; }
grep -q 'int uml_nt_console_marker_pid(void)' "$C" || { echo "FAIL: no pid accessor"; exit 1; }
grep -q 'uml_nt_console_marker_is_pending()' "$K" || { echo "FAIL: stub does not read the shared state"; exit 1; }
grep -q 'uml_nt_console_marker_pending((int)c->pid)' "$K" || { echo "FAIL: stub does not arm the shared state"; exit 1; }
# delivery must still refuse a zero/foreign pid
awk '/^int uml_nt_console_deliver_marker_now/,/^}/' "$C" | grep -q 'g_mk_pid == 0 || pid != g_mk_pid' \
	|| { echo "FAIL: pid guard lost in the merge"; exit 1; }
echo "one_marker_machine: console.c owns it, stub reads and arms it"
