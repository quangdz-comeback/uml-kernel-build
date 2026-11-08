#!/usr/bin/env bash
# S454: a stub_data view that is unmapped must never be read again.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
M="$HERE/../kernel/overlay/arch/um/os-Windows/skas/mmctx.c"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

grep -q 'uml_nt_stub_view_add(data_va)' "$K" || { echo "FAIL: views are not registered"; exit 1; }
grep -q 'uml_nt_stub_view_del' "$M" || { echo "FAIL: destroy does not unregister"; exit 1; }
grep -q 'if (!uml_nt_stub_view_ok(d))' "$S" || { echo "FAIL: no guard"; exit 1; }
# the guard must refuse BEFORE args are read
n=$(grep -n 'if (!uml_nt_stub_view_ok(d))' "$S" | head -1 | cut -d: -f1)
a=$(grep -n 'const unsigned long long \*a = d->args;' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] && [ -n "$a" ] && [ "$n" -lt "$a" ] || { echo "FAIL: guard follows the deref"; exit 1; }
grep -q 'return;.*refuse, do not dereference' "$S" || { echo "FAIL: no refusal"; exit 1; }
grep -q '\[dangling-stub\]' "$S" || { echo "FAIL: refusal is silent"; exit 1; }
echo "stub_view_lifecycle: registered live, unregistered on death, refused before use"
