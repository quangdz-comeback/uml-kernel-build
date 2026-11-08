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
# S455: a full registry must shout, not silently drop a live view
grep -q '\[view-reg-full\]' "$K" || { echo "FAIL: registry overflow is silent"; exit 1; }
grep -q 'uml_nt_view_reg_full_n++' "$K" || { echo "FAIL: overflow not counted"; exit 1; }
# and it must be a set, not an append: a duplicate va returns early
grep -q 'if (stub_views\[i\] == va)' "$K" || { echo "FAIL: duplicate registration not prevented"; exit 1; }
# the spawn failure path must release the slot it reserved
awk '/^fail:/{f=1} f&&/uml_nt_stub_view_del\(data_va\)/{found=1} END{exit !found}' "$K" \
	|| { echo "FAIL: fail path leaks a registry slot"; exit 1; }
echo "stub_view_lifecycle: registered live, unregistered on death, refused before use"
