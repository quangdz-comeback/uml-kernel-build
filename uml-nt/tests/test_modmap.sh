#!/usr/bin/env bash
# S115: the stub publishes its module map; the kernel names a host rip with it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H="$HERE/../kernel/overlay/arch/um/include/shared/stub_nt.h"
S="$HERE/../stub/stub.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'mod_base\[2\]' "$H" || { echo "FAIL: no module map in the shared block"; exit 1; }
grep -q 'mod_size\[2\]' "$H" || { echo "FAIL: no sizes"; exit 1; }
grep -q 'mod_seq' "$H" || { echo "FAIL: no publication sequence"; exit 1; }
grep -q 'publish_module_map(d)' "$S" || { echo "FAIL: map never published"; exit 1; }
grep -q 'GetModuleInformation' "$S" || { echo "FAIL: no module information"; exit 1; }
# published once at init, not in the dispatch path
n_pub=$(grep -c 'publish_module_map(d)' "$S")
[ "$n_pub" -eq 1 ] || { echo "FAIL: published more than once"; exit 1; }
# the spin line must use the map, with a fallback name
grep -q 'mod=%s +0x%llx' "$K" || { echo "FAIL: spin does not name a module"; exit 1; }
grep -q '"ntdll.dll"' "$K" || { echo "FAIL: ntdll not named"; exit 1; }
grep -q '"stub.exe"' "$K" || { echo "FAIL: stub.exe not named"; exit 1; }
echo "modmap: published once, read with a name and an offset"
