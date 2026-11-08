#!/usr/bin/env bash
# S452: every uncommitted-page refusal names its own call site.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c"

grep -q 'uml_nt_phys_miss_total' "$P" || { echo "FAIL: no counter"; exit 1; }
grep -q 'uml_nt_phys_miss_caller\[8\]' "$P" || { echo "FAIL: no per-caller table"; exit 1; }
n=$(grep -n 'phys_miss_note((unsigned long long)off)' "$P" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: refusals are not recorded"; exit 1; }
# recorded before the refusal returns, and only on the uncommitted path
blk=$(sed -n "$((n - 3)),$((n + 2))p" "$P")
case "$blk" in *'return -1'*) ;; *) echo "FAIL: not on the refusal path"; exit 1;; esac
case "$blk" in *'refs[first] == 0'*) ;; *) echo "FAIL: not gated on refs==0"; exit 1;; esac
# no os_info in this file: it is log-free by design
if grep -q 'os_info' "$P"; then echo "FAIL: os_info reached a log-free file"; exit 1; fi
echo "phys_miss: refusals counted per caller, file stays log-free"
