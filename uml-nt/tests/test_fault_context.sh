#!/usr/bin/env bash
# S452: a rip in mid-instruction is not a data fault; three lines decide.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/start_up.c"

grep -q 'rip-page readable=%d' "$S" || { echo "FAIL: no byte dump at rip"; exit 1; }
grep -q 'stack\[%d..%d\]' "$S" || { echo "FAIL: no stack top"; exit 1; }
# readability must go through the existing ntabi VirtualQuery wrapper
grep -q 'uml_nt_page_readable(rip)' "$S" || { echo "FAIL: rip page unguarded"; exit 1; }
grep -q 'uml_nt_page_readable(srsp' "$S" || { echo "FAIL: stack page unguarded"; exit 1; }
# no direct VirtualQuery call in the new block (ntabi only)
n=$(grep -n 'rip-page readable=%d' "$S" | cut -d: -f1)
blk=$(sed -n "$((n - 20)),$((n + 3))p" "$S")
case "$blk" in *'nt->VirtualQuery'*) echo "FAIL: direct VirtualQuery in the report path"; exit 1;; esac
echo "fault_context: rip bytes, guarded stack top, ntabi-only readability"
