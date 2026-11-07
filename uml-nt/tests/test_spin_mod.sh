#!/usr/bin/env bash
# S114: name the range a spinning conn sits in, and how deep its stack is.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
S="$HERE/../stub/stub.c"

grep -q '\[spin-mod\]' "$K" || { echo "FAIL: spin range unnamed"; exit 1; }
grep -q 'range=%s' "$K" || { echo "FAIL: no range field"; exit 1; }
grep -q 'host-module' "$K" || { echo "FAIL: host module band not distinguished"; exit 1; }
grep -q '0x7ff8' "$K" || { echo "FAIL: band is still a single prefix, not the 0x7ff8-0x7fff range"; exit 1; }

# unowned: stack slack + a comparable sequence number
grep -q 'slack=%lld' "$S" || { echo "FAIL: no stack slack at UNOWNED"; exit 1; }
grep -q 'stackbase=%llx stacksize=%llx' "$S" || { echo "FAIL: no stack extent"; exit 1; }
grep -q 'seq=%llu tick=%llu' "$S" || { echo "FAIL: UNOWNED has no comparable seq"; exit 1; }

# r15-watch carries a sequence too, so the two can be joined
grep -q 'seq=%llu' "$K" || { echo "FAIL: r15-watch has no seq"; exit 1; }
echo "spin_mod: range named, stack slack measured, both markers carry a seq"
