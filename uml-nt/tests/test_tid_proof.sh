#!/usr/bin/env bash
# S118: the deadlock proof is a tid comparison, so both sides must carry one.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H="$HERE/../kernel/overlay/arch/um/include/shared/stub_nt.h"
S="$HERE/../stub/stub.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'unsigned long long tid;' "$H" || { echo "FAIL: the shared block carries no tid"; exit 1; }
grep -q 'GetCurrentThreadId' "$S" || { echo "FAIL: the stub never reports its thread"; exit 1; }
grep -q 'tid=%llu' "$S" || { echo "FAIL: UNOWNED has no tid"; exit 1; }
grep -q 'dead_tid' "$K" || { echo "FAIL: the kernel does not keep the dead tid"; exit 1; }
grep -q 'dead_holder=%s' "$K" || { echo "FAIL: spin-stuck cannot name the holder"; exit 1; }
grep -q 'tid=%llu (same site)' "$K" || { echo "FAIL: groups do not carry tids"; exit 1; }
echo "tid_proof: both sides carry a tid and the comparison is printed"
