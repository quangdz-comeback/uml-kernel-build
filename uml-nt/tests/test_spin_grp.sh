#!/usr/bin/env bash
# S117: a deadlock is one fact, not 1449 lines.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
grep -q '\[spin-grp\]' "$K" || { echo "FAIL: spins are not grouped"; exit 1; }
grep -q 'samples=%lu (same site)' "$K" || { echo "FAIL: no sample count per site"; exit 1; }
grep -q '\[spin-stuck\]' "$K" || { echo "FAIL: no stuck classification"; exit 1; }
# one line per site per window, not per sample
n=$(grep -n '\[spin\] pid' "$K" | head -1 | cut -d: -f1)
blk=$(sed -n "$((n - 25)),$((n + 5))p" "$K")
case "$blk" in *'grp_rip != rip'*) ;; *) echo "FAIL: no collapse on (pid, rip)"; exit 1;; esac
case "$blk" in *'grp_n++'*) ;; *) echo "FAIL: no suppression path"; exit 1;; esac
echo "spin_grp: samples collapse per (pid,rip) window, stuck sites flagged"
