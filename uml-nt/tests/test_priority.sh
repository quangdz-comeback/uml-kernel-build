#!/usr/bin/env bash
# S443: pam_limits dies without setpriority/getpriority, and Linux clamps nice.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/syscall.h"

grep -q 'case 140: /\* setpriority' "$S" || { echo "FAIL: no setpriority"; exit 1; }
grep -q 'case 141: /\* getpriority' "$S" || { echo "FAIL: no getpriority"; exit 1; }
grep -q 'int nice;' "$H" || { echo "FAIL: no per-conn nice"; exit 1; }

n=$(grep -n 'case 140: /\* setpriority' "$S" | cut -d: -f1)
blk=$(sed -n "$n,$((n + 30))p" "$S")
# invalid which is EINVAL, exactly the only error stock answers with
case "$blk" in *'> 2'*) ;; *) echo "FAIL: which is not range-checked"; exit 1;; esac
case "$blk" in *SC_EINVAL*) ;; *) echo "FAIL: no EINVAL path"; exit 1;; esac
# a nice value out of range must be CLAMPED, never refused
case "$blk" in *'nice = -20'*) ;; *) echo "FAIL: lower bound not clamped"; exit 1;; esac
case "$blk" in *'nice = 19'*) ;; *) echo "FAIL: upper bound not clamped"; exit 1;; esac
case "$blk" in *'ret = 0;'*) ;; *) echo "FAIL: setpriority can fail on a value"; exit 1;; esac
# getpriority must return the stored value, not an error
g=$(sed -n "$(grep -n 'case 141: /\* getpriority' "$S" | cut -d: -f1),+10p" "$S")
case "$g" in *'c->nice'*) ;; *) echo "FAIL: getpriority does not read the value"; exit 1;; esac
echo "priority: 140/141 implemented, which validated, nice clamped, value stored"
