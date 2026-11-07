#!/usr/bin/env bash
# S110: what the guest is born with, printed before the thread resumes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
n=$(grep -n 'd->init_regs = \*init;' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: init_regs seed disappeared"; exit 1; }
blk=$(sed -n "${n},$((n + 30))p" "$S")
case "$blk" in *'[init-r15]'*) ;; *) echo "FAIL: the seed is unrecorded"; exit 1;; esac
case "$blk" in *'kind=%s'*) ;; *) echo "FAIL: no exec/fork distinction"; exit 1;; esac
case "$blk" in *r15=0x%llx*) ;; *) echo "FAIL: r15 not printed"; exit 1;; esac
case "$blk" in *init_r15_budget*) ;; *) echo "FAIL: no budget"; exit 1;; esac
# the seed must be copied BEFORE the record (the record is about the seed)
seed=$(grep -n 'd->init_regs = \*init;' "$S" | head -1 | cut -d: -f1)
rec=$(grep -n '\[init-r15\]' "$S" | head -1 | cut -d: -f1)
[ "$rec" -gt "$seed" ] || { echo "FAIL: record precedes the copy it describes"; exit 1; }
echo "init_r15: the seed is recorded per spawn, before the thread resumes"
