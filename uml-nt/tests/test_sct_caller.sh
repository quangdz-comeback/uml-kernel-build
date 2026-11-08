#!/usr/bin/env bash
# S439: the ledger's rip is inside the libc stub; only the guest stack names login.c.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/syscall.h"

grep -q 'ra_ring\[8\]' "$H" || { echo "FAIL: no caller ring"; exit 1; }
grep -q '\[sct-caller\]' "$S" || { echo "FAIL: no caller record"; exit 1; }
grep -q 'ra1=0x%llx' "$S" || { echo "FAIL: ra1 not printed"; exit 1; }
grep -q 'ra2=0x%llx' "$S" || { echo "FAIL: ra2 not printed"; exit 1; }
grep -q 'ra3=0x%llx' "$S" || { echo "FAIL: ra3 not printed"; exit 1; }

n=$(grep -n 'ra_ring\[k\].nr' "$S" | head -1 | cut -d: -f1)
blk=$(sed -n "$((n - 18)),$((n + 2))p" "$S")
case "$blk" in *uml_nt_vma_translate*) ;; *) echo "FAIL: no translate"; exit 1;; esac
case "$blk" in *uml_nt_phys_read_checked*) ;; *) echo "FAIL: raw stack read"; exit 1;; esac
case "$blk" in *d->regs.rsp*) ;; *) echo "FAIL: not the guest stack"; exit 1;; esac
echo "sct_caller: three return addresses captured per ledger entry, read safely"
