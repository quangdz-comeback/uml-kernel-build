#!/usr/bin/env bash
# S440: the caller ring must survive the teardown burst.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/syscall.h"

grep -q 'ra_ring\[64\]' "$H" || { echo "FAIL: ring is not 64"; exit 1; }
grep -q 'c->ra_ri % 64' "$S" || { echo "FAIL: index still modulo the old size"; exit 1; }
grep -q 'nr != 11' "$S" || { echo "FAIL: munmap is not excluded"; exit 1; }
grep -q '\[sct-caller\]' "$S" || { echo "FAIL: no caller record"; exit 1; }
for f in ra1 ra2 ra3; do
	grep -q "$f=0x%llx" "$S" || { echo "FAIL: $f not printed"; exit 1; }
done
n=$(grep -n 'ra_ring\[k\].nr' "$S" | head -1 | cut -d: -f1)
blk=$(sed -n "$((n - 20)),$((n + 2))p" "$S")
case "$blk" in *uml_nt_vma_translate*) ;; *) echo "FAIL: no translate"; exit 1;; esac
case "$blk" in *uml_nt_phys_read_checked*) ;; *) echo "FAIL: raw stack read"; exit 1;; esac

# getpid truth: five answers, with the kernel's own opinion beside them
grep -q '\[getpid-truth\]' "$S" || { echo "FAIL: no getpid witness"; exit 1; }
grep -q 'task_pid=%d' "$S" || { echo "FAIL: no kernel pid"; exit 1; }
grep -q 'getpid_n < 5' "$S" || { echo "FAIL: budget wrong"; exit 1; }
echo "sct_caller: 64 entries, munmap excluded, getpid truth recorded"
