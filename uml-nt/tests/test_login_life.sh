#!/usr/bin/env bash
# S435: the login ledger must be PRINTED at death, not just recorded.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/syscall.h"

grep -q 'unsigned life_dump;' "$H" || { echo "FAIL: no sticky flag"; exit 1; }
n=$(grep -n 'c->life_dump = 1;' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: the flag is never set"; exit 1; }
d=$(grep -n 'void uml_nt_sc_dump_final' "$S" | cut -d: -f1)
blk=$(sed -n "$d,$((d + 12))p" "$S")
case "$blk" in *'c->life_dump'*) ;; *) echo "FAIL: the dump gate ignores the sticky flag"; exit 1;; esac
# the ring must carry what the question needs: nr, ret, rip
grep -q 'c->sc_ring\[slot\].ret = ret;' "$S" || { echo "FAIL: no return in the ledger"; exit 1; }
grep -q 'c->sc_ring\[slot\].rip = d->regs.rip;' "$S" || { echo "FAIL: no rip in the ledger"; exit 1; }
grep -q 'n = c->sc_total < 200 ? c->sc_total : 200;' "$S" || { echo "FAIL: dump window changed"; exit 1; }
echo "login_life: the ledger is sticky, carries nr/ret/rip, dumps 200 at death"
