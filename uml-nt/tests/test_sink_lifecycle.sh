#!/usr/bin/env bash
# S451: the walker's global sink must not outlive the conn it was armed for.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$HERE/../kernel/overlay/arch/um/os-Windows/skas/uaccess_walk.c"
U="$HERE/../kernel/overlay/arch/um/os-Windows/skas/uaccess.c"
M="$HERE/../kernel/overlay/arch/um/os-Windows/skas/mmctx.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/uaccess_walk.h"

grep -q 'uml_nt_uacc_sink_owner' "$H" || { echo "FAIL: no owner ledger"; exit 1; }
grep -q 'void uml_nt_uacc_sink_clear' "$W" || { echo "FAIL: no clear"; exit 1; }
grep -q 'uml_nt_uacc_sink_clear((unsigned int)c->pid)' "$M" \
	|| { echo "FAIL: the sink is not cleared when the mm dies"; exit 1; }
grep -q 'uml_nt_uacc_sink_stale' "$U" || { echo "FAIL: stale use is not counted"; exit 1; }
# the guard must refuse BEFORE the plan is dereferenced
n=$(grep -n 'uml_nt_uacc_sink_stale++' "$U" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: no guard"; exit 1; }
blk=$(sed -n "$((n - 8)),$((n + 4))p" "$U")
case "$blk" in *'plan == (const struct uml_nt_fault_plan *)0'*) ;; *) echo "FAIL: plan is not checked"; exit 1;; esac
echo "sink_lifecycle: cleared on mm death, stale use refused and counted"
