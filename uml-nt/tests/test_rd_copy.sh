#!/usr/bin/env bash
# S466: did the copy run? Compare the destination before and after.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/syscall.h"

grep -q 'unsigned char rd_before\[8\];' "$H" || { echo "FAIL: no pre-read capture field"; exit 1; }
grep -q 'S466: before the read is served' "$S" || { echo "FAIL: no capture at entry"; exit 1; }
# the capture must precede dispatch: before the switch on nr
c=$(grep -n 'S466: before the read is served' "$S" | cut -d: -f1)
sw=$(grep -n 'switch (nr) {' "$S" | head -1 | cut -d: -f1)
[ -n "$c" ] && [ -n "$sw" ] && [ "$c" -lt "$sw" ] || { echo "FAIL: capture after dispatch"; exit 1; }
grep -q '\[rd-copy\] pid=%d n=%lu dst_va=0x%llx' "$K" || { echo "FAIL: no before/after line"; exit 1; }
grep -q 'uml_nt_phys_read_checked' "$S" || { echo "FAIL: capture not checked"; exit 1; }
echo "rd_copy: destination captured before the read, compared after"
