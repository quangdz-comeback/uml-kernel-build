#!/usr/bin/env bash
# S91 (round 391): the exit marker must sit on the door the guest actually uses,
# and the death dump must be wide enough to see the teardown.
#
# [exit-why] was written on the "case 231" arm; no 231 ever reached it — login's
# ring ends in a munmap burst, so its exit arrives through task teardown. And
# [sc-final] printed 16 calls, which the reader's death had already filled once.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
M="$HERE/../kernel/overlay/arch/um/os-Windows/skas/mmctx.c"

# 1. the dump is 64 for a chain/login conn, not 16
awk '/^void uml_nt_sc_dump_final/,/^}/' "$S" | grep -q 'sc_total < 200' \
	|| { echo "FAIL: the death dump is not 200 wide"; exit 1; }

# 2. [exit-why] is emitted where the conn actually dies (the dump's own door),
#    and it names how from the ring instead of assuming a syscall
awk '/^void uml_nt_sc_dump_final/,/^}/' "$S" | grep -q '\[exit-why\]' \
	|| { echo "FAIL: [exit-why] is not on the teardown door"; exit 1; }
awk '/^void uml_nt_sc_dump_final/,/^}/' "$S" | grep -q 'munmap_burst' \
	|| { echo "FAIL: [exit-why] cannot name a munmap-burst exit"; exit 1; }
grep -q 'uml_nt_sc_dump_final' "$M" \
	|| { echo "FAIL: the teardown does not reach the dump"; exit 1; }
echo "exit_why: the marker sits on the teardown door and the dump is 64 wide"
