#!/usr/bin/env bash
# S429: translate() success does not mean the physical page is committed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

grep -q 'int uml_nt_phys_read_checked' "$S" || { echo "FAIL: no checked reader"; exit 1; }
n=$(grep -n 'int uml_nt_phys_read_checked(struct uml_nt_stub_conn \*c,' "$S" | tail -1 | cut -d: -f1)
blk=$(sed -n "$n,$((n + 30))p" "$S")
case "$blk" in *'MEM_COMMIT'*) ;; *) echo "FAIL: commit state not checked"; exit 1;; esac
case "$blk" in *'PAGE_NOACCESS'*) ;; *) echo "FAIL: protection not checked"; exit 1;; esac
case "$blk" in *'mbi.RegionSize'*) ;; *) echo "FAIL: range not bounded by the region"; exit 1;; esac
# nothing may be copied before the checks
chk=$(printf '%s\n' "$blk" | grep -n 'MEM_COMMIT' | head -1 | cut -d: -f1)
cpy=$(printf '%s\n' "$blk" | grep -n 'memcpy(dst' | head -1 | cut -d: -f1)
[ -n "$chk" ] && [ -n "$cpy" ] && [ "$chk" -lt "$cpy" ] \
	|| { echo "FAIL: copies before validating"; exit 1; }
# and the abort tcache dump must use it, not a raw dereference
awk '/\[abrt\]   \+0x%03x/{found=1} END{exit !found}' "$S" \
	|| { echo "FAIL: the tcache dump moved"; exit 1; }
grep -q 'UNAVAILABLE(reason=phys-unmapped)' "$S" \
	|| { echo "FAIL: no provenance on an unmapped run"; exit 1; }
echo "phys_read: bounded, validated, and the dump reports UNAVAILABLE"
