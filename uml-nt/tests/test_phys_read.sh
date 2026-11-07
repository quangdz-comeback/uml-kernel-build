#!/usr/bin/env bash
# S429/S431: translate success does not mean the run is committed, and the
# kernel side may not call host APIs directly.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

grep -q 'int uml_nt_phys_read_checked' "$S" || { echo "FAIL: no checked reader"; exit 1; }
# S431: this tree reaches NT only through the resolved ntabi table
if grep -q 'VirtualQuery' "$S"; then echo "FAIL: direct host API in kernel side"; exit 1; fi

n=$(grep -n '^int uml_nt_phys_read_checked(struct uml_nt_stub_conn' "$S" | tail -1 | cut -d: -f1)
blk=$(sed -n "$n,$((n + 25))p" "$S")
case "$blk" in *uml_nt_phys_block_check*) ;; *) echo "FAIL: no engine-side commit check"; exit 1;; esac
case "$blk" in *memcpy\(dst*) ;; *) echo "FAIL: no copy path"; exit 1;; esac
chk=$(printf '%s\n' "$blk" | grep -n 'uml_nt_phys_block_check' | head -1 | cut -d: -f1)
cpy=$(printf '%s\n' "$blk" | grep -n 'memcpy(dst' | head -1 | cut -d: -f1)
if [ -z "$chk" ] || [ -z "$cpy" ] || [ "$chk" -ge "$cpy" ]; then
	echo "FAIL: copies before validating"; exit 1
fi
grep -q 'UNAVAILABLE(reason=phys-unmapped)' "$S" \
	|| { echo "FAIL: no provenance on an unmapped run"; exit 1; }
echo "phys_read: engine bookkeeping gates the read, no host API"
