#!/usr/bin/env bash
# S458: one snapshot, all reads local, one guarded write-back.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

grep -q 'struct uml_nt_snap {' "$S" || { echo "FAIL: no small snapshot type"; exit 1; }
grep -q '_Static_assert(sizeof(struct uml_nt_snap) <= 512' "$S" \
	|| { echo "FAIL: snapshot size is not asserted"; exit 1; }
grep -q 'S458 write-back — guarded' "$S" \
	|| { echo "FAIL: no guarded write-back marker"; exit 1; }

# (a) the snapshot must follow the view check
g=$(grep -n 'if (!uml_nt_stub_view_ok(d))' "$S" | head -1 | cut -d: -f1)
sn=$(grep -n 's->halt = (int)d->halt;' "$S" | head -1 | cut -d: -f1)
[ -n "$g" ] && [ -n "$sn" ] && [ "$g" -lt "$sn" ] || { echo "FAIL: snapshot precedes the guard"; exit 1; }

# (b) no d-> between the snapshot and the write-back
wb=$(grep -n 'S458 write-back — guarded' "$S" | head -1 | cut -d: -f1)
leak=$(sed -n "${sn},$((wb - 1))p" "$S" | grep -c 'd->' || true)
[ "${leak:-0}" -eq 0 ] || { echo "FAIL: $leak d-> still read between snapshot and write-back"; exit 1; }

# (c) the write-back must be guarded and counted
tail=$(sed -n "${wb},$((wb + 12))p" "$S")
case "$tail" in *'uml_nt_stub_view_ok(d)'*) ;; *) echo "FAIL: write-back unguarded"; exit 1;; esac
case "$tail" in *'late-write-refused'*) ;; *) echo "FAIL: refusal not reported"; exit 1;; esac
case "$tail" in *'uml_nt_late_write_refused++'*) ;; *) echo "FAIL: refusal not counted"; exit 1;; esac
# (d) no whole-struct snapshot may come back
if grep -q 'memcpy(&s_local' "$S"; then echo "FAIL: whole-struct snapshot is back"; exit 1; fi
if grep -qE 'sizeof\(struct uml_nt_stub_data\)' "$S"; then
	echo "FAIL: a local sized as the whole stub_data exists"; exit 1
fi
echo "snapshot: small copy, size asserted, zero d-> between, guarded write-back"
