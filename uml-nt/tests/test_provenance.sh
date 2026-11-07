#!/usr/bin/env bash
# S424: no successful read means no byte observation.
#
# [open-miss]/[err-write]/[pam-mod] share one helper; it used to print a
# pre-zeroed buffer as text, which is how "userdb……|…<.`…" garbage entered the
# record and sent the hunt after a string that never existed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

n=$(grep -n 'static void uml_nt_note_text' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: the text helper moved"; exit 1; }
blk=$(sed -n "$n,$((n + 40))p" "$S")

case "$blk" in *'readable=0 bytes_valid=0'*) ;; *) echo "FAIL: a failed read is not marked"; exit 1;; esac
case "$blk" in *'UNAVAILABLE(reason=translate)'*) ;; *) echo "FAIL: no reason given"; exit 1;; esac
case "$blk" in *'readable=1 bytes_valid=1'*) ;; *) echo "FAIL: a good read is not marked"; exit 1;; esac
# the failure must return before any bytes are rendered
fail=$(printf '%s\n' "$blk" | grep -n 'UNAVAILABLE' | head -1 | cut -d: -f1)
copy=$(printf '%s\n' "$blk" | grep -n 'memcpy(buf' | head -1 | cut -d: -f1)
[ -n "$fail" ] && [ -n "$copy" ] && [ "$fail" -lt "$copy" ] \
	|| { echo "FAIL: bytes are copied before the readability gate"; exit 1; }
case "$blk" in *'return;'*) ;; *) echo "FAIL: no early return on failure"; exit 1;; esac
echo "provenance: failed reads print UNAVAILABLE, good reads say bytes_valid=1"
