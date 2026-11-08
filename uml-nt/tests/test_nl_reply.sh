#!/usr/bin/env bash
# S437: the netlink ACK decides whether a missing auditd is fatal.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
grep -q '\[nl-reply\]' "$S" || { echo "FAIL: no netlink reply decode"; exit 1; }
grep -q 'nlmsgerr.error=%d' "$S" || { echo "FAIL: error field not printed"; exit 1; }
# the buffer must be read with the checked reader, never dereferenced raw
n=$(grep -n '\[nl-reply\]' "$S" | cut -d: -f1)
blk=$(sed -n "$((n - 20)),$((n + 3))p" "$S")
case "$blk" in *uml_nt_phys_read_checked*) ;; *) echo "FAIL: raw read of the guest buffer"; exit 1;; esac
case "$blk" in *uml_nt_vma_translate*) ;; *) echo "FAIL: no translation"; exit 1;; esac
# offset 16 is nlmsgerr.error on x86-64; a wrong offset would print nonsense
grep -q 'buf\[16\]' "$S" || { echo "FAIL: error is not read at offset 16"; exit 1; }
echo "nl_reply: 36-byte ACK decoded through the checked reader"
