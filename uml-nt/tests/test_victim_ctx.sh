#!/usr/bin/env bash
# S103: a SIGSEGV victim must say WHERE the rip landed, not just that it did.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
body=$(awk '/SIGSEGV victim/{f=1} f{print} f&&/wild-ret/{c++} c&&/^\t\t\t\t}/{exit}' "$S")
[ -n "$body" ] || { echo "FAIL: victim block not found"; exit 1; }
case "$body" in *'[victim-ctx]'*) ;; *) echo "FAIL: no victim context"; exit 1;; esac
case "$body" in *'bytes@rip-8=%s'*) ;; *) echo "FAIL: rip bytes not shown"; exit 1;; esac
case "$body" in *'uml_nt_vma_find(c->mm'*) ;; *) echo "FAIL: rip VMA not resolved"; exit 1;; esac
case "$body" in *UML_NT_VMA_FILE*) ;; *) echo "FAIL: file flag not reported"; exit 1;; esac
case "$body" in *'[wild-ret]'*) ;; *) echo "FAIL: no return-address witness"; exit 1;; esac
# the safe reader, never the sink
case "$body" in *uml_nt_uacc_walk*) echo "FAIL: drives the uaccess sink"; exit 1;; esac
echo "victim_ctx: rip region, file flag, surrounding bytes and stack returns recorded"
