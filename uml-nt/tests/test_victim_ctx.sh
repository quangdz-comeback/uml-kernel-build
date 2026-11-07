#!/usr/bin/env bash
# S103: a SIGSEGV victim must say WHERE the rip landed, not just that it did.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

# both markers exist, in that order, near the victim counter
ln_ctx=$(grep -n '\[victim-ctx\]' "$S" | head -1 | cut -d: -f1)
ln_ret=$(grep -n '\[wild-ret\]' "$S" | head -1 | cut -d: -f1)
ln_vic=$(grep -n 'SIGSEGV victim' "$S" | head -1 | cut -d: -f1)
[ -n "$ln_ctx" ] || { echo "FAIL: no victim context"; exit 1; }
[ -n "$ln_ret" ] || { echo "FAIL: no return-address witness"; exit 1; }
# the context sits immediately before the victim line it explains
[ "$ln_ctx" -lt "$ln_vic" ] || { echo "FAIL: context is not at the victim"; exit 1; }
[ $((ln_vic - ln_ctx)) -lt 80 ] || { echo "FAIL: context drifted away from the victim"; exit 1; }

blk=$(sed -n "$((ln_ctx - 90)),$((ln_vic + 30))p" "$S")
case "$blk" in *'bytes@rip-8=%s'*) ;; *) echo "FAIL: rip bytes not shown"; exit 1;; esac
case "$blk" in *'uml_nt_vma_find(c->mm'*) ;; *) echo "FAIL: rip VMA not resolved"; exit 1;; esac
case "$blk" in *UML_NT_VMA_FILE*) ;; *) echo "FAIL: file flag not reported"; exit 1;; esac
case "$blk" in *rsp+%d=0x%llx*) ;; *) echo "FAIL: stack qwords not printed"; exit 1;; esac
case "$blk" in *'[rela-ctx]'*) ;; *) echo "FAIL: the RELA entry is not recorded"; exit 1;; esac
case "$blk" in *'[reg-dump2]'*) ;; *) echo "FAIL: callee-saved regs are not dumped"; exit 1;; esac
case "$blk" in *'r15=0x%llx'*) ;; *) echo "FAIL: r15 not printed"; exit 1;; esac
case "$blk" in *'r_offset=0x%llx'*) ;; *) echo "FAIL: r_offset not printed"; exit 1;; esac
case "$blk" in *uml_nt_uacc_walk*) echo "FAIL: drives the uaccess sink"; exit 1;; esac
echo "victim_ctx: rip region, file flag, bytes, stack returns, RELA entry"
