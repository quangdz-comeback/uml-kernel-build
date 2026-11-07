#!/usr/bin/env bash
# S108: the syscall sentinel must be confirmed before folding retval.
#
# A page mid-materialization can hand the VEH 0f 0b while the guest's own fetch
# sees something else; folding then writes rax = the PROT_DONE retval (1) and
# resumes at rip+2, inside an instruction. The dead victims showed exactly that
# shape (r15/base = 1 with a valid rcx on every survivor).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../stub/stub.c"

n=$(grep -n 'uml_nt_resume_illegal_is_syscall(1, readable, ib)' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: the syscall gate moved"; exit 1; }
blk=$(sed -n "${n},$((n + 45))p" "$S")

case "$blk" in *'[is-sys-div]'*) ;; *) echo "FAIL: divergence is silent"; exit 1;; esac
case "$blk" in *'is_syscall = 1'*) ;; *) echo "FAIL: no positive confirmation path"; exit 1;; esac
case "$blk" in *'is_fault = 1'*) ;; *) echo "FAIL: divergence does not fall back to the fault flow"; exit 1;; esac
case "$blk" in *'is_sys_div_n'*) ;; *) echo "FAIL: divergences are not counted"; exit 1;; esac
# the re-read must be guarded by the readable probe, never a raw memcpy
case "$blk" in *'veh_readable_n(rip, 2)'*) ;; *) echo "FAIL: the second read is unguarded"; exit 1;; esac
# and the fold must not happen on the divergent path: is_syscall must be cleared
case "$blk" in *'is_syscall = 0'*) ;; *) echo "FAIL: a divergent round keeps is_syscall"; exit 1;; esac
echo "is_sys_div: the sentinel is confirmed twice; divergence takes the fault flow"
