#!/usr/bin/env bash
# S112: catch the writer in the act — the r15 canary at every resume boundary.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
n=$(grep -n '\[r15-watch\]' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] || { echo "FAIL: no r15 canary"; exit 1; }
blk=$(sed -n "$((n - 30)),$((n + 12))p" "$S")
case "$blk" in *'old=0x%llx new=0x%llx'*) ;; *) echo "FAIL: no old->new transition"; exit 1;; esac
case "$blk" in *'verbatim=%u'*) ;; *) echo "FAIL: verbatim split missing"; exit 1;; esac
case "$blk" in *'pushed=%u'*) ;; *) echo "FAIL: pushed split missing"; exit 1;; esac
case "$blk" in *'d->regs.r15'*) ;; *) echo "FAIL: not sampling the published cell"; exit 1;; esac
# it must fire on transition, not every resume, and be budgeted
case "$blk" in *'last_r15 != now15'*) ;; *) echo "FAIL: does not detect a change"; exit 1;; esac
case "$blk" in *'r15_watch_budget'*) ;; *) echo "FAIL: unbudgeted"; exit 1;; esac
echo "r15_watch: transitions recorded with cmd/verbatim/pushed"
