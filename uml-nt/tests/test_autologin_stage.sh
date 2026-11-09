#!/usr/bin/env bash
# S463: with login -f root there is no username prompt; exec of the shell is the
# readiness point, and it must move the gate to stage 3.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q "login chain armed by exec" "$K" || { echo "FAIL: exec-arm point moved"; exit 1; }
n=$(grep -n "login chain armed by exec" "$K" | head -1 | cut -d: -f1)
blk=$(sed -n "${n},$((n + 14))p" "$K")
case "$blk" in *'uml_nt_console_gate.stage = 3'*) ;; *) echo "FAIL: stage is not set on exec"; exit 1;; esac
case "$blk" in *'anchor=exec-bash autologin'*) ;; *) echo "FAIL: the transition is not declared"; exit 1;; esac
# the text anchors must survive for images that do prompt
grep -q 'g->stage = 1' "$HERE/../kernel/overlay/arch/um/include/shared/feedgate.h" \
	|| { echo "FAIL: text anchors were removed"; exit 1; }
echo "autologin_stage: exec of the shell arms stage 3, text anchors kept"
