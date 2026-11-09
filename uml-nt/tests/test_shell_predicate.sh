#!/usr/bin/env bash
# S470: only a shell exec may arm the marker — agetty is a login-chain exec too.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q 'int uml_nt_exec_path_is_shell(const char \*p)' "$K" \
	|| { echo "FAIL: no shell predicate"; exit 1; }
# the predicate must accept bash/sh and reject agetty
body=$(awk '/int uml_nt_exec_path_is_shell/,/^}/' "$K")
case "$body" in *"'b'"*) ;; *) echo "FAIL: bash not matched"; exit 1;; esac
case "$body" in *"'s'"*) ;; *) echo "FAIL: sh not matched"; exit 1;; esac
if printf '%s\n' "$body" | grep -q "agetty"; then
	echo "FAIL: predicate hardcodes agetty"; exit 1
fi
# arming must go through the predicate, not through g_exec_login alone
n=$(grep -n "login chain armed by exec" "$K" | head -1 | cut -d: -f1)
blk=$(sed -n "${n},$((n + 18))p" "$K")
case "$blk" in *'uml_nt_exec_path_is_shell(g_exec_path)'*) ;; *) echo "FAIL: arm does not test the path"; exit 1;; esac
case "$blk" in *'anchor=exec-bash autologin'*) ;; *) echo "FAIL: transition not declared"; exit 1;; esac
# refeed cap must survive
grep -q 'g_marker_refeed < 12' "$K" || { echo "FAIL: refeed cap removed"; exit 1; }
echo "shell_predicate: only bash/sh arms stage 3; refeed cap kept"
