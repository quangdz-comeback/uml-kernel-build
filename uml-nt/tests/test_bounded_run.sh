#!/usr/bin/env bash
# S85: the boot step's bound has to actually fire.
#
# '| timeout -k 30 900 ./launcher.exe' never killed the launcher — it signals its
# own MSYS2 child, the Windows-native VM survives, and the step hangs forever
# (referee 42294016398: step 9 in_progress 56+ minutes, bound never taking
# effect). A hung instrument loses the whole run's evidence, so the bound now
# lives inside bounded-run.sh and hard-kills the tree.
#
# The MSYS2 half cannot be reproduced on this (Linux) runner; what is tested here
# is the contract the Windows path relies on: the bound fires without timeout(1),
# the command's own exit code comes back unchanged, and stdin still reaches the
# command (the feed pipeline is the boundary).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/../launcher/bounded-run.sh"
[ -x "$RUN" ] || { echo "FAIL: bounded-run.sh missing or not executable"; exit 1; }

# 1. a long runner is killed at the bound, and the script says so
start=$(date +%s)
set +e
out="$(bash "$RUN" 2 sleep 600 2>&1)"
rc=$?
set -e
took=$(( $(date +%s) - start ))
[ "$rc" -ne 0 ] || { echo "FAIL: a killed command must not report success"; exit 1; }
[ "$took" -le 12 ] || { echo "FAIL: bound did not fire (took ${took}s for a 2s bound)"; exit 1; }
case "$out" in *"bound 2s reached"*) ;; *) echo "FAIL: no bound record: $out"; exit 1;; esac

# 2. a short command keeps its own exit code and is not touched
bash "$RUN" 30 true >/dev/null 2>&1 || { echo "FAIL: a clean command must exit 0"; exit 1; }
set +e; bash "$RUN" 30 bash -c 'exit 7' >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 7 ] || { echo "FAIL: exit code not passed through (got $rc)"; exit 1; }

# 3. stdin still reaches the command: the feed pipeline is the boundary
got="$(printf 'root\nroot\necho LOGIN-OK\n' | bash "$RUN" 30 head -3)"
[ "$got" = "$(printf 'root\nroot\necho LOGIN-OK')" ] || { echo "FAIL: stdin was not passed through: $got"; exit 1; }

# 4. the workflow relies on our bound, not on timeout(1) for the launcher
W="$HERE/../../.github/workflows/uml-nt-m55-systemd.yml"
grep -q 'bash bounded-run.sh' "$W" || { echo "FAIL: the boot step does not use the bounded runner"; exit 1; }
if grep -q '| timeout -k' "$W"; then echo "FAIL: the boot step still pipes through timeout(1)"; exit 1; fi
awk '/NATIVE systemd boot \(M5.5a/,/^ *[a-z-]+:/' "$W" | grep -q 'timeout-minutes:' \
	|| { echo "FAIL: no GitHub backstop on the boot step"; exit 1; }
echo "bounded_run: the bound fires, the code comes back, stdin survives"
