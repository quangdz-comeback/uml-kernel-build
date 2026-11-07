#!/usr/bin/env bash
# S101: the last unmeasured door is connect() — pam_systemd to the userdb varlink.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

body=$(awk '/^static void uml_nt_con_path_note\(/{f=1} f{print} f&&/^}/{exit}' "$S")
[ -n "$body" ] || { echo "FAIL: no connect-path witness"; exit 1; }
case "$body" in *'[con-path]'*) ;; *) echo "FAIL: no marker"; exit 1;; esac
case "$body" in *uml_nt_uacc_walk*) echo "FAIL: drives the uaccess sink"; exit 1;; esac
case "$body" in *'uml_nt_vma_translate'*) ;; *) echo "FAIL: not the safe read"; exit 1;; esac
# fires for connect in a chain/login conn, with the return value
awk '/^void uml_nt_syscall_handle\(/{f=1} f{print} f&&/^}/{exit}' "$S" |
	grep -q 'nr == 42' || { echo "FAIL: not wired to connect"; exit 1; }

# the syslog budget must really be 32 in the source that runs
grep -q 'c->syslog_n < 32' "$S" || { echo "FAIL: cap is not 32"; exit 1; }
echo "con_path: connect() in a login chain is witnessed, syslog cap is 32"
