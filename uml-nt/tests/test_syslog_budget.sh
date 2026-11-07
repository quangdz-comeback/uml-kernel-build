#!/usr/bin/env bash
# S100: the syslog cap must not cut between GetUserRecord and the abort.
#
# The 4-record cap hid every pam_syslog LOG_CRIT that names the module and the
# value it returned — the log was thrifty exactly where it mattered.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

grep -q 'c->syslog_n < 32' "$S" || { echo "FAIL: syslog cap still cuts at 4"; exit 1; }
grep -q '\[pam-mod\]' "$S" || { echo "FAIL: no [pam-mod] label"; exit 1; }
body=$(awk '/^static void uml_nt_pam_mod_note\(/{f=1} f{print} f&&/^}/{exit}' "$S")
[ -n "$body" ] || { echo "FAIL: pam-mod helper missing"; exit 1; }
case "$body" in
*'strstr(buf, "pam_")'*) ;;
*) echo "FAIL: pam modules are not filtered"; exit 1;; esac
case "$body" in
*'/lib/security/'*) ;;
*) echo "FAIL: the security dir is not recognised"; exit 1;; esac
# it must read the safe way, never through the uaccess sink
case "$body" in
*uml_nt_uacc_walk*) echo "FAIL: pam-mod drives the uaccess sink"; exit 1;; esac
echo "syslog_budget: 32 records for the chain, pam modules named, sink untouched"
