#!/usr/bin/env bash
# S92: name the fault. Three referees faulted inside uml_nt_syscall_handle and
# nobody saw it until a human symbolized the rips against the CI vmlinux.
set -euo pipefail
LOG="${1:?usage: symbolize_faults.sh <systemd.log> <vmlinux>}"
VL="${2:?}"
rips=$(grep -oE "KERNEL NATIVE FAULT[^\n]*rip=[0-9a-fA-F]+" "$LOG" 2>/dev/null | grep -oE "rip=[0-9a-fA-F]+" | cut -d= -f2 | sort -u)
[ -n "$rips" ] || { echo "FAULT-SYM: no native fault"; exit 0; }
for r in $rips; do
  case "$r" in *[!0-9a-fA-F]*) continue;; esac
  line=$(llvm-addr2line -f -e "$VL" "0x$r" 2>/dev/null | tr "\n" " ")
  echo "FAULT-SYM rip=0x$r $line"
done
