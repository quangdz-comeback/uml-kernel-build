#!/usr/bin/env bash
# S93: one line that says which beast this run was.
#
# One SHA has produced three shapes — a 272-line stall (kernel silent after
# tty0-enable), a 29k-line run with a native fault, and a 76k-line deep run.
# "Referee x2 on the same SHA" only means something if the two shapes can be
# compared without a human reading both logs.
set -euo pipefail
LOG="${1:?usage: log_shape.sh <systemd.log>}"
lines=$(wc -l < "$LOG" 2>/dev/null || echo 0)
fault=$(grep -c 'KERNEL NATIVE FAULT' "$LOG" 2>/dev/null || true)
rip=$(grep -oE 'KERNEL NATIVE FAULT[^\n]*rip=[0-9a-fA-F]+' "$LOG" 2>/dev/null |
      grep -oE 'rip=[0-9a-fA-F]+' | cut -d= -f2 | sort -u | head -1)
tty0=$(grep -c 'tty0.*enabl\|agetty.*tty0' "$LOG" 2>/dev/null || true)
tailq=$(tail -c 400 "$LOG" 2>/dev/null | grep -c 'login\|Password' || true)
stall=0
if [ "${tty0:-0}" -gt 0 ] && [ "${tailq:-0}" -eq 0 ]; then stall=1; fi
sym="-"
if [ -n "${rip:-}" ] && [ -n "${VMLINUX:-}" ] && [ -f "${VMLINUX}" ]; then
  sym=$(llvm-addr2line -f -e "$VMLINUX" "0x$rip" 2>/dev/null | head -1)
fi
echo "[shape] fault=${fault:-0} lines=$lines stall=$stall rip=${rip:-none} sym=$sym"
