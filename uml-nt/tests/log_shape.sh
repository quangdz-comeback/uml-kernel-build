#!/usr/bin/env bash
# S93: one line that says which beast this run was.
#
# One SHA has produced three shapes — a 272-line stall (kernel silent after
# tty0-enable), a 29k-line run with a native fault, and a 76k-line deep run.
# "Referee x2 on the same SHA" only means something if the two shapes can be
# compared without a human reading both logs.
set -uo pipefail   # S95: a shape line must always be printed, even for a log that matches nothing
LOG="${1:?usage: log_shape.sh <systemd.log>}"
lines=$(wc -l < "$LOG" 2>/dev/null) || lines=0
fault=$(grep -c 'KERNEL NATIVE FAULT' "$LOG" 2>/dev/null) || fault=0
rip=$(grep -oE 'KERNEL NATIVE FAULT[^\n]*rip=[0-9a-fA-F]+' "$LOG" 2>/dev/null |
      grep -oE 'rip=[0-9a-fA-F]+' | cut -d= -f2 | sort -u | head -1)
tty0=$(grep -c 'tty0.*enabl\|agetty.*tty0' "$LOG" 2>/dev/null) || tty0=0
tailq=$(tail -c 400 "$LOG" 2>/dev/null | grep -c 'login\|Password') || tailq=0
stall=0
case "${tty0:-0}" in ""|*[!0-9]*) tty0=0;; esac
case "${tailq:-0}" in ""|*[!0-9]*) tailq=0;; esac
case "${fault:-0}" in ""|*[!0-9]*) fault=0;; esac
if [ "$tty0" -gt 0 ] && [ "$tailq" -eq 0 ]; then stall=1; fi
sym="-"
if [ -n "${rip:-}" ] && [ -n "${VMLINUX:-}" ] && [ -f "${VMLINUX}" ]; then
  sym=$(llvm-addr2line -f -e "$VMLINUX" "0x$rip" 2>/dev/null | head -1)
fi
echo "[shape] fault=${fault:-0} lines=$lines stall=$stall rip=${rip:-none} sym=$sym"
