#!/usr/bin/env bash
# S465: compare the tty the feed inserted into with the one the reader consumes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q '\[rd-src\] port=%d itty=%p n=%u' "$C" || { echo "FAIL: no source identity"; exit 1; }
grep -q '\[rd-dst\] pid=%d port=%d itty=%p' "$K" || { echo "FAIL: no reader identity"; exit 1; }
grep -q 'uml_nt_console_port_itty' "$C" || { echo "FAIL: no accessor"; exit 1; }
# the reader line must print the port the feed chose, not a guess
n=$(grep -n '\[rd-dst\]' "$K" | cut -d: -f1)
blk=$(sed -n "${n},$((n + 4))p" "$K")
case "$blk" in *'uml_nt_console_feed_port()'*) ;; *) echo "FAIL: uses another port"; exit 1;; esac
echo "rd_src: feed port/tty and reader port/tty both named"
