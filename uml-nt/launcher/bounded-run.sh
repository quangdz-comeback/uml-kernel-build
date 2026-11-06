#!/usr/bin/env bash
# bounded-run.sh — run a NATIVE command with a bound that actually fires.
#
# '| timeout -k 30 900 ./launcher.exe' never killed the launcher: timeout(1)
# signals its own MSYS2 child, the Windows-native VM process survives, and the
# step hangs with no end (referee 42294016398: step 9 in_progress for 56+
# minutes with the 900s timeout never taking effect). A hung instrument costs the
# whole run's evidence — the lesson of referee 40794805029 — so the bound moves
# inside: start the command in the background (stdin, i.e. the feed pipeline,
# still points at it), wait with a deadline, and on overrun kill the process
# TREE the way Windows understands.
#
# usage: … | bounded-run.sh <bound-seconds> <command> [args…]
set -uo pipefail

bound="${1:?usage: bounded-run.sh <bound-seconds> <command> [args…]}"
shift

# '<&0' is not decoration: a non-interactive bash gives an asynchronous list
# /dev/null as its stdin, which would silently starve the guest of the whole
# feed pipeline. The explicit duplication keeps the pipe.
"$@" <&0 &
lpid=$!

hard_kill() { # $1 = pid of the command we started
	# MSYS2: the launcher is a native Windows process; taskkill needs the
	# double slash so MSYS does not path-mangle the switch.
	if command -v taskkill >/dev/null 2>&1; then
		taskkill //F //T //PID "$1" >/dev/null 2>&1 && return 0
	fi
	# POSIX fallback (the CI unit tests run here): the command's own children
	# first, then the command. NEVER the process group — that is our own group
	# in a script, and killing it would take the harness with it.
	if command -v pkill >/dev/null 2>&1; then
		pkill -9 -P "$1" >/dev/null 2>&1
	fi
	kill -9 "$1" >/dev/null 2>&1
}

(
	sleep "$bound"
	if kill -0 "$lpid" 2>/dev/null; then
		echo "[bounded-run] bound ${bound}s reached — hard-killing pid ${lpid}" >&2
		hard_kill "$lpid"
	fi
) &
watchdog=$!

wait "$lpid"
rc=$?
kill "$watchdog" 2>/dev/null
wait "$watchdog" 2>/dev/null
exit "$rc"
