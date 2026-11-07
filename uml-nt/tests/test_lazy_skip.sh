#!/usr/bin/env bash
# S102: the door that can hand a process a zero page instead of file bytes.
#
# lazy_run() returned 0 whenever a VMA already covered the run — "a VMA exists"
# was read as "the page is there". A VMA in the table is not a page in the file,
# and a zero page inside /sbin/init is a SIGSEGV with insn=ALL ZEROS.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

body=$(awk '/^static int lazy_run\(/{f=1} f{print} f&&/^}/{exit}' "$S")
[ -n "$body" ] || { echo "FAIL: lazy_run not found"; exit 1; }
case "$body" in *'[lazy-skip]'*) ;; *) echo "FAIL: the skip door is silent"; exit 1;; esac
case "$body" in *'lazy_skip_runs'*) ;; *) echo "FAIL: skips are not counted"; exit 1;; esac
# the read must still happen on the normal path
case "$body" in *kernel_read*) ;; *) echo "FAIL: the file read disappeared"; exit 1;; esac
# a skip must never be silent when the VMA is file-backed: the loud line is the
# evidence, so it must print the file flag and the run offset
case "$body" in *'file=%d prot=0x%x'*) ;; *) echo "FAIL: skip line does not name the VMA"; exit 1;; esac
echo "lazy_skip: a materialize-without-read is counted and named, read preserved"
