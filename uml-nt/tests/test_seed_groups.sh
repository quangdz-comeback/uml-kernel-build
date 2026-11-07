#!/usr/bin/env bash
# S98: the eager fork-seed copy is checked per contiguous run group.
#
# Referee 42348970558 refused 14 of 14 seeds with "src:span-discontinuous
# dst:ok": the parent's table is a patchwork of scattered 64 KiB COW copies, so
# a four-run VMA range is never one block. The guard was right; one-range
# granularity was not. A group that is itself broken must still refuse.
#
# STRUCTURAL check only — the group loop needs the stub's physmem base and the
# real table, so a behavioural fixture (patchwork ⇒ bytes copied; gap ⇒ refused)
# is recorded as test debt in report 398 rather than faked here.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

body=$(awk '/^static int uml_nt_seed_group_check\(/{f=1} f{print} f&&/^}/{exit}' "$S")
[ -n "$body" ] || { echo "FAIL: no group checker"; exit 1; }

case "$body" in
*"uml_nt_phys_block_check(child->ph"*) ;;
*) echo "FAIL: dst group is not checked"; exit 1;; esac
case "$body" in
*"uml_nt_phys_block_check(parent->ph"*) ;;
*) echo "FAIL: src group is not checked"; exit 1;; esac
case "$body" in
*"return -ENOMEM"*) ;;
*) echo "FAIL: a broken group can no longer refuse"; exit 1;; esac
# the loop must advance over groups, not copy the whole range once
case "$body" in
*"while (done < len)"*) ;;
*) echo "FAIL: no group loop"; exit 1;; esac
# and the seed must call it instead of a single whole-range check
case "$(awk '/int uml_nt_fork_seed\(/{f=1} f{print} f&&/^}/{exit}' "$S")" in
*"uml_nt_seed_group_check(parent, child, pv, cv, 1)"*) ;;
*) echo "FAIL: fork_seed still does a whole-range check"; exit 1;; esac

# S99: an unmaterialized SOURCE group is a hole, not corruption — it is skipped
# (the child faults in zero, which is anonymous semantics), and only other whys
# refuse. A 1.6 MB VMA with one 64 KiB hole must not cost a fork.
case "$body" in
*'first-run-unmaterialized'*) ;;
*) echo "FAIL: holes are not distinguished from corruption"; exit 1;; esac
case "$body" in
*'skipped-unmaterialized'*) ;;
*) echo "FAIL: skipped groups are not counted"; exit 1;; esac
case "$body" in
*'done += gl;'*'continue;'*) ;;
*) echo "FAIL: a skipped group does not advance the walk"; exit 1;; esac

echo "seed_groups: eager seed copies per group, skips unmaterialized holes"
