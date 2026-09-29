#!/usr/bin/env bash
# apply.sh — materialize the uml-nt overlay + patch series onto a fetched
# v6.18.37 tree (from `fetch.sh extract`). Never modifies the repo: the
# tree lives in the cache outside git (HANDOFF hard-rule 1).
#
# Why overlay+patches instead of a forked tree: kernel patches stay a
# readable series against pristine upstream; our new files (os-Windows/,
# defconfig, Makefile-os-Windows) copy in verbatim.
#
# Usage: apply.sh <tree-dir>   (idempotent — safe to re-run)
set -euo pipefail

TREE="${1:?usage: apply.sh <tree-dir>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v patch >/dev/null 2>&1 || { echo "apply.sh: patch(1) not found" >&2; exit 1; }

cp -a "$ROOT/overlay/." "$TREE/"

status=0
for p in "$ROOT"/patches/*.patch; do
	# Idempotency: forward dry-run = fresh apply; reverse dry-run applies
	# = already applied. -N + -i avoid interactive prompts entirely.
	if patch -s -N -p1 --dry-run -d "$TREE" -i "$p" 2>/dev/null; then
		patch -s -N -p1 -d "$TREE" -i "$p"
	elif patch -s -N -R -p1 --dry-run -d "$TREE" -i "$p" 2>/dev/null; then
		: # already applied — nothing to do
	else
		echo "apply.sh: $(basename "$p") did not apply cleanly" >&2
		status=1
	fi
done
exit "$status"
