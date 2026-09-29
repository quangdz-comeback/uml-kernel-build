#!/usr/bin/env bash
# mm core unit test (M3.2): physalloc + vma + fault plan generation.
# Compiles the overlay files as-is on the host (self-contained by design).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
OS_DIR="$SRC_DIR/os-Windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$OS_DIR/include" -I"$SRC_DIR/include/shared" \
	-o "$TMP/test" "$HERE/test_mm.c" \
	"$OS_DIR/skas/fault.c" "$OS_DIR/skas/vma.c" \
	"$OS_DIR/skas/physalloc.c"
"$TMP/test"
