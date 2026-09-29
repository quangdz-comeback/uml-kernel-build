#!/usr/bin/env bash
# fault.c decider unit test (M3.1): fault → action/prot/page contract.
# Compiles the overlay file as-is on the host (self-contained by design).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
OS_DIR="$SRC_DIR/os-Windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$OS_DIR/include" -I"$SRC_DIR/include/shared" \
	-o "$TMP/test" "$HERE/test_fault.c" "$OS_DIR/skas/fault.c"
"$TMP/test"
