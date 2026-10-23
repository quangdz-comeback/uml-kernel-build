#!/usr/bin/env bash
# The lazy file-backed VMA model (M5.6a D27): run-window + read clamp.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$SRC_DIR/os-Windows/include" \
	-o "$TMP/test" "$HERE/test_lazyfile.c"
"$TMP/test"
