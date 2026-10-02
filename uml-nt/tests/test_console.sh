#!/usr/bin/env bash
# console-status classifier (Shelley 100-real-alpine): the stdin
# reader must re-arm on the spurious zero-info statuses (0x101!)
# and park only on the real EOF/handle-death. Compiles
# console_status.c as-is (pure integers, no host deps).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
OS_DIR="$SRC_DIR/os-Windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$OS_DIR/include" \
	-o "$TMP/test" "$HERE/test_console.c" "$OS_DIR/console_status.c"
"$TMP/test"
