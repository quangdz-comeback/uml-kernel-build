#!/usr/bin/env bash
# The kernel->guest write ledger (D28 follow-up): run-keyed ring.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
"$CC" -O1 -Wall -Wextra -Werror -I"$SRC_DIR/os-Windows/include" \
	-o "$TMP/test" "$HERE/test_writeledger.c"
"$TMP/test"
