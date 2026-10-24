#!/usr/bin/env bash
# Guard-stability model (M5.6a login-depth follow-up): the PTR_MANGLE
# arithmetic + stability verdict + AT_RANDOM->TCB derivation, compiled
# on the host from the shared header as-is.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$SRC_DIR/include/shared" \
	-o "$TMP/test" "$HERE/test_guard.c"
"$TMP/test"
