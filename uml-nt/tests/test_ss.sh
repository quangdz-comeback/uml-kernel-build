#!/usr/bin/env bash
# The replay single-step (TF) state machine model (M5.6a K7 slice D):
# the stub VEH's pure half — flag sanitizers, the #DB classifier, the
# arm epoch — compiled on the host from the shared header as-is.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$SRC_DIR/include/shared" \
	-o "$TMP/test" "$HERE/test_ss.c"
"$TMP/test"
