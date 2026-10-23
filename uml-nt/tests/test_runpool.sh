#!/usr/bin/env bash
# The backend run pool model (M5.6a K8): put/get/pop/drain bookkeeping
# over run-aligned section offsets — the fragmentation fix's pure half.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$SRC_DIR/os-Windows/include" \
	-o "$TMP/test" "$HERE/test_runpool.c"
"$TMP/test"
