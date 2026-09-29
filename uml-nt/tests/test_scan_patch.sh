#!/usr/bin/env bash
# scan_patch.c decoder unit test (M2): 0F 05 at instruction boundaries
# patched, immediates/junk untouched. Compiles the overlay file as-is
# on the host (self-contained by design).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../kernel/overlay/arch/um/os-Windows/skas/scan_patch.c"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -D_GNU_SOURCE -o "$TMP/test" "$HERE/test_scan_patch.c" "$SRC"
"$TMP/test"
