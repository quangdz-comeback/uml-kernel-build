#!/usr/bin/env bash
# The resume-boundary model (M5.6a writer-hunt follow-up): the stub
# VEH's syscall gate + the kernel's resume arithmetic, compiled on the
# host from the shared header as-is.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$SRC_DIR/include/shared" \
	-o "$TMP/test" "$HERE/test_resume.c"
"$TMP/test"
