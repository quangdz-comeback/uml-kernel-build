#!/usr/bin/env bash
# bench_stats unit test (M4.1): the pure math the freestanding kernel
# ships must agree with the host test — sort, percentile ranks,
# mean/eps (see bench.h for the rank contract).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../kernel/overlay/arch/um/os-Windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

command -v "$CC" >/dev/null 2>&1 || { echo "clang not found"; exit 1; }

"$CC" -O1 -Wall -Wextra -Werror -I"$SRC/include" \
	-o "$TMP/test" "$HERE/test_bench.c" "$SRC/skas/bench_stats.c"
"$TMP/test"
