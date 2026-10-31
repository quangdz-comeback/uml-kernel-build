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

# The launcher's mem= contract (M5.6 groundwork): parse 128M/512M/1G/rác,
# section sizing, and the ceiling arithmetic — host-side, no Windows needed.
"$CC" -O1 -Wall -Wextra -Werror \
	-o "$TMP/memparse" "$HERE/test_memparse.c" "$HERE/../launcher/memparse.c"

# The debug continue map: which event is continued, which is left to the
# debuggee.
"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/dbgmap" "$HERE/test_dbgmap.c"

"$TMP/test"
"$TMP/memparse"
"$TMP/dbgmap"
