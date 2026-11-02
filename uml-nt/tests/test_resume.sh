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

# Shelley 287/288 (Astra S2b/S2c): the VEH diagnostic placement, wired here
# because this runner is the one CI already calls — no workflow change and no
# gate change. Source-only and deterministic: it reads stub/stub.c and never
# builds, executes or inspects a binary, so a missing PE can never read as a
# pass.
bash "$HERE/test_veh_diag_order.sh"

# Shelley 295 (Astra S8): one diagnostic record is one host write — the
# production framing helper through a recording sink, plus the source shape of
# the selected emitters and the two kernel formatters. Host logic only: it is
# not evidence about Windows write atomicity.
bash "$HERE/test_diag_record.sh"

# Shelley 301 (Astra S11a): the launcher's dump hook needs a weak DEFAULT, or
# the kernel's own link leaves the symbol at address 0 and the guard loads
# through it. Links the guard without the launcher, as the kernel does.
bash "$HERE/test_dump_hook.sh"
