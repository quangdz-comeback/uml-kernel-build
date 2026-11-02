#!/usr/bin/env bash
# S13 (Astra review 306, A2): execute the REAL raw handler and dispatch.
#
# This runner does not model the raw handler's ordering, and it does not copy
# the hop_live contract: it extracts `veh_handler`, `veh_dispatch`, the
# begin/finalize/decision helpers and the SS_STRAY branch VERBATIM from
# stub/stub.c, and it includes the PRODUCTION hop_live.h and veh_model.h. Only
# the Windows API and the stack switch are faked, plus a controlled body.
#
# It is an attribution/control-flow probe, not Windows execution evidence.
#
#   bash tests/test_hop_live_dispatch.sh [stub.c] [--quiet]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/.."
STUB="${1:-$ROOT/stub/stub.c}"
INC="$ROOT/kernel/overlay/arch/um/include/shared"
CC="${CC:-clang}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 "$HERE/hop_live_dispatch_probe.py" "$STUB" "$INC" "$TMP" "$CC"
