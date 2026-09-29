#!/usr/bin/env bash
# Unit tests for kernel/fetch.sh — pure logic, NO network. Runs on Linux CI.
# Network paths are tested by overriding do_curl with a fixture-copier.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FETCH="$HERE/../kernel/fetch.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
ok() { PASS=$((PASS + 1)); printf 'ok  - %s\n' "$1"; }
fail() { printf 'FAIL- %s\n' "$1"; exit 1; }

# --- fixture: a tiny tarball whose tree passes verify_tree ---------------
make_fixture_tree() { # <dir>
  mkdir -p "$1/arch/um"
  printf 'VERSION = 6\nPATCHLEVEL = 18\nSUBLEVEL = 37\nNAME = test\n' > "$1/Makefile"
  printf 'obj-y += x.o\n' > "$1/arch/um/Makefile"
}
make_fixture_tarball() { # <out.tar.xz> — prints its sha256
  local stage="$TMP/stage-fix"
  rm -rf "$stage"
  mkdir -p "$stage/linux-6.18.37"
  make_fixture_tree "$stage/linux-6.18.37"
  tar -cJf "$1" -C "$stage" linux-6.18.37
  sha256sum "$1" | awk '{print $1}'
}
FIXTURE="$TMP/fixture.tar.xz"
FIXTURE_SHA="$(make_fixture_tarball "$FIXTURE")"

# --- pin + env hooks must exist BEFORE sourcing fetch.sh -----------------
export UML_NT_CACHE_DIR="$TMP/cache"
export UML_NT_PIN_SHA256="$FIXTURE_SHA"

# FETCH is computed from $HERE at runtime; shellcheck cannot follow it.
# shellcheck disable=SC1091
source "$FETCH"

# 1. Pin is baked in and immutable via readonly version.
[[ "$LINUX_VERSION" == "6.18.37" ]] || fail "LINUX_VERSION pin"
ok "LINUX_VERSION pinned to 6.18.37"

# 2. file_url substitutes path into the cgit-stable template.
[[ "$(file_url "arch/um/Makefile")" == *"plain/arch/um/Makefile?h=v6.18.37"* ]] \
  || fail "file_url template"
ok "file_url substitutes path, pinned h=v6.18.37"

# 3. verify_sha256 accept/reject.
printf 'hi' > "$TMP/f"
H="$(sha256sum "$TMP/f" | awk '{print $1}')"
verify_sha256 "$TMP/f" "$H" || fail "verify_sha256 accepts matching"
ok "verify_sha256 accepts matching"
if verify_sha256 "$TMP/f" "deadbeef" 2>/dev/null; then
  fail "verify_sha256 must reject mismatch"
fi
ok "verify_sha256 rejects mismatch"

# 4. verify_tree accept/reject.
make_fixture_tree "$TMP/tree"
verify_tree "$TMP/tree" || fail "verify_tree accepts pinned tree"
ok "verify_tree accepts pinned tree"
sed -i 's/SUBLEVEL = 37/SUBLEVEL = 38/' "$TMP/tree/Makefile"
if verify_tree "$TMP/tree" 2>/dev/null; then
  fail "verify_tree must reject wrong sublevel"
fi
ok "verify_tree rejects wrong sublevel"

# 5. ensure_tarball: download once, then cache hit (no second fetch).
CURL_CALLS=0
do_curl() { # fixture-copier: fetch.sh calls `do_curl --output <file> <url>`
  local out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output) out="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  CURL_CALLS=$((CURL_CALLS + 1))
  cp "$FIXTURE" "$out"
}
ensure_tarball
[[ -f "$(tarball_path)" ]] || fail "ensure_tarball produced no tarball"
ok "ensure_tarball downloads into cache"
[[ "$CURL_CALLS" -eq 1 ]] || fail "expected 1 download call, got $CURL_CALLS"
ok "exactly one network call on cold cache"

ensure_tarball
[[ "$CURL_CALLS" -eq 1 ]] || fail "cache hit re-downloaded (calls=$CURL_CALLS)"
ok "cache hit performs no network call"

# 6. Corrupt cache is detected, removed, re-fetched on next call.
printf 'garbage' >> "$(tarball_path)"
if ensure_tarball 2>/dev/null; then
  fail "corrupt cache must fail verification"
fi
[[ ! -f "$(tarball_path)" ]] || fail "corrupt cache file must be removed"
ok "corrupt cache detected and removed"
ensure_tarball
[[ "$CURL_CALLS" -eq 2 ]] || fail "expected re-download after corruption"
ok "re-downloads after cache corruption"

# 7. ensure_tree extracts fixture and is idempotent (no re-extract).
ensure_tree
[[ -f "$(tree_path)/Makefile" ]] || fail "ensure_tree produced no tree"
[[ -d "$(tree_path)/arch/um" ]] || fail "tree missing arch/um"
ok "ensure_tree extracts verified tree"
printf 'sentinel' > "$(tree_path)/.sentinel"
ensure_tree
[[ "$(cat "$(tree_path)/.sentinel")" == "sentinel" ]] || fail "ensure_tree re-extracted existing tree"
ok "ensure_tree idempotent (no re-extract)"

printf '\nall %d tests passed\n' "$PASS"
