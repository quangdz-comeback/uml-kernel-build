#!/usr/bin/env bash
# uml-nt — fetch pinned Linux source (v6.18.37) on the fly. NEVER commit source.
#
# Why: HANDOFF hard-rule 1 forbids committing/pre-downloading Linux source into
# the repo; this script is the single sanctioned entry point to obtain it:
#
#   fetch.sh check    — cheap URL/pin validation, no big download (CI every push)
#   fetch.sh tarball  — download + sha256-verify tarball into cache
#   fetch.sh extract  — tarball + extract + verify tree (Makefile version pin)
#   fetch.sh file P   — fetch one file at the pinned tag (patch-series helper)
#   fetch.sh clean    — remove cache
#
# Pin facts (verified 2026-09-29):
#   - torvalds/linux does NOT carry sublevel tags: raw.githubusercontent.com/
#     torvalds/linux/v6.18.37 and the matching codeload tarball return 404.
#     HANDOFF's documented fallback therefore becomes primary:
#       * per-file fetches  -> cgit stable ?h=v6.18.37
#       * tarball           -> kernel.org pub/linux/kernel/v6.x CDN, checksum
#         cross-checked against the official sha256sums.asc of that directory.
set -euo pipefail

readonly LINUX_VERSION="6.18.37"
readonly TARBALL="linux-${LINUX_VERSION}.tar.xz"
# sha256 from kernel.org pub/linux/kernel/v6.x/sha256sums.asc (official sums).
readonly PIN_SHA256_DEFAULT="a83cd200e6646db52866b8309e9137b9e9048b613cbda10ced2b811aae125255"
# Test hook only (tests/test_fetch.sh overrides it for fixture tarballs).
PIN_SHA256="${UML_NT_PIN_SHA256:-$PIN_SHA256_DEFAULT}"

readonly TARBALL_URLS=(
  "https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/${TARBALL}"
  "https://www.kernel.org/pub/linux/kernel/v6.x/${TARBALL}"
)
readonly SHA256SUMS_URL="https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc"
# Per-file pin template (torvalds raw is 404 for sublevel tags — see header).
readonly FILE_URL_TEMPLATE="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/{path}?h=v${LINUX_VERSION}"

err() { printf 'fetch.sh: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

cache_dir() { printf '%s' "${UML_NT_CACHE_DIR:-${HOME:?}/.cache/uml-nt}"; }
tarball_path() { printf '%s/%s' "$(cache_dir)" "${TARBALL:?}"; }
tree_path() { printf '%s/src-v%s' "$(cache_dir)" "${LINUX_VERSION:?}"; }
file_url() { printf '%s' "${FILE_URL_TEMPLATE/\{path\}/$1}"; }

# Thin network wrapper so unit tests can intercept it; do not bypass.
do_curl() { curl -fSL --retry 3 --connect-timeout 15 "$@"; }

verify_sha256() { # <file> <expected-hex>
  local got
  got="$(sha256sum "$1")" || return 1
  got="${got%% *}"
  if [[ "$got" != "$2" ]]; then
    err "sha256 mismatch for $1: got $got want $2"
    return 1
  fi
}

verify_tree() { # <dir> — cheap content pin: Makefile version fields
  local dir="${1:?}" fields
  if [[ ! -f "$dir/Makefile" ]]; then
    err "no Makefile in $dir"
    return 1
  fi
  fields="$(awk '/^(VERSION|PATCHLEVEL|SUBLEVEL) =/ {printf "%s ", $3}' "$dir/Makefile")"
  if [[ "$fields" != "6 18 37 " ]]; then
    err "Makefile version fields '$fields' != pinned 6 18 37"
    return 1
  fi
  if [[ ! -d "$dir/arch/um" ]]; then
    err "arch/um missing — not a usable kernel tree"
    return 1
  fi
}

# ensure_* return non-zero instead of exiting: callers (incl. tests in `if`
# context) must be able to compose them; only main() terminates the process.
ensure_tarball() {
  local tp url ok=""
  tp="$(tarball_path)"
  mkdir -p "$(cache_dir)"
  if [[ -f "$tp" ]]; then
    if ! verify_sha256 "$tp" "$PIN_SHA256"; then
      rm -f "$tp"
      err "cached tarball corrupt — removed, re-run to re-download"
      return 1
    fi
    return 0
  fi
  for url in "${TARBALL_URLS[@]}"; do
    err "downloading $url"
    if do_curl --output "$tp.partial" "$url"; then
      ok=1
      break
    fi
    rm -f "$tp.partial"
  done
  if [[ -z "$ok" ]]; then
    err "all mirrors failed for $TARBALL"
    return 1
  fi
  if ! verify_sha256 "$tp.partial" "$PIN_SHA256"; then
    rm -f "$tp.partial"
    err "downloaded tarball failed pin check"
    return 1
  fi
  mv "$tp.partial" "$tp"
}

ensure_tree() {
  local tree tmp
  tree="$(tree_path)"
  if [[ -d "$tree" ]] && verify_tree "$tree"; then
    return 0
  fi
  ensure_tarball || return 1
  tmp="$(tree_path).tmp.$$"
  rm -rf "$tree" "$tmp"
  mkdir -p "$tmp"
  err "extracting $TARBALL"
  if ! tar -xJf "$(tarball_path)" -C "$tmp" --strip-components=1; then
    rm -rf "$tmp"
    err "extraction failed"
    return 1
  fi
  if ! verify_tree "$tmp"; then
    rm -rf "$tmp"
    err "extracted tree failed pin check"
    return 1
  fi
  mv "$tmp" "$tree"
}

cmd_tarball() { ensure_tarball; printf '%s\n' "$(tarball_path)"; }
cmd_extract() { ensure_tree; printf '%s\n' "$(tree_path)"; }

cmd_file() { # <repo-relative-path> [dest]
  if [[ $# -lt 1 ]]; then
    die "usage: fetch.sh file <path> [dest]"
  fi
  do_curl "$(file_url "$1")" --output "${2:-/dev/stdout}"
}

cmd_check() { # validate pins cheaply — runs on every CI push
  local url code
  for url in "${TARBALL_URLS[@]}"; do
    code="$(curl -sIL -o /dev/null -w '%{http_code}' --max-time 30 "$url" || true)"
    printf 'tarball %-4s %s\n' "$code" "$url"
  done
  code="$(curl -sL -o /dev/null -w '%{http_code}' --max-time 30 "$(file_url Makefile)" || true)"
  printf 'file    %-4s %s\n' "$code" "$(file_url Makefile)"
  # Re-validate the pin against kernel.org's official sums (catches a bad pin).
  if ! curl -sL --max-time 60 "$SHA256SUMS_URL" | grep -F "$PIN_SHA256_DEFAULT" >/dev/null; then
    err "PIN_SHA256 not found in official $SHA256SUMS_URL"
    return 1
  fi
  printf 'pin     ok    %s\n' "$PIN_SHA256_DEFAULT"
}

cmd_clean() {
  local dir
  dir="$(cache_dir)"
  rm -rf "${dir:?}/"
}

main() {
  case "${1:-}" in
    tarball) shift; cmd_tarball "$@" ;;
    extract) shift; cmd_extract "$@" ;;
    file)    shift; cmd_file "$@" ;;
    check)   shift; cmd_check "$@" ;;
    clean)   shift; cmd_clean "$@" ;;
    *) die "usage: fetch.sh {check|tarball|extract|file <path> [dest]|clean}" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
