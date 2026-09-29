#!/usr/bin/env bash
# Compile-check the os-Windows skeleton (M1.3): every module must build
# freestanding for the ELF target — the same gate the real kernel build
# (M1.6, D5a) will apply, minus kernel headers.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../kernel/os-Windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

command -v "$CC" >/dev/null 2>&1 || { echo "clang not found"; exit 1; }

# Module file set must mirror the os-Linux map (minus elf_aux.c, plus
# stub-impl.c scaffolding). internal.h + Makefiles are not compiled here.
EXPECTED="file.c start_up.c mem.c process.c execvp.c helper.c umid.c \
signal.c util.c time.c irq.c sigio.c tty.c registers.c main.c \
user_syms.c stub-impl.c skas/mem.c skas/process.c"
ACTUAL="$(cd "$SRC" && find . -name '*.c' | sed 's|^\./||' | sort | tr '\n' ' ')"
EXPECTED_SORTED="$(printf '%s\n' $EXPECTED | sort | tr '\n' ' ')"
if [[ "$ACTUAL" != "$EXPECTED_SORTED" ]]; then
  echo "FAIL- file set drifted"
  echo "  expected: $EXPECTED_SORTED"
  echo "  actual:   $ACTUAL"
  exit 1
fi
echo "ok  - file set mirrors os-Linux map (elf_aux.c excluded, stub-impl.c added)"

FAIL=0
for f in $EXPECTED; do
  obj="$TMP/$(echo "$f" | tr '/' '_').o"
  if ! "$CC" --target=x86_64-linux-gnu -c -ffreestanding -nostdinc \
       -Wall -Werror -I "$SRC/include" \
       -o "$obj" "$SRC/$f" 2>"$TMP/err"; then
    echo "FAIL- compile: $f"
    cat "$TMP/err"
    FAIL=1
    continue
  fi
  # PANIC-style contract: every module with entry points must PANIC.
  case "$f" in
    user_syms.c|stub-impl.c) ;; # documented exceptions (empty / hook body)
    *)
      if ! grep -q 'stub_panic(' "$SRC/$f"; then
        echo "FAIL- not PANIC-style: $f"
        FAIL=1
      fi
      ;;
  esac
done
[[ "$FAIL" -eq 0 ]] || exit 1
echo "ok  - all $(printf '%s\n' $EXPECTED | wc -l) objects compile freestanding (-Wall -Werror), PANIC-style enforced"
