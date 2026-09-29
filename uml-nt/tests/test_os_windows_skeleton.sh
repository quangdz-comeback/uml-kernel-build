#!/usr/bin/env bash
# os-Windows module contract (M1.7): the split between REAL modules and
# remaining PANIC-skeleton modules must hold.
#
#   REAL modules implement actual NT behavior via the D9 table + kernel
#   headers — they must NOT include stub-impl.h (its type mirrors collide
#   with the real headers; found the hard way at M1.7). They are compiled
#   by the kbuild path (test_kbuild_glue.sh, uml-nt-m1.yml build).
#
#   SKELETON modules keep the M1.3 PANIC scaffolding and must still
#   compile freestanding standalone (-Wall -Werror).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../kernel/overlay/arch/um/os-Windows"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

command -v "$CC" >/dev/null 2>&1 || { echo "clang not found"; exit 1; }

EXPECTED=(file.c start_up.c mem.c process.c execvp.c helper.c umid.c \
signal.c util.c time.c irq.c sigio.c tty.c registers.c main.c \
user_syms.c stub-impl.c skas/mem.c skas/process.c)
ACTUAL="$(cd "$SRC" && find . -name '*.c' | sed 's|^\./||' | sort | tr '\n' ' ')"
EXPECTED_SORTED="$(printf '%s\n' "${EXPECTED[@]}" | sort | tr '\n' ' ')"
if [[ "$ACTUAL" != "$EXPECTED_SORTED" ]]; then
  echo "FAIL- file set drifted"
  echo "  expected: $EXPECTED_SORTED"
  echo "  actual:   $ACTUAL"
  exit 1
fi
echo "ok  - file set mirrors os-Linux map (elf_aux.c excluded, stub-impl.c added)"

# --- REAL modules: kernel-header based, no scaffolding type mirrors -----
REAL="main.c util.c time.c mem.c signal.c irq.c start_up.c process.c"
for f in $REAL; do
  if grep -q 'stub-impl\.h' "$SRC/$f"; then
    echo "FAIL- real module $f still includes stub-impl.h (type-mirror collision)"
    exit 1
  fi
done
grep -q 'boot-info\.h' "$SRC/main.c" || {
  echo "FAIL- main.c must include boot-info.h (launcher handoff)"; exit 1; }
grep -q 'UML_BOOT_MAGIC' "$SRC/main.c" || {
  echo "FAIL- main.c must validate the boot-info magic"; exit 1; }
grep -q 'UML_NT_MEMFD_PHYS' "$SRC/process.c" || {
  echo "FAIL- process.c must route physmem pseudo-fd (mem.c)"; exit 1; }
echo "ok  - real modules: no stub-impl.h, D9 handoff validated in main.c"

# --- SKELETON modules: freestanding compile + PANIC-style enforced ------
SKELETON=(file.c execvp.c helper.c umid.c sigio.c tty.c registers.c \
skas/mem.c skas/process.c)
FAIL=0
for f in "${SKELETON[@]}"; do
  obj="$TMP/$(echo "$f" | tr '/' '_').o"
  if ! "$CC" --target=x86_64-linux-gnu -c -ffreestanding -nostdinc \
       -Wall -Werror -I "$SRC/include" \
       -o "$obj" "$SRC/$f" 2>"$TMP/err"; then
    echo "FAIL- compile: $f"
    cat "$TMP/err"
    FAIL=1
    continue
  fi
  if ! grep -q 'stub_panic(' "$SRC/$f"; then
    echo "FAIL- not PANIC-style: $f"
    FAIL=1
  fi
done
[[ "$FAIL" -eq 0 ]] || exit 1
echo "ok  - skeleton modules compile freestanding (-Wall -Werror), PANIC-style enforced"

# --- user_syms.c / stub-impl.c structural -------------------------------
[[ -s "$SRC/user_syms.c" ]] || { echo "FAIL- user_syms.c vanished"; exit 1; }
grep -q 'stub-panic\.h' "$SRC/include/stub-impl.h" || {
  echo "FAIL- stub-impl.h must include stub-panic.h (single panic decl)"; exit 1; }
echo "ok  - stub-impl.h/panic split intact"
