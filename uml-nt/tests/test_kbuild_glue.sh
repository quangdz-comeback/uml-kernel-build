#!/usr/bin/env bash
# Kbuild glue test (M1.4): on a pristine fetched+extracted v6.18.37 tree,
# apply.sh must land the overlay + patch series, uml_nt_defconfig must
# resolve CONFIG_OS_WINDOWS=y, and Kbuild must compile the os-Windows
# objects through the normal descent (dir Makefiles read, ccflags applied).
#
# Runs on Linux CI (D5a environment) and locally; needs the tarball cache
# (network on first ever run).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel"
LOG="$(mktemp)"
BUILD="$(mktemp -d /tmp/uml-glue-build.XXXXXX)"
trap 'rm -rf "$BUILD" "$LOG"' EXIT

TREE="$(bash "$K/fetch.sh" extract)"

bash "$K/apply.sh" "$TREE" >/dev/null
bash "$K/apply.sh" "$TREE" >/dev/null  # idempotency: second run is a no-op
echo "ok  - apply.sh lands overlay + patches (idempotent)"

make -C "$TREE" O="$BUILD" ARCH=um uml_nt_defconfig > "$LOG" 2>&1 || {
  echo "FAIL- uml_nt_defconfig"; tail -20 "$LOG"; exit 1; }
grep -q '^CONFIG_OS_WINDOWS=y' "$BUILD/.config" || {
  echo "FAIL- CONFIG_OS_WINDOWS=y missing from .config"; exit 1; }
echo "ok  - uml_nt_defconfig resolves CONFIG_OS_WINDOWS=y"

make -C "$TREE" O="$BUILD" ARCH=um \
	arch/um/os-Windows/file.o \
	arch/um/os-Windows/skas/process.o \
	arch/x86/um/os-Windows/mcontext.o \
	> "$LOG" 2>&1 || { echo "FAIL- kbuild os-Windows objects"; tail -30 "$LOG"; exit 1; }
for o in arch/um/os-Windows/file.o \
	 arch/um/os-Windows/skas/process.o \
	 arch/x86/um/os-Windows/mcontext.o; do
  [[ -f "$BUILD/$o" ]] || { echo "FAIL- missing $o"; exit 1; }
done
echo "ok  - Kbuild compiles os-Windows objects (um + x86/um, subdir descent + ccflags)"

echo
echo "all glue checks passed"
