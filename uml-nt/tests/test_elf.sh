#!/usr/bin/env bash
# guest ELF loader unit test (M3.4): synthetic images + the REAL
# linker-produced probe guest (built here with clang+lld — the same
# recipe as the CI kernel job's guest build, so the fixture cannot
# drift from what the loader actually sees).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$HERE/../kernel/overlay/arch/um"
OS_DIR="$SRC_DIR/os-Windows"
GUEST_DIR="$HERE/../guest"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
LD="${LD:-ld.lld}"

# the real-fixture build needs an ELF cross linker
if ! command -v "$LD" >/dev/null 2>&1; then
	echo "ld.lld not found — building synthetic-only" >&2
	LD=""
fi

"$CC" -O1 -Wall -Wextra -Werror \
	-I"$OS_DIR/include" -I"$SRC_DIR/include/shared" \
	-o "$TMP/test" "$HERE/test_elf.c" \
	"$OS_DIR/skas/elf.c" "$OS_DIR/skas/elf_split.c" "$OS_DIR/skas/vma.c" \
	"$OS_DIR/skas/physalloc.c" "$OS_DIR/skas/scan_patch.c"

# the REAL S3 init fixture — the rootfs recipe verbatim (rootfs/
# Makefile): -static -nostdlib -no-pie links at 0x400000, so this
# exercises the low-link shift on real linker output
INIT_FIXTURE=""
if [ -n "$LD" ]; then
	"$CC" --target=x86_64-linux-gnu -c "$GUEST_DIR/init.S" \
		-o "$TMP/init.o"
	"$LD" -static -nostdlib -e _start -z max-page-size=0x10000 \
		--image-base=0x62000000 -o "$TMP/guest-init.elf" \
		"$TMP/init.o"
	"$CC" --target=x86_64-linux-gnu -static -nostdlib -no-pie -O1 \
		-Wall -o "$TMP/rootfs-init" "$HERE/../rootfs/init.c"
	INIT_FIXTURE="$TMP/rootfs-init"
	"$TMP/test" "$TMP/guest-init.elf" "$INIT_FIXTURE"
else
	"$TMP/test"
fi
