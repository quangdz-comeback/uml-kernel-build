#!/usr/bin/env bash
# S111: the stub is a separate program with its own print path.
#
# stub.c is compiled by the boot job's Makefile with mingw, not by the kernel
# build I was checking. Calling os_info() there is an implicit declaration, which
# is fatal on that toolchain — and the two referees died in the BUILD step, not
# in the boot. Kernel-side helpers are not available inside the stub.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUB="$HERE/../stub"

# 1. no kernel-side logging in the stub
if grep -nE '^[^/]*\bos_info\(' "$STUB/stub.c" | grep -v '^\s*\*' ; then
	echo "FAIL: stub.c calls the kernel-side os_info"; exit 1
fi

# 2. and it really compiles for the target it ships to, when the toolchain exists
CC=x86_64-w64-mingw32-gcc
if command -v "$CC" >/dev/null 2>&1; then
	"$CC" -c "$STUB/stub.c" -o /tmp/uml_nt_stub_check.o \
		-I"$STUB" \
		-I"$HERE/../kernel/overlay/arch/um/include/shared" \
		-I"$HERE/../kernel/overlay/arch/um/os-Windows/include" \
		2>/tmp/uml_nt_stub_check.log || {
		grep -E 'error' /tmp/uml_nt_stub_check.log | head -5
		echo "FAIL: stub.c does not compile"; exit 1; }
	echo "stub_build: stub.c compiles for mingw with no kernel-side calls"
else
	echo "stub_build: no mingw here; kernel-side API check only"
fi
