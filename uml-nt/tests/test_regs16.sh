#!/usr/bin/env bash
# S457: rbp names the faulting frame, rbx+rdi name the store target.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/start_up.c"
M="$HERE/../kernel/overlay/arch/um/os-Windows/skas/mmctx.c"

grep -q 'regs16 rax=%llx rbx=%llx rcx=%llx rdx=%llx' "$S" \
	|| { echo "FAIL: first eight registers not printed"; exit 1; }
grep -q 'regs16 r8=%llx r9=%llx r10=%llx r11=%llx' "$S" \
	|| { echo "FAIL: r8-r15 not printed"; exit 1; }
# the offsets must be the real CONTEXT ones, not duplicates
grep -q 'CTXR(0xb0)' "$S" || { echo "FAIL: rdi offset wrong"; exit 1; }
grep -q 'CTXR(0xa0)' "$S" || { echo "FAIL: rbp offset wrong"; exit 1; }
grep -q 'CTXR(0x90)' "$S" || { echo "FAIL: rbx offset wrong"; exit 1; }
# S457: mmctx unmap must sit inside the NULL test
awk '/if \(c->d != NULL\) \{/{f=1} f&&/UnmapViewOfFile\(c->d\)/{print "OK"; exit}' "$M" | grep -q OK \
	|| { echo "FAIL: UnmapViewOfFile outside the null test"; exit 1; }
echo "regs16: sixteen registers at the true CONTEXT offsets; unmap braced"
