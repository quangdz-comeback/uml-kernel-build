#!/usr/bin/env bash
# ntabi.h checks (M1.5): one header, two compilers, two ABIs.
#   1. ELF freestanding compile + DISASSEMBLY proof that calls through the
#      D9 table use the Microsoft x64 convention (arg1 in rcx, no SysV
#      rdi/rsi argument setup).
#   2. mingw PE compile (launcher/stub will include the same header).
#   3. Self-containedness of the header alone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
PE_CC="${PE_CC:-x86_64-w64-mingw32-gcc}"

# --- 1. ELF freestanding + ABI disassembly ------------------------------
"$CC" --target=x86_64-linux-gnu -c -ffreestanding -nostdinc -O1 \
	-I "$INC" -o "$TMP/ntabi_elf.o" "$HERE/ntabi_abi_check.c"
echo "ok  - ntabi.h compiles freestanding for ELF (SysV target)"

disasm="$("$CC" --target=x86_64-linux-gnu -c -ffreestanding -nostdinc -O1 \
	-I "$INC" -o "$TMP/consume.o" -x c - <<'EOF'
#include <ntabi.h>
NTSTATUS consume(struct uml_nt_api_table *t, HANDLE h, void *buf, ULONG len)
{
	IO_STATUS_BLOCK iosb;
	return t->NtWriteFile(h, 0, 0, 0, &iosb, buf, len, 0, 0);
}
EOF
)"
objdump -d "$TMP/consume.o" > "$TMP/disasm.txt"

# consume() is SysV (kernel-side ELF): t in %rdi, h in %rsi. The call into
# NT must convert to ms_abi: h -> %rcx, shadow space + stack args, indirect
# call via the table (NtWriteFile pinned at offset 0x18 by static assert).
if ! grep -qE 'call +\*0x18\(%rdi\)' "$TMP/disasm.txt"; then
	echo "FAIL- expected indirect call via table offset 0x18"
	grep -A 30 'consume' "$TMP/disasm.txt" | head -30
	exit 1
fi
if ! grep -qE 'mov +%rsi,%rcx' "$TMP/disasm.txt"; then
	echo "FAIL- arg1 not converted into %rcx (ms_abi arg1 broken)"
	cat "$TMP/disasm.txt"
	exit 1
fi
if ! grep -qE 'mov +%r[a-z0-9]+,0x20\(%rsp\)' "$TMP/disasm.txt"; then
	echo "FAIL- no shadow-space/stack-arg store at 0x20(%rsp) (ms_abi broken)"
	cat "$TMP/disasm.txt"
	exit 1
fi
echo "ok  - NT call: fn via table 0x18(%rdi), arg1 -> %rcx, shadow space at 0x20(%rsp) — ms_abi proven"

# --- 2. mingw PE compile (same header feeds launcher/stub) ---------------
if command -v "$PE_CC" >/dev/null 2>&1; then
	"$PE_CC" -c -O1 -I "$INC" -o "$TMP/ntabi_pe.o" "$HERE/ntabi_abi_check.c"
	echo "ok  - ntabi.h compiles under x86_64-w64-mingw32-gcc (PE)"
else
	echo "skip- PE cross-compiler not installed locally (CI linux has it)"
fi

# --- 3. self-containedness ----------------------------------------------
printf '#include <ntabi.h>\nint probe(void){return STATUS_SUCCESS;}\n' \
	> "$TMP/self.c"
"$CC" --target=x86_64-linux-gnu -c -ffreestanding -nostdinc -I "$INC" \
	-o "$TMP/self.o" "$TMP/self.c"
echo "ok  - ntabi.h is self-contained (no windows.h, no libc)"
