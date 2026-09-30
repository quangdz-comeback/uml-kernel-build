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

# --- 4. uml_nt_ntpath (M3.5): pure path logic, runnable host test --------
# glibc host runtime + the freestanding types: no name collisions (the
# typedefs above are all NT-isms), so this compiles and RUNS.
cat > "$TMP/ntpath.c" <<'EOF'
#include <stdio.h>
#include <ntabi.h>
static int fails;
static void expect(long long got, long long want, const char *what)
{
	if (got != want) {
		printf("FAIL- %s: got %lld want %lld\n", what, got, want);
		fails++;
	}
}
int main(void)
{
	WCHAR buf[64];

	expect(uml_nt_ntpath("C:\\base.img", buf, 64), 15, "len basic");
	if (buf[0] != '\\' || buf[1] != '?' || buf[2] != '?' ||
	    buf[3] != '\\') { puts("FAIL- prefix"); fails++; }
	if (buf[4] != 'C' || buf[14] != 'g') { puts("FAIL- body"); fails++; }
	if (buf[15] != 0) { puts("FAIL- NUL"); fails++; }

	expect(uml_nt_ntpath(NULL, buf, 64), -3, "NULL path");
	expect(uml_nt_ntpath("", buf, 64), -3, "empty path");
	expect(uml_nt_ntpath("caf\xc3\xa9", buf, 64), -1, "non-ascii");
	expect(uml_nt_ntpath("12345678901234567890", buf, 8), -2,
	       "output too small");
	{
		char big[60];
		int i;
		for (i = 0; i < 59; i++)
			big[i] = 'x';
		big[59] = 0;
		/* 4 prefix + 59 chars = 63 WCHARs, NUL at [63] fits */
		expect(uml_nt_ntpath(big, buf, 64), 63, "max fit");
	}
	expect(uml_nt_ntpath("xxxxxxxxxx", buf, 64), 14, "short fit");

	if (fails)
		return 1;
	puts("ok  - uml_nt_ntpath: \\??\\ prefix, widening, bounds, errors");
	return 0;
}
EOF
"$CC" --target=x86_64-linux-gnu -I "$INC" -o "$TMP/ntpath" \
	"$TMP/ntpath.c"
"$TMP/ntpath"

# --- 5. winsock helpers (M5.1a): pure inline logic, runnable host test ---
cat > "$TMP/inet.c" <<'EOF'
#include <stdio.h>
#include <ntabi.h>
static int fails;
static void expect(int cond, const char *what)
{
	if (!cond) {
		printf("FAIL- %s\n", what);
		fails++;
	}
}
int main(void)
{
	unsigned int a;

	expect(uml_nt_htons(0x1234) == 0x3412, "htons");
	expect(uml_nt_htonl(0x11223344u) == 0x44332211u, "htonl");
	expect(uml_nt_htonl(0) == 0 && uml_nt_htons(0) == 0, "hton zero");

	expect(uml_nt_inet_pton4("127.0.0.1", &a) == 1, "parse 127.0.0.1");
	expect(((unsigned char *)&a)[0] == 127 &&
	       ((unsigned char *)&a)[1] == 0 &&
	       ((unsigned char *)&a)[2] == 0 &&
	       ((unsigned char *)&a)[3] == 1, "127.0.0.1 wire bytes");

	expect(uml_nt_inet_pton4("10.0.2.15", &a) == 1, "parse 10.0.2.15");
	expect(((unsigned char *)&a)[0] == 10 &&
	       ((unsigned char *)&a)[3] == 15, "10.0.2.15 wire bytes");

	expect(uml_nt_inet_pton4("0.0.0.0", &a) == 1 && a == 0,
	       "parse 0.0.0.0");
	expect(uml_nt_inet_pton4("255.255.255.255", &a) == 1 &&
	       a == 0xffffffffu, "parse 255.255.255.255");

	expect(uml_nt_inet_pton4("256.1.1.1", &a) == 0, "reject octet 256");
	expect(uml_nt_inet_pton4("1.2.3", &a) == 0, "reject 3 octets");
	expect(uml_nt_inet_pton4("1.2.3.4.5", &a) == 0, "reject 5 octets");
	expect(uml_nt_inet_pton4("a.b.c.d", &a) == 0, "reject letters");
	expect(uml_nt_inet_pton4("01.2.3.4", &a) == 0, "reject leading zero");
	expect(uml_nt_inet_pton4("1.2.3.4 ", &a) == 0, "reject trailing junk");
	expect(uml_nt_inet_pton4("1..2.3", &a) == 0, "reject empty octet");
	expect(uml_nt_inet_pton4(NULL, &a) == 0, "reject NULL");

	if (fails)
		return 1;
	puts("ok  - uml_nt_htons/htonl/inet_pton4: byte order + strict parse");
	return 0;
}
EOF
"$CC" --target=x86_64-linux-gnu -I "$INC" -o "$TMP/inet" "$TMP/inet.c"
"$TMP/inet"
