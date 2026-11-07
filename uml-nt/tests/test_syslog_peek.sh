#!/usr/bin/env bash
# S80: the /dev/log peek — the chain's own words, printable and clamped.
#
# Report 380: the console reader (agetty) ended run 42274124035 with
# socket/connect/sendto/close/clock_nanosleep — log_err() feeding syslog and
# then exit_slowly() — and the 89-byte message went to journald, where a
# referee's systemd.log cannot see it. The next run has to say WHAT the guest
# complained about, not merely that it complained.
#
# The copy is untrusted guest memory on its way into a one-record-per-line log,
# so the sanitiser is the contract: printable bytes only, always terminated,
# never longer than the caller's buffer.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <diag_str.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
int main(void)
{
	char out[16];

	/* a plain message survives byte for byte */
	CHECK(uml_nt_diag_sanitize(out, sizeof(out), "login: root", 11) == 11);
	CHECK(strcmp(out, "login: root") == 0);

	/* a newline cannot end the record early — the referee greps lines */
	CHECK(uml_nt_diag_sanitize(out, sizeof(out), "a\nb", 3) == 3);
	CHECK(strcmp(out, "a.b") == 0);

	/* NUL, DEL, ESC sequences and every high byte are dots, in place */
	{
		const char evil[] = { 'x', 0x00, 0x1b, '[', 'A', 0x7f, 0xff, 'y' };

		CHECK(uml_nt_diag_sanitize(out, sizeof(out), evil, sizeof(evil)) == 8);
		CHECK(strcmp(out, "x..[A..y") == 0);
	}

	/* clamped to dstmax-1, and always terminated */
	{
		char big[64];
		char small[5];

		memset(big, 'A', sizeof(big));
		CHECK(uml_nt_diag_sanitize(out, 8, big, sizeof(big)) == 7);
		CHECK(out[7] == 0);
		CHECK(strlen(out) == 7);
		CHECK(uml_nt_diag_sanitize(small, sizeof(small), big, sizeof(big)) == 4);
		CHECK(strcmp(small, "AAAA") == 0);
	}

	/* empty input and a zero-size destination are not special cases */
	CHECK(uml_nt_diag_sanitize(out, sizeof(out), "abc", 0) == 0);
	CHECK(out[0] == 0);
	CHECK(uml_nt_diag_sanitize(out, 0, "abc", 3) == 0);

	if (fails) { printf("syslog_peek: %d failure(s)\n", fails); return 1; }
	printf("syslog_peek: guest bytes reach the log as one printable line\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"

S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
H="$HERE/../kernel/overlay/arch/um/os-Windows/include/syscall.h"
grep -q '#include <diag_str.h>' "$S" \
	|| { echo "FAIL: the syscall path does not use the sanitiser"; exit 1; }
grep -q '\[syslog\] pid' "$S" \
	|| { echo "FAIL: no [syslog] record — the payload still goes only to journald"; exit 1; }
grep -q 'nr == 44 /\* sendto \*/' "$S" \
	|| { echo "FAIL: the peek is not attached to sendto"; exit 1; }
grep -q 'c->syslog_n < 32' "$S" \
	|| { echo "FAIL: the peek is not budgeted per conn"; exit 1; }
grep -q 'uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a\[1\]' "$S" \
	|| { echo "FAIL: the payload is not read back through the D15 walker"; exit 1; }
grep -q 'unsigned syslog_n;' "$H" \
	|| { echo "FAIL: no per-conn budget field"; exit 1; }
# S91: the window widened from 16 to 64 — sixteen filled up on the reader's
# syslog dance and again on login's GetUserRecord → munmap teardown.
grep -q 'sc_total < 64' "$S" \
	|| { echo "FAIL: the death dump did not widen to 64 calls"; exit 1; }
echo "syslog_peek: the chain's /dev/log message reaches the referee's log"
echo "syslog_peek: the death dump is sixty-four calls wide"
