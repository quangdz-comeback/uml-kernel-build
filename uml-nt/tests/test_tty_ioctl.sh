#!/usr/bin/env bash
# S41: the console answers the tty questions login asks.
#
# This port has no kernel tty, so the generic ioctl path answered ENOTTY for
# TCGETS — referee 42069926848 shows exactly one such call in the whole boot,
# "ioctl(0x5401) -> -25", from systemd's kbrequest setup, and login has the same
# question to ask before it can prompt. The answers live in ttymodel.h so they
# can be checked here: what login reads back has to look like a cooked console.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <ttymodel.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
static unsigned int w0(const unsigned char *p) { return *(const unsigned int *)p; }
int main(void)
{
	unsigned char buf[UML_NT_TERMIOS_SIZE];
	int n;
	const unsigned char *cc;

	/* TCGETS: a cooked console with the console's own erase character */
	memset(buf, 0xa5, sizeof(buf));
	n = uml_nt_tty_ioctl_fill(UML_NT_TCGETS, buf, sizeof(buf));
	CHECK(n == UML_NT_TERMIOS_SIZE);
	CHECK(w0(buf + 0) & UML_NT_T_I_ICRNL);
	CHECK(w0(buf + 0) & UML_NT_T_I_IXON);
	CHECK(w0(buf + 4) & UML_NT_T_O_OPOST);
	CHECK((w0(buf + 8) & UML_NT_T_C_CS8) == UML_NT_T_C_CS8);
	CHECK(w0(buf + 8) & UML_NT_T_C_CREAD);
	CHECK(w0(buf + 12) & UML_NT_T_L_ICANON);
	CHECK(w0(buf + 12) & UML_NT_T_L_ISIG);
	CHECK(w0(buf + 12) & UML_NT_T_L_ECHO);
	cc = buf + 16;
	CHECK(cc[0] == 0);				/* c_line */
	CHECK(cc[1 + UML_NT_T_VERASE_IDX] == 0x7f);	/* DEL erases */
	CHECK(cc[1 + UML_NT_T_VMIN_IDX] == 1);
	CHECK(cc[1 + UML_NT_T_VTIME_IDX] == 0);

	/* the window and the process group */
	n = uml_nt_tty_ioctl_fill(UML_NT_TIOCGWINSZ, buf, sizeof(buf));
	CHECK(n == 8);
	CHECK(((unsigned short *)buf)[0] == 24);
	CHECK(((unsigned short *)buf)[1] == 80);
	n = uml_nt_tty_ioctl_fill(UML_NT_TIOCGPGRP, buf, sizeof(buf));
	CHECK(n == 4);

	/* the writes are accepted with nothing to return */
	CHECK(uml_nt_tty_ioctl_fill(UML_NT_TCSETS, buf, sizeof(buf)) == 0);
	CHECK(uml_nt_tty_ioctl_fill(UML_NT_TCSETSF, buf, sizeof(buf)) == 0);
	CHECK(uml_nt_tty_ioctl_fill(UML_NT_TCFLSH, buf, sizeof(buf)) == 0);
	CHECK(uml_nt_tty_ioctl_fill(UML_NT_TIOCSPGRP, buf, sizeof(buf)) == 0);

	/* and something alien is still not ours */
	CHECK(uml_nt_tty_ioctl_fill(0xdeadbeefu, buf, sizeof(buf)) == -1);
	/* a buffer too small is refused, not overrun */
	CHECK(uml_nt_tty_ioctl_fill(UML_NT_TCGETS, buf, 8) == -1);

	if (fails) { printf("tty_ioctl: %d failure(s)\n", fails); return 1; }
	printf("tty_ioctl: TCGETS answers a cooked console, the rest is sane\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
grep -q "uml_nt_tty_ioctl_fill" "$S" || { echo "FAIL: the ioctl path does not consult the model"; exit 1; }
echo "tty_ioctl: the syscall path consults it"
