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
static void wset(unsigned char *p, unsigned off, unsigned int v) { memcpy(p + off, &v, 4); }
int main(void)
{
	unsigned char buf[UML_NT_TERMIOS_SIZE];
	struct uml_nt_tty_model m;
	int n;
	const unsigned char *cc;

	memset(&m, 0, sizeof(m));	/* a fresh descriptor: nothing set yet */

	/* TCGETS: a cooked console with the console's own erase character */
	memset(buf, 0xa5, sizeof(buf));
	n = uml_nt_tty_ioctl_fill(&m, UML_NT_TCGETS, NULL, buf, sizeof(buf));
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
	n = uml_nt_tty_ioctl_fill(&m, UML_NT_TIOCGWINSZ, NULL, buf, sizeof(buf));
	CHECK(n == 8);
	CHECK(((unsigned short *)buf)[0] == 24);
	CHECK(((unsigned short *)buf)[1] == 80);
	n = uml_nt_tty_ioctl_fill(&m, UML_NT_TIOCGPGRP, NULL, buf, sizeof(buf));
	CHECK(n == 4);

	/* the writes are accepted with nothing to return */
	CHECK(uml_nt_tty_ioctl_fill(&m, UML_NT_TCSETS, buf, buf, sizeof(buf)) == 0);
	CHECK(uml_nt_tty_ioctl_fill(&m, UML_NT_TCSETSF, buf, NULL, sizeof(buf)) == 0);
	CHECK(uml_nt_tty_ioctl_fill(&m, UML_NT_TCFLSH, NULL, NULL, sizeof(buf)) == 0);
	CHECK(uml_nt_tty_ioctl_fill(&m, UML_NT_TIOCSPGRP, NULL, buf, sizeof(buf)) == 0);

	/* and something alien is still not ours */
	CHECK(uml_nt_tty_ioctl_fill(&m, 0xdeadbeefu, NULL, buf, sizeof(buf)) == -1);
	/* a buffer too small is refused, not overrun */
	CHECK(uml_nt_tty_ioctl_fill(&m, UML_NT_TCGETS, NULL, buf, 8) == -1);

	/* S81: the set STICKS. Debian's glibc tcsetattr() is
	 * TCGETS -> TCSETS -> TCGETS and calls a set that did not take effect an
	 * EINVAL (libc+0xfd44b, report 380); a constant answer cannot pass that,
	 * and agetty died in termio_final() because of it. */
	{
		struct uml_nt_tty_model m2;
		unsigned char want[UML_NT_TERMIOS_SIZE];
		unsigned char back[UML_NT_TERMIOS_SIZE];

		memset(&m2, 0, sizeof(m2));
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCGETS, NULL, want,
					    sizeof(want)) == UML_NT_TERMIOS_SIZE);
		/* what agetty's termio_final asks for: cooked, ECHO on, IXON,
		 * CS8 | CREAD | HUPCL | B9600 */
		wset(want, 0, UML_NT_T_I_ICRNL | UML_NT_T_I_IXON | 0x1000u /* IXOFF */);
		wset(want, 4, UML_NT_T_O_OPOST | UML_NT_T_O_ONLCR);
		wset(want, 8, 0x0d00u | UML_NT_T_C_CS8 | UML_NT_T_C_CREAD | 0x400u);
		wset(want, 12, UML_NT_T_L_ISIG | UML_NT_T_L_ICANON |
			      UML_NT_T_L_ECHO | UML_NT_T_L_ECHOE |
			      UML_NT_T_L_ECHOK | 0x800u /* ECHOKE */);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCSETS, want, NULL,
					    sizeof(want)) == 0);
		/* the read-back must be the request, byte for byte */
		memset(back, 0xa5, sizeof(back));
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCGETS, NULL, back,
					    sizeof(back)) == UML_NT_TERMIOS_SIZE);
		CHECK(memcmp(back, want, sizeof(want)) == 0);
		/* and a raw-mode set (agetty's prompt time) sticks the same way */
		wset(want, 12, 0);		/* c_lflag = 0: no ECHO, no ICANON */
		wset(want, 0, 0);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCSETS, want, NULL,
					    sizeof(want)) == 0);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCGETS, NULL, back,
					    sizeof(back)) == UML_NT_TERMIOS_SIZE);
		CHECK(memcmp(back, want, sizeof(want)) == 0);
		/* TCSETSW/TCSETSF remember too */
		wset(want, 12, UML_NT_T_L_ICANON);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCSETSF, want, NULL,
					    sizeof(want)) == 0);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCGETS, NULL, back,
					    sizeof(back)) == UML_NT_TERMIOS_SIZE);
		CHECK(memcmp(back, want, sizeof(want)) == 0);
		/* an unreadable input buffer changes nothing and does not lie */
		wset(back, 12, 0xdeadbeefu);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCSETS, NULL, NULL,
					    sizeof(want)) == 0);
		CHECK(uml_nt_tty_ioctl_fill(&m2, UML_NT_TCGETS, NULL, back,
					    sizeof(back)) == UML_NT_TERMIOS_SIZE);
		CHECK(w0(back + 12) == UML_NT_T_L_ICANON);
	}

	if (fails) { printf("tty_ioctl: %d failure(s)\n", fails); return 1; }
	printf("tty_ioctl: TCGETS answers a cooked console, the rest is sane\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
grep -q "uml_nt_tty_ioctl_fill(&c->tty_model" "$S" \
	|| { echo "FAIL: the ioctl path does not consult this conn's model"; exit 1; }
grep -q 'uml_nt_uacc_walk(c->mm, uml_boot.physmem_base, a\[2\]' "$S" \
	|| { echo "FAIL: the TCSETS argument is never read, so nothing can be remembered"; exit 1; }
echo "tty_ioctl: the syscall path consults it"
echo "tty_ioctl: a set sticks — the read-back is what was asked for"
