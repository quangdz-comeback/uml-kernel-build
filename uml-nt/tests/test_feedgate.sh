#!/usr/bin/env bash
# S42: the console feed follows the prompts.
#
# The referee feeds credentials from the moment the guest starts, so they are
# pending long before login asks — and login's own tcsetattr(TCSAFLUSH) then
# discards them (referee 42078765811: three "[confeed] dropped ... at a tty input
# flush", and no "Password:" ever appeared). The feed now waits for the prompt it
# answers: one line per prompt, in order, and never for a "/bin/login:" log line.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <feedgate.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
static void scan(struct uml_nt_feed_gate *g, const char *s)
{
	uml_nt_feed_gate_scan(g, s, (unsigned)strlen(s), 0);
}
int main(void)
{
	struct uml_nt_feed_gate g;

	/* nothing on the console yet: nothing may be released */
	uml_nt_feed_gate_reset(&g);
	scan(&g, "systemd boots\nReached target Multi-User\n");
	CHECK(uml_nt_feed_gate_take(&g) == 0);

	/* S44: colour codes land inside the line — the prompt is still a prompt */
	scan(&g, "\033[0;1;38;5;100mlog\033[0min: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	scan(&g, "\n");

	/* a log line that merely mentions the binary is not a prompt */
	scan(&g, "/bin/login: /bin/login: no version information available\n");
	CHECK(uml_nt_feed_gate_take(&g) == 0);

	/* S43: the prompt split across writes still counts */
	scan(&g, "\numl log");
	CHECK(uml_nt_feed_gate_take(&g) == 0);
	scan(&g, "in: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	scan(&g, "\n");
	/* ... and a kernel log line landing inside it does not lose the prompt */
	scan(&g, "uml log");
	scan(&g, "in: [commit-ahead] pid 1");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	scan(&g, "\n");

	/* the prompt itself: one line, once */
	scan(&g, "\numl login: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	CHECK(uml_nt_feed_gate_take(&g) == 0);

	/* the password prompt: the next line, in order */
	scan(&g, "Password: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	CHECK(uml_nt_feed_gate_take(&g) == 0);

	/* the shell: one command line */
	scan(&g, "\r\n# ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	CHECK(g.lines == 6);	/* 3 from the split/colour cases, then 3 prompts */

	/* a second login prompt re-arms, and order is preserved */
	scan(&g, "\r\numl login: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	scan(&g, "Password: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	CHECK(g.lines == 8);

	/* the ESC stripper on its own: CSI and two-byte forms */
	{
		char out[64];
		unsigned n = uml_nt_feed_strip_esc(out, sizeof(out),
						   "\033[1mab\033[0mcd",
						   (unsigned)strlen("\033[1mab\033[0mcd"));

		CHECK(n == 4);
		CHECK(out[0] == 'a' && out[1] == 'b' && out[2] == 'c' && out[3] == 'd');
		n = uml_nt_feed_strip_esc(out, sizeof(out), "x\033cy", 4);
		CHECK(n == 2 && out[0] == 'x' && out[1] == 'y');
	}

	/* S45: a kernel line between the halves of the guest prompt does not
	 * reset the guest's own line */
	{
		struct uml_nt_feed_gate h;

		uml_nt_feed_gate_reset(&h);
		uml_nt_feed_gate_scan(&h, "\numl log", 8, 0);
		uml_nt_feed_gate_scan(&h, "[commit-ahead] pid 1\n", 21, 1);
		CHECK(uml_nt_feed_gate_take(&h) == 0);
		uml_nt_feed_gate_scan(&h, "in: ", 4, 0);
		CHECK(uml_nt_feed_gate_take(&h) == 1);
	}

	/* S46: three sources, one door. The gate is fed by nt_console_write, so
	 * every writer — the tty driver, printk, the guest's write(2) — arrives
	 * with src=0 and assembles the same line. */
	{
		struct uml_nt_feed_gate k;

		uml_nt_feed_gate_reset(&k);
		uml_nt_feed_gate_scan(&k, "\numl log", 8, 0);	/* write(2) */
		uml_nt_feed_gate_scan(&k, "[commit-ahead] pid 1", 19, 1);
		CHECK(uml_nt_feed_gate_take(&k) == 0);
		uml_nt_feed_gate_scan(&k, "in: ", 4, 0);	/* the rest */
		CHECK(uml_nt_feed_gate_take(&k) == 1);
	}

	/* S47: a line whose head was cut must never match. The kernel line that
	 * armed the last run was "/bin/login: …" with its '/' truncated away. */
	{
		struct uml_nt_feed_gate q;
		char big[UML_NT_FEED_LINE_MAX + 40];

		uml_nt_feed_gate_reset(&q);
		memset(big, 'x', sizeof(big) - 20);
		big[sizeof(big) - 20] = 0;
		strcat(big, "/bin/login: ");
		uml_nt_feed_gate_scan(&q, big, (unsigned)strlen(big), 1);
		CHECK(uml_nt_feed_gate_take(&q) == 0);	/* headless, no match */
	}

	/* S48: the writer declares itself. A log write between the two halves of
	 * the guest's prompt must not join the guest's line — the source flag is
	 * what separates them, not the text. */
	{
		struct uml_nt_feed_gate m;

		uml_nt_feed_gate_reset(&m);
		uml_nt_feed_gate_scan(&m, "\numl log", 8, 0);		/* guest */
		uml_nt_feed_gate_scan(&m, "binfmt_umlnt: load_binary\n", 27, 1);
		CHECK(uml_nt_feed_gate_take(&m) == 0);
		uml_nt_feed_gate_scan(&m, "in: ", 4, 0);		/* guest */
		CHECK(uml_nt_feed_gate_take(&m) == 1);
	}

	if (fails) { printf("feedgate: %d failure(s)\n", fails); return 1; }
	printf("feedgate: one line per prompt, in order, never for a log line\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
grep -q "uml_nt_feed_gate_take(&uml_nt_console_gate)" "$C" || {
	echo "FAIL: the console flush does not wait for a prompt"; exit 1; }
echo "feedgate: the console flush waits for it"
