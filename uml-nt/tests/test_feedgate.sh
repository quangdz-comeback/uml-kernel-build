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
	uml_nt_feed_gate_scan(g, s, (unsigned)strlen(s));
}
int main(void)
{
	struct uml_nt_feed_gate g;

	/* nothing on the console yet: nothing may be released */
	uml_nt_feed_gate_reset(&g);
	scan(&g, "systemd boots\nReached target Multi-User\n");
	CHECK(uml_nt_feed_gate_take(&g) == 0);

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
	CHECK(g.lines == 5);	/* 2 from the split cases above, then 3 prompts */

	/* a second login prompt re-arms, and order is preserved */
	scan(&g, "\r\numl login: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	scan(&g, "Password: ");
	CHECK(uml_nt_feed_gate_take(&g) == 1);
	CHECK(g.lines == 7);

	if (fails) { printf("feedgate: %d failure(s)\n", fails); return 1; }
	printf("feedgate: one line per prompt, in order, never for a log line\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
grep -q "uml_nt_feed_gate_take(&g_feed_gate)" "$C" || {
	echo "FAIL: the console flush does not wait for a prompt"; exit 1; }
echo "feedgate: the console flush waits for it"
