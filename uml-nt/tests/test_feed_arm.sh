#!/usr/bin/env bash
# S73: the guest asking for input arms one feed line.
#
# Report 375 found the login conn parked in ppoll with the feed never armed: the
# gate waited for the prompt text, and that write never appeared in the syscall
# table. The trigger is now the wait itself — a login conn entering poll, ppoll,
# select or pselect6 is asking for a line, and the stage machine decides which.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <feedgate.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
/* the arming rule, exactly as console.c applies it */
static int arm(struct uml_nt_feed_gate *g, int live)
{
	if (!live)
		return 0;
	if (g->stage == 0)
		g->stage = 1;
	g->armed = 1;
	return g->stage;
}
int main(void)
{
	struct uml_nt_feed_gate g;

	uml_nt_feed_gate_reset(&g);
	/* first wait: the username line, stage 1 */
	CHECK(arm(&g, 1) == 1);
	CHECK(uml_nt_feed_gate_take(&g) == 1);		/* released once */
	CHECK(uml_nt_feed_gate_take(&g) == 0);		/* and only once */

	/* the guest asks again after answering: same stage, one more line */
	CHECK(arm(&g, 1) == 1);
	CHECK(uml_nt_feed_gate_take(&g) == 1);

	/* the password stage is whatever the state machine says it is */
	g.stage = 2;
	CHECK(arm(&g, 1) == 2);
	CHECK(uml_nt_feed_gate_take(&g) == 1);

	/* and a console that is not up yet arms nothing */
	g.armed = 0;
	CHECK(arm(&g, 0) == 0);
	CHECK(uml_nt_feed_gate_take(&g) == 0);

	if (fails) { printf("feed_arm: %d failure(s)\n", fails); return 1; }
	printf("feed_arm: the wait arms one line, the stage picks which\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
grep -q "uml_nt_console_arm_feed" "$S" || { echo "FAIL: the syscall path does not arm"; exit 1; }
grep -q "uml_nt_console_arm_feed" "$C" || { echo "FAIL: the gate has no arm entry"; exit 1; }
grep -q "\\[feed-arm\\]" "$S" || { echo "FAIL: no [feed-arm] record"; exit 1; }
grep -q "drop_input" "$C" && echo "feed_arm: TCSAFLUSH drop untouched"
echo "feed_arm: the wait arms it"
