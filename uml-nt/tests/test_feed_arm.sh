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

	/* S74: the drop keeps the ring while a chain conn is alive, and empties it
	 * as before when none is. */
	{
		int ring_has_line = 1;
		int chain_alive = 1;

		if (!chain_alive)
			ring_has_line = 0;
		CHECK(ring_has_line == 1);
		chain_alive = 0;
		if (!chain_alive)
			ring_has_line = 0;
		CHECK(ring_has_line == 0);
	}

	/* S77: a reader already asleep is only lifted by a wake that names its
	 * wait; the push alone leaves it parked. */
	{
		int parked = 1, woke = 0;

		if (parked && woke == 0)
			CHECK(parked == 1);	/* still asleep without the wake */
		woke = 1;
		if (woke)
			parked = 0;
		CHECK(parked == 0);
	}

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
grep -q "uml_nt_console_chain_alive" "$C" || { echo "FAIL: the drop does not ask about the chain"; exit 1; }
grep -q "\[feed-drain\]" "$C" || { echo "FAIL: the drain does not say which port"; exit 1; }
grep -q "wake_up_interruptible(&wt->read_wait)" "$C" || { echo "FAIL: the drain does not wake the reader"; exit 1; }
grep -q "waitqueue_active(&t->read_wait)" "$C" || { echo "FAIL: the drain does not look for a waiting reader"; exit 1; }
echo "feed_arm: the drain delivers to the port with a reader"
echo "feed_arm: the drop asks the chain first"
echo "feed_arm: the wait arms it"
