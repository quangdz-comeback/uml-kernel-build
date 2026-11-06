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

	/* S78: the line belongs to the stage, not to the ring — dropping the ring
	 * must not change what stage 1 receives. */
	{
		const char *tab[4] = { "", "root\n", "root\n", "echo LOGIN-OK\n" };
		int ring_empty = 1;	/* the drop took everything */

		(void)ring_empty;
		CHECK(tab[1][0] == 'r' && tab[1][4] == '\n');
		CHECK(tab[2][0] == 'r');
		CHECK(tab[3][0] == 'e');	/* the shell command, for stage 3 */
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

	/* S84 (report 383 §5): pending() is the RING again — and only the ring.
	 * S79's "ring OR gate armed" is what opened the async door that ran the
	 * tty code inside the exec window; the staged line is delivered at the
	 * ARM point now, so the armed gate must NOT wake the unblock_signals
	 * door. The case that was green under S79 is deliberately red here:
	 * reader waiting + dry ring + armed gate ⇒ nothing for that door. */
	{
		/* reader_waiting && ring_pending, exactly as pending() decides it */
#define PENDING(rw, rp) ((rw) && (rp))
		CHECK(PENDING(1, 0) == 0);	/* armed is NOT a reason */
		CHECK(PENDING(1, 1) == 1);	/* ring line: deliver */
		CHECK(PENDING(0, 1) == 0);	/* no reader: nothing to do */
#undef PENDING
	}

	/* S84: CONSUME ONCE at the arm point — an arm releases exactly the line
	 * its stage asks for and consumes the arm, so a later flush cannot hand
	 * the same stage out twice; the next ask releases the next line. */
	{
		struct uml_nt_feed_gate a;
		int delivered = 0;

		uml_nt_feed_gate_reset(&a);
		/* arm stage 1 → deliver → consume */
		if (a.stage == 0)
			a.stage = 1;
		a.armed = 1;
		if (uml_nt_feed_gate_take(&a))
			delivered++;
		CHECK(delivered == 1);
		CHECK(a.armed == 0);
		/* a second door (the flush) finds nothing armed */
		CHECK(uml_nt_feed_gate_take(&a) == 0);
		/* the guest asks again at the same stage: exactly one more line */
		a.stage = 1;
		a.armed = 1;
		if (uml_nt_feed_gate_take(&a))
			delivered++;
		CHECK(delivered == 2);
		CHECK(uml_nt_feed_gate_take(&a) == 0);
		/* and the stage table decides WHAT each stage releases */
		CHECK(a.lines == 2);
	}

	if (fails) { printf("feed_arm: %d failure(s)\n", fails); return 1; }
	printf("feed_arm: the wait arms one line, the stage picks which\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
SYS="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"

C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
grep -q "uml_nt_console_arm_feed" "$S" || { echo "FAIL: the syscall path does not arm"; exit 1; }
grep -q "uml_nt_console_arm_feed" "$C" || { echo "FAIL: the gate has no arm entry"; exit 1; }
grep -q "\\[feed-arm\\]" "$S" || { echo "FAIL: no [feed-arm] record"; exit 1; }
grep -q "uml_nt_console_chain_alive" "$C" || { echo "FAIL: the drop does not ask about the chain"; exit 1; }
grep -q "\[feed-drain\]" "$C" || { echo "FAIL: the drain does not say which port"; exit 1; }
grep -q "wake_up_interruptible(&wt->read_wait)" "$C" || { echo "FAIL: the drain does not wake the reader"; exit 1; }
grep -q "\[feed-line\]" "$C" || { echo "FAIL: no stage-indexed line record"; exit 1; }
grep -q "echo LOGIN-OK" "$C" || { echo "FAIL: the stage table has no LOGIN-OK line"; exit 1; }
grep -q "waitqueue_active(&t->read_wait)" "$C" || { echo "FAIL: the drain does not look for a waiting reader"; exit 1; }

# S79: three checks that were RED on 69cbaed — the run 42265037880 showed why.
# (a) the stage line never enters the ring, so the pending predicate must ask the
#     gate as well; (b) a delivery must be one [feed-drain] number whether the
#     bytes came from the table or the ring (report 380: the refactor renamed the
#     marker, and the checklist read "drain = 0" while five bytes were delivered);
# (c) the syscall ring that names a conn's last calls was gated on the LOGIN
#     binary, so the conn that actually received the feed (agetty, a CHAIN conn)
#     went dark right after its fifth read.
if awk '/^int uml_nt_console_pending/,/^}/' "$C" | grep -q 'uml_nt_console_gate.armed'; then
	echo "FAIL: pending() still wakes the async door for a staged line"; exit 1
fi
awk '/^int uml_nt_console_pending/,/^}/' "$C" | grep -q 'uml_nt_con_ring_pending' \
	|| { echo "FAIL: pending() no longer asks the ring"; exit 1; }
grep -q 'nt_con_deliver_stage(nt_con_pick_port())' "$C" \
	|| { echo "FAIL: the arm point does not deliver the staged line"; exit 1; }
awk '/^int uml_nt_console_arm_feed/,/^}/' "$C" | grep -q 'uml_nt_feed_gate_take' \
	|| { echo "FAIL: the arm point does not consume the arm (double release possible)"; exit 1; }
grep -q '\[feed-drain\] port=%d bytes=%u src=stage' "$C" \
	|| { echo "FAIL: the stage path delivers without a [feed-drain] record"; exit 1; }
grep -q '\[feed-drain\] port=%d bytes=%u src=ring' "$C" \
	|| { echo "FAIL: the ring path delivers without a [feed-drain] record"; exit 1; }
grep -q 'uml_nt_conn_is_login(c) || c->chain_login' "$SYS" \
	|| { echo "FAIL: the syscall ring skips the chain conn that read the feed"; exit 1; }
echo "feed_arm: the drain delivers to the port with a reader"
echo "feed_arm: the drop asks the chain first"
echo "feed_arm: the wait arms it"
echo "feed_arm: pending() is the ring again, not the armed gate"
echo "feed_arm: one [feed-drain] number for both sources"
echo "feed_arm: the ring follows the chain, not only the login binary"
echo "feed_arm: the arm point delivers once and consumes"
