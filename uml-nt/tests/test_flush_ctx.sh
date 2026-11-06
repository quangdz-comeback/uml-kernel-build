#!/usr/bin/env bash
# S82 (D19): the console flush may only run on a conn/vCPU thread — and the log
# must say which door and which thread every flush came from.
#
# Report 381 §3: the kernel faulted right after the console chain first reached
# execv(/bin/login), and the crash line said "thread=timer" — but that field was
# a single GLOBAL the timer thread had written at startup, not the identity of
# the thread that faulted. The flush is the one place in this port that runs
# kernel tty code (flip buffers, the line discipline, wake-ups) from a callback
# (unblock_signals) that can fire anywhere on a conn thread, and S81's pending()
# widening ("ring OR gate armed") made it fire in windows it never used before.
# So: identity per thread, a door tag per flush, and a refusal when the thread is
# not a conn.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <threadrole.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
int main(void)
{
	struct uml_nt_thread_slot t[UML_NT_THREAD_SLOTS];

	memset(t, 0, sizeof(t));

	/* unclaimed is a conn thread: the vCPU threads never claim */
	CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 77), "conn") == 0);
	CHECK(uml_nt_thread_is_conn_role("conn") == 1);

	/* aux threads claim their own id; ids are independent */
	CHECK(strcmp(uml_nt_thread_claim(t, UML_NT_THREAD_SLOTS, 11, "timer"), "timer") == 0);
	CHECK(strcmp(uml_nt_thread_claim(t, UML_NT_THREAD_SLOTS, 12, "net-reader"), "net-reader") == 0);
	CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 11), "timer") == 0);
	CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 12), "net-reader") == 0);
	CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 13), "conn") == 0);
	CHECK(uml_nt_thread_is_conn_role("timer") == 0);
	CHECK(uml_nt_thread_is_conn_role("net-reader") == 0);

	/* re-claim replaces, and a full table never steals another slot */
	CHECK(strcmp(uml_nt_thread_claim(t, UML_NT_THREAD_SLOTS, 11, "other"), "other") == 0);
	CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 11), "other") == 0);
	{
		int i;

		for (i = 13; i < 13 + UML_NT_THREAD_SLOTS; i++)
			uml_nt_thread_claim(t, UML_NT_THREAD_SLOTS, (unsigned long long)i, "other");
		uml_nt_thread_claim(t, UML_NT_THREAD_SLOTS, 999, "late");
		CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 999), "conn") == 0);
		CHECK(strcmp(uml_nt_thread_role_at(t, UML_NT_THREAD_SLOTS, 11), "other") == 0);
	}

	/* the DOOR RULE: a timer tick with the gate armed flushes NOTHING */
	CHECK(uml_nt_flush_door_ok("timer") == 0);
	CHECK(uml_nt_flush_door_ok("net-reader") == 0);
	CHECK(uml_nt_flush_door_ok("conn") == 1);

	if (fails) { printf("flush_ctx: %d failure(s)\n", fails); return 1; }
	printf("flush_ctx: only a conn thread may flush, and it says which door\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"

C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"
SIG="$HERE/../kernel/overlay/arch/um/os-Windows/signal.c"
PROC="$HERE/../kernel/overlay/arch/um/os-Windows/skas/process.c"
ST="$HERE/../kernel/overlay/arch/um/os-Windows/start_up.c"
grep -q "uml_nt_flush_door_ok" "$C" \
	|| { echo "FAIL: the flush does not ask who is calling"; exit 1; }
grep -q '\[flush-ctx\] door=%d who=%s tid=%lu' "$C" \
	|| { echo "FAIL: the flush does not name its door and thread"; exit 1; }
grep -q 'REFUSED' "$C" \
	|| { echo "FAIL: a wrong-thread flush is not refused loudly"; exit 1; }
grep -q "uml_nt_console_flush(0" "$SIG" \
	|| { echo "FAIL: the unblock_signals door is not tagged"; exit 1; }
grep -q "uml_nt_console_flush(1" "$PROC" \
	|| { echo "FAIL: the pump wake door is not tagged"; exit 1; }
grep -q "uml_nt_thread_role_claim" "$ST" \
	|| { echo "FAIL: the role is still a global, not a per-thread claim"; exit 1; }
grep -q "uml_nt_thread_role_claim" "$HERE/../kernel/overlay/arch/um/os-Windows/time.c" \
	|| { echo "FAIL: the timer thread does not claim its role"; exit 1; }
echo "flush_ctx: the timer thread can no longer reach the tty feed"
echo "flush_ctx: every flush names its door and its thread"
