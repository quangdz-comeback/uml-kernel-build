#!/usr/bin/env bash
# S53: the login conn's last 200 syscalls, kept in order.
#
# The conn loads libpam and then goes quiet without dying and without printing.
# Asking "what is it doing" needs the actual syscall stream, but the whole boot
# emits tens of thousands of them — so the last two hundred are kept in a ring and
# printed in order at a few checkpoints, which is exactly the window that says
# where progress stopped.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
/* the ring exactly as the kernel keeps it */
struct rec { unsigned long long nr, a0, ret; };
static struct rec ring[200];
static unsigned ri, total;
static void push(unsigned long long nr, unsigned long long a0, unsigned long long ret)
{
	ring[ri].nr = nr; ring[ri].a0 = a0; ring[ri].ret = ret;
	ri = (ri + 1) % 200;
	total++;
}
int main(void)
{
	unsigned i, n, start, k;
	unsigned long long seen[200];

	for (i = 0; i < 450; i++)
		push(1000 + i, i, (unsigned long long)i * 2);
	CHECK(total == 450);
	n = total < 200 ? total : 200;
	start = (ri + 200 - n) % 200;
	CHECK(n == 200);
	/* the window is the LAST two hundred, oldest first */
	for (i = 0; i < n; i++) {
		k = (start + i) % 200;
		seen[i] = ring[k].nr;
	}
	CHECK(seen[0] == 1000 + 250);
	CHECK(seen[199] == 1000 + 449);
	for (i = 1; i < n; i++)
		CHECK(seen[i] == seen[i - 1] + 1);
	if (fails) { printf("scring: %d failure(s)\n", fails); return 1; }
	printf("scring: 200 slots, oldest first, the newest last\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c"
grep -q "\[scring\]" "$S" || { echo "FAIL: no scring dump"; exit 1; }
grep -q "sc_total == 16" "$S" || { echo "FAIL: the small checkpoints are gone"; exit 1; }
grep -q "\[sc-tail\]" "$S" || { echo "FAIL: no rolling tail"; exit 1; }
echo "scring: the kernel dumps it"
