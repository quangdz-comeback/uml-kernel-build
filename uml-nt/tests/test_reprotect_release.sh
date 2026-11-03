#!/usr/bin/env bash
# S31: the fork's COW re-protect must release only views that exist.
#
# For every writable shared VMA the fork queues UNMAP+MAP: drop the writable
# view, put a read-only one back. For a VMA whose view the stub never received —
# a reserve still owed its MAP — that UNMAP names an address the stub has no
# view for: 487, a KILL action, and init dead (referee 41702725234: the unmap of
# 0x60850000 was issued with n_ops=121 and no MAP for that address ever was).
# With no view there is nothing to release, and the MAP alone materializes it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <stackreserve_model.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
int main(void)
{
	/* a view is in the ledger: the standard COW pair (UNMAP then MAP) */
	CHECK(uml_nt_reprotect_release_first(1) == 1);
	/* no view: release nothing, the MAP alone materializes it */
	CHECK(uml_nt_reprotect_release_first(0) == 0);
	if (fails) { printf("reprotect_release: %d failure(s)\n", fails); return 1; }
	printf("reprotect_release: only an existing view is released\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
# and the call site must actually use the predicate for the unmapped-reserve case
grep -q "uml_nt_reprotect_release_first" "$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c" || {
	echo "reprotect_release: the seed's call site does not consult the predicate"; exit 1; }
echo "reprotect_release: call site consults the predicate"
