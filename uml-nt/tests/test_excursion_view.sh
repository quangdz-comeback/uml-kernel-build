#!/usr/bin/env bash
# S20: what the stub's own view says about the excursion window.
#
# The PAM frame dips ~256 KiB below the committed stack run. Whether that dip
# can fault at all depends on the pages being committed in the STUB's view —
# the kernel cannot query them at postmortem, so the stub samples them and the
# death record prints the answer. This drives the REAL sampler with a fake VQ.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUB="${1:-$HERE/../stub/stub.c}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
python3 - "$STUB" "$TMP/t.c" <<'PYEXTRACT'
import re, sys
src=open(sys.argv[1]).read(); out=sys.argv[2]
m=re.search(r"static void sample_excursion_view_with\(struct uml_nt_stub_data \*sd,\n.*?\n\}\n", src, re.S)
assert m, "sample_excursion_view_with missing"
fn=m.group(0)
prog = r'''
#include <stdio.h>
#include <string.h>
#define UML_NT_EXC_PAGES 8
#define MEM_COMMIT 0x1000ull
#define MEM_FREE   0x10000ull
#define MEM_RESERVE 0x2000ull
typedef int (*exc_query_fn)(void *ctx, unsigned long long va,
			    unsigned long long *state, unsigned long long *prot);
struct uml_nt_stub_data {
	unsigned long long exc_va0;
	unsigned int exc_state[UML_NT_EXC_PAGES];
	unsigned int exc_prot[UML_NT_EXC_PAGES];
	unsigned int exc_committed;
	unsigned int exc_sampled;
};
''' + fn + r'''
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

/* a fake view: the top N pages committed, the rest free */
static int committed_pages;
static unsigned long long top_va = 0x6082d000ull;
static int fail_all;
static int q(void *ctx, unsigned long long va, unsigned long long *st, unsigned long long *pr)
{
	unsigned long long idx;
	(void)ctx;
	if (fail_all) return -1;
	if (va > top_va) return -1;
	idx = (top_va - va) / 0x1000ull;
	if (idx < (unsigned long long)committed_pages) { *st = MEM_COMMIT; *pr = 0x04; }
	else { *st = MEM_FREE; *pr = 0x01; }
	return 0;
}
int main(void)
{
	struct uml_nt_stub_data s;

	/* all eight committed: a store there could NOT fault */
	committed_pages = 8;
	memset(&s, 0, sizeof(s));
	sample_excursion_view_with(&s, top_va, q, 0);
	CHECK(s.exc_sampled == 8);
	CHECK(s.exc_committed == 8);
	CHECK(s.exc_state[0] == MEM_COMMIT && s.exc_state[7] == MEM_COMMIT);

	/* the realistic case: only the top run is committed, the dip is free */
	committed_pages = 1;
	memset(&s, 0, sizeof(s));
	sample_excursion_view_with(&s, top_va, q, 0);
	CHECK(s.exc_committed == 1);
	CHECK(s.exc_state[0] == MEM_COMMIT);
	CHECK(s.exc_state[1] == MEM_FREE);
	CHECK(s.exc_state[7] == MEM_FREE);

	/* a query that fails is counted as sampled-less, never as committed */
	fail_all = 1;				/* the OS refuses the query */
	memset(&s, 0, sizeof(s));
	sample_excursion_view_with(&s, top_va, q, 0);
	CHECK(s.exc_sampled == 0);
	CHECK(s.exc_committed == 0);
	fail_all = 0;
	if (fails) { printf("excursion_view: %d failure(s)\n", fails); return 1; }
	printf("excursion_view: per-page state counted, failures not counted as commit\n");
	return 0;
}
'''
open(out,'w').write(prog)
PYEXTRACT
"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
