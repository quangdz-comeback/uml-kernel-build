#!/usr/bin/env bash
# S33: a reserve queued into a DRAINING plan is carried to the stub.
#
# The reserve used to refuse a mid-drain plan (referee 41707512704: the conn that
# died at the PAM dip was skipped twice with reason=plan, left=4..3 next=1, and
# never reserved at all). That refusal was written when a repair RESET the plan
# and dropped the unissued tail; the repair now appends (S27), so a reserve can
# join the stream instead of waiting for a quiescent plan that a fast-dying conn
# never has.
#
# The invariant: after the helper adds its run to a plan at position `next`, the
# recount must cover every unissued op — including the one just added — or the
# stub never hears of the MAP and the VMA is an orphan again.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC_OS="$HERE/../kernel/overlay/arch/um/os-Windows/include"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <fault.h>
#include <vma.h>
#include <physalloc.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
#define RUN UML_NT_PHYS_RUN_SIZE
static unsigned char taken[64];
long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	int i, j;
	for (i = 0; i + nruns <= 64; i++) {
		int ok = 1;
		for (j = 0; j < nruns; j++) if (taken[i + j]) { ok = 0; break; }
		if (!ok) continue;
		for (j = 0; j < nruns; j++) taken[i + j] = 1;
		*page_out = &taken[i];
		return (1u << 20) + (long long)i * RUN;
	}
	return -1;
}
void uml_nt_phys_backend_free(void *page, int nruns)
{
	int i = (int)((char *)page - (char *)taken), j;
	for (j = 0; j < nruns; j++) if (i + j >= 0 && i + j < 64) taken[i + j] = 0;
}
int main(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	int i, n0, left, saw = 0;
	unsigned long long target = 0x60850000ull;

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;
	uml_nt_mm_init(&mm);
	mm.stack_top = 0x60870000ull;
	mm.stack_limit = 0x60070000ull;
	(void)uml_nt_vma_add(&mm, 0x60860000ull, 0x60870000ull,
			     (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READWRITE, 0);

	/* a plan four ops long, one already applied: the drain is in flight */
	memset(&plan, 0, sizeof(plan));
	for (i = 0; i < 4; i++) {
		plan.ops[i].op = UML_NT_FOP_MAP;
		plan.ops[i].va = 0x60010000ull + (unsigned long long)i * 0x10000ull;
		plan.ops[i].len = 0x10000;
		plan.ops[i].prot = 0x04;
		plan.ops[i].off = 0x100000;
	}
	plan.n_ops = 4;
	n0 = plan.n_ops;

	/* the reserve joins the stream */
	CHECK(uml_nt_stack_commit_ahead(&mm, &ph, 0x6086f038ull,
					0x60860000ull, 0x60870000ull,
					0x60070000ull, 0x40000ull, &plan) == 1);
	CHECK(plan.n_ops == n0 + 1);
	for (i = 0; i < plan.n_ops; i++)
		if (plan.ops[i].op == UML_NT_FOP_MAP && plan.ops[i].va == target)
			saw = 1;
	CHECK(saw == 1);

	/* and the recount covers it: every op from the drain cursor onwards */
	left = uml_nt_fault_plan_left_at_trap(&plan, 1);
	CHECK(left == plan.n_ops - 1);
	if (fails) { printf("ca_append: %d failure(s)\n", fails); return 1; }
	printf("ca_append: a mid-drain reserve joins the stream\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
# and the call site must no longer defer on 'plan mid-drain'
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
grep -q "reason=plan" "$S" && { echo "FAIL: the mid-drain deferral still exists"; exit 1; }
grep -q "uml_nt_fault_plan_left_at_trap(&c->plan" "$S" || {
	echo "FAIL: the answer path never recounts the remainder"; exit 1; }
echo "ca_append: the deferral is retired and the remainder is recounted"
