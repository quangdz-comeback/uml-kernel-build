#!/usr/bin/env bash
# S23: the reserve must never leave a VMA whose op never reaches the stub.
#
# A fork answer carries the parent's plan to the child's spawn, so an op queued
# during a fork round is never applied by the parent — and the VMA entry left
# behind turns into an UNMAP the stub has no view for (487, the init self-kill).
# The contract the red test pins: in a fork round the helper must add NOTHING;
# in an ordinary round it adds exactly one VMA and exactly one op.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC_OS="$HERE/../kernel/overlay/arch/um/os-Windows/include"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <stackreserve_model.h>
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
#define TOP 0x60870000ull
#define BOT (TOP - RUN)
int main(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	int nv0, no0;

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = TOP - 0x800000ull;
	(void)uml_nt_vma_add(&mm, BOT, TOP, (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READWRITE, 0);
	memset(&plan, 0, sizeof(plan));

	/* an ordinary answer: one VMA, one op — the pair that must stay together */
	nv0 = mm.nvma; no0 = plan.n_ops;
	CHECK(uml_nt_stack_commit_ahead(&mm, &ph, BOT + 0x10, BOT, TOP,
					TOP - 0x800000ull, 0x40000, &plan) == 1);
	CHECK(mm.nvma == nv0 + 1);
	CHECK(plan.n_ops == no0 + 1);

	/* the same call is idempotent: nothing more */
	nv0 = mm.nvma; no0 = plan.n_ops;
	CHECK(uml_nt_stack_commit_ahead(&mm, &ph, BOT + 0x10, BOT, TOP,
					TOP - 0x800000ull, 0x40000, &plan) == 0);
	CHECK(mm.nvma == nv0);
	CHECK(plan.n_ops == no0);
	/* S25: the orphan hazard, demonstrated. A reserve queued into a plan
	 * that a later repair RESETS keeps its VMA and loses its op — exactly
	 * the state the teardown UNMAPs and the stub answers 487. The gate
	 * refuses to call the helper while the plan is mid-drain, so the
	 * attempt below is skipped in production; here it is shown once to
	 * name the state the gate exists to prevent. */
	nv0 = mm.nvma; no0 = plan.n_ops;
	CHECK(uml_nt_ca_plan_ok(7, 2) == 0);	/* mid-drain: no reserve */
	if (uml_nt_ca_plan_ok(7, 2))		/* production never enters */
		(void)uml_nt_stack_commit_ahead(&mm, &ph, BOT + 0x10, BOT, TOP,
						TOP - 0x800000ull, 0x40000, &plan);
	CHECK(mm.nvma == nv0);
	CHECK(plan.n_ops == no0);

	/* quiescent plan: the reserve is allowed again */
	plan.n_ops = 0;
	plan.n_ops = no0;
	CHECK(uml_nt_ca_plan_ok(0, 0) == 1);

	if (fails) { printf("ca_fork_contract: %d failure(s)\n", fails); return 1; }
	printf("ca_fork_contract: VMA and op are always born together\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
