#!/usr/bin/env bash
# S36: the margin can be committed INSIDE an existing stack VMA.
#
# A fork child inherits the parent's stack VMA, and that VMA can cover the whole
# reservation below the stack pointer. The add-only reserve refuses to touch it —
# correctly — so the margin never landed and the dip pages stayed free (referee
# 42055980664: mapped=0, alloc=0 across the window).
#
# The second path has a narrower contract, and only because the range it maps is
# already owned by the VMA that covers it: no VMA is added, no bound moves, no
# allocation happens, and a MAP op is all the stub needs. This test pins exactly
# that: nvma unchanged, the plan maps the dip window, and a range the VMA does
# NOT own is refused rather than mapped.
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
#include <stackgrow_model.h>
#include <fault.h>
#include <vma.h>
#include <physalloc.h>
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
#define RUN UML_NT_PHYS_RUN_SIZE
#define TOP 0x60870000ull
#define BOT (TOP - RUN)
#define RES_LO (TOP - 0x800000ull)
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
	unsigned long long dip_lo = 0x6082d000ull, dip_hi = 0x6085e000ull;
	unsigned long long lo = ~0ull, hi = 0;
	int nv0, added, i, saw_target = 0;

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = RES_LO;
	/* ONE VMA covering the whole reservation, as a fork child inherits it */
	(void)uml_nt_vma_add(&mm, RES_LO, TOP,
			     (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READWRITE, 0);
	nv0 = mm.nvma;
	memset(&plan, 0, sizeof(plan));

	added = uml_nt_ca_margin_inside(&mm, &ph, &plan, TOP, RES_LO,
					UML_NT_CA_MARGIN_RUNS);
	CHECK(added > 0);
	/* (a) the table does not change shape */
	CHECK(mm.nvma == nv0);
	/* (b) the plan maps the dip window */
	for (i = 0; i < plan.n_ops; i++) {
		if (plan.ops[i].op != UML_NT_FOP_MAP) continue;
		if (plan.ops[i].va < lo) lo = plan.ops[i].va;
		if (plan.ops[i].va + plan.ops[i].len > hi)
			hi = plan.ops[i].va + plan.ops[i].len;
		if (plan.ops[i].va <= dip_lo && plan.ops[i].va + plan.ops[i].len > dip_lo)
			saw_target = 1;
	}
	CHECK(lo <= dip_lo);
	CHECK(hi >= dip_hi);
	CHECK(saw_target == 1);

	/* a range the VMA does not own is refused, not mapped */
	{
		struct uml_nt_mm lone;
		struct uml_nt_fault_plan p2;
		int n;

		uml_nt_mm_init(&lone);
		lone.stack_top = TOP;
		lone.stack_limit = RES_LO;
		memset(&p2, 0, sizeof(p2));
		n = uml_nt_ca_margin_inside(&lone, &ph, &p2, TOP, RES_LO,
					    UML_NT_CA_MARGIN_RUNS);
		CHECK(n == 0);		/* no VMA covers it: nothing to map */
		CHECK(p2.n_ops == 0);
	}
	if (fails) { printf("ca_margin_inside: %d failure(s)\n", fails); return 1; }
	printf("ca_margin_inside: %d run(s) mapped inside the VMA, nvma untouched\n",
	       added);
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
echo "ca_margin_inside: add-only stays separate"
