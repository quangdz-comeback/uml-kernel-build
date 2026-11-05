#!/usr/bin/env bash
# S35: a chain child is born with the margin, because it never has an INIT.
#
# Referee 42053211120: the conn that died at the PAM dip was a FORK CHILD — it
# never received an INIT answer of its own, so the birth margin of S34 never ran
# for it, and its eight dip pages were still free. A fork child is born running;
# the only place to commit its margin is the mm the clone copies.
#
# The contract, in two halves: a chain child's seed leaves margin runs in the mm
# (and its plan maps them), and a non-chain child is left alone so the budget
# stays where the report put it.
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
/* the seed's margin loop, as the kernel runs it */
static int margin(struct uml_nt_mm *mm, struct uml_nt_phys *ph)
{
	struct uml_nt_fault_plan *p = 0;
	unsigned long long bot = mm->stack_top - UML_NT_SG_RUN;
	int r, added = 0;
	static char scratch[sizeof(struct uml_nt_fault_plan)];

	p = (struct uml_nt_fault_plan *)scratch;
	memset(p, 0, sizeof(*p));
	for (r = 0; r < UML_NT_CA_MARGIN_RUNS; r++, bot -= UML_NT_SG_RUN) {
		if (uml_nt_stack_commit_ahead(mm, ph, bot, bot, mm->stack_top,
					      mm->stack_limit, UML_NT_SG_RUN,
					      p) <= 0)
			break;
		added++;
	}
	return added;
}
static void one_mm(struct uml_nt_mm *mm, struct uml_nt_phys *ph)
{
	uml_nt_mm_init(mm);
	mm->stack_top = TOP;
	mm->stack_limit = TOP - 0x800000ull;
	(void)uml_nt_vma_add(mm, BOT, TOP, (unsigned long long)uml_nt_phys_alloc(ph),
			     UML_NT_PAGE_READWRITE, 0);
}
int main(void)
{
	struct uml_nt_mm mm, twin;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan init;
	int added, i, mapped = 0;
	unsigned long long dip_lo = 0x6082d000ull, dip_hi = 0x6085e000ull;
	unsigned long long lo = ~0ull, hi = 0;

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;

	/* a chain child: the margin lands in the mm the clone will copy */
	one_mm(&mm, &ph);
	added = margin(&mm, &ph);
	CHECK(added == UML_NT_CA_MARGIN_RUNS);
	CHECK(uml_nt_mm_init_plan(&mm, &ph, &init) == 0);
	for (i = 0; i < init.n_ops; i++) {
		if (init.ops[i].op != UML_NT_FOP_MAP) continue;
		if (init.ops[i].va < lo) lo = init.ops[i].va;
		if (init.ops[i].va + init.ops[i].len > hi)
			hi = init.ops[i].va + init.ops[i].len;
	}
	CHECK(lo <= dip_lo);
	CHECK(hi >= dip_hi);
	for (i = 0; i < init.n_ops; i++)
		if (init.ops[i].op == UML_NT_FOP_MAP &&
		    init.ops[i].va == BOT - UML_NT_SG_RUN)
			mapped = 1;
	CHECK(mapped == 1);

	/* a non-chain child: no margin, and none in its plan either */
	one_mm(&twin, &ph);
	CHECK(uml_nt_mm_init_plan(&twin, &ph, &init) == 0);
	for (i = 0; i < init.n_ops; i++)
		if (init.ops[i].op == UML_NT_FOP_MAP &&
		    init.ops[i].va == BOT - UML_NT_SG_RUN)
			mapped = 2;
	CHECK(mapped == 1);	/* still only the chain one */

	if (fails) { printf("ca_margin_seed: %d failure(s)\n", fails); return 1; }
	printf("ca_margin_seed: the chain child is born with 0x%llx of margin\n",
	       (unsigned long long)UML_NT_CA_MARGIN_RUNS * UML_NT_SG_RUN);
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
S="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"
grep -q "fork seed (chain child" "$S" || {
	echo "FAIL: the fork seed does not commit the margin"; exit 1; }
grep -q "ca-margin-skip" "$S" || { echo "FAIL: INIT has no skip record"; exit 1; }
echo "ca_margin_seed: the seed commits it, INIT says when it does not"
