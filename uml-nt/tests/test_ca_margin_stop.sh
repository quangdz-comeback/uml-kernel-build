#!/usr/bin/env bash
# S38: every way the margin claim stops names itself.
#
# "2 runs" was measured twice and explained twice by guesswork. The claim loop has
# four exits and all four were silent: the bottom fell below the limit, no VMA of
# this conn covered the page, the run could not be claimed in place, or the plan
# refused the op. Each now returns its own code, and this test drives all four.
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
#define RES_LO (TOP - 0x800000ull)
static unsigned char taken[512];
long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{
	int i, j;
	for (i = 0; i + nruns <= 512; i++) {
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
	for (j = 0; j < nruns; j++) if (i + j >= 0 && i + j < 512) taken[i + j] = 0;
}
int main(void)
{
	struct uml_nt_phys ph;
	struct uml_nt_mm mm;
	struct uml_nt_fault_plan plan;
	int why, n;

	if (uml_nt_phys_init(&ph, 256 * RUN) < 0) return 2;

	/* 1. limit: the bottom is already at the floor */
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = TOP;			/* nothing below is admissible */
	memset(&plan, 0, sizeof(plan));
	why = -1;
	n = uml_nt_ca_margin_inside(&mm, &ph, &plan, TOP, TOP, 1, &why);
	CHECK(n == 0);
	CHECK(why == UML_NT_CAM_LIMIT);

	/* 2. no-vma: the page belongs to no VMA of this conn */
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = RES_LO;
	why = -1;
	n = uml_nt_ca_margin_inside(&mm, &ph, &plan, TOP, RES_LO, 1, &why);
	CHECK(n == 0);
	CHECK(why == UML_NT_CAM_NOVMA);

	/* 3. claim: the VMA covers the page but its run is out of table */
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = RES_LO;
	/* a run_off past the end of the phys table: the claim cannot place it */
	(void)uml_nt_vma_add(&mm, RES_LO, TOP, 256ull * RUN,
			     UML_NT_PAGE_READWRITE, 0);
	why = -1;
	n = uml_nt_ca_margin_inside(&mm, &ph, &plan, TOP, RES_LO, 1, &why);
	CHECK(n == 0);
	CHECK(why == UML_NT_CAM_CLAIM);

	/* 4. plan: a plan with no room left */
	{
		struct uml_nt_mm m4;
		struct uml_nt_fault_plan full;
		int i;

		uml_nt_mm_init(&m4);
		m4.stack_top = TOP;
		m4.stack_limit = RES_LO;
		(void)uml_nt_vma_add(&m4, RES_LO, TOP,
				     (unsigned long long)uml_nt_phys_alloc(&ph),
				     UML_NT_PAGE_READWRITE, 0);
		memset(&full, 0, sizeof(full));
		for (i = 0; i < UML_NT_FAULT_MAX_OPS; i++)
			full.ops[i].op = UML_NT_FOP_PROTECT;
		full.n_ops = UML_NT_FAULT_MAX_OPS;
		why = -1;
		n = uml_nt_ca_margin_inside(&m4, &ph, &full, TOP, RES_LO, 1, &why);
		CHECK(n == 0);
		CHECK(why == UML_NT_CAM_PLAN);
	}

	if (fails) { printf("ca_margin_stop: %d failure(s)\n", fails); return 1; }
	printf("ca_margin_stop: limit, no-vma, claim and plan each say their name\n");
	return 0;
}
EOF
chmod +x /home/exedev/uml-nt/uml-nt/tests/test_ca_margin_stop.sh
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
