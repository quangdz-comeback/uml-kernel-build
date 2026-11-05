#!/usr/bin/env bash
# S39: the margin fills only the gap the conn does not already cover.
#
# A fork child is born on one run of coverage — [0x60850000,0x60870000) in the
# referee — while the PAM dip reaches 0x6082d000. What the margin must add is the
# uncovered part and nothing else: a VMA that overlapped existing coverage is
# what the add-only rule refuses, and re-mapping pages the guest already has is
# the class this hunt has spent whole reports on.
#
# This test pins the shape: gap [0x60820000,0x60850000), three runs, one new VMA,
# nothing on a second pass, and no VMA at all when the range is already covered.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC_OS="$HERE/../kernel/overlay/arch/um/os-Windows/include"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
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
	unsigned long long glo = 0, ghi = 0;
	int n, nv0;

	if (uml_nt_phys_init(&ph, 256 * RUN) < 0) return 2;

	/* the conn's own coverage: two runs at the top of the reservation */
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = RES_LO;
	(void)uml_nt_vma_add(&mm, TOP - 2 * RUN, TOP,
			     (unsigned long long)uml_nt_phys_alloc_span(&ph, 2),
			     UML_NT_PAGE_READWRITE, 0);
	nv0 = mm.nvma;

	n = uml_nt_ca_margin_gap(&mm, &ph, UML_NT_CA_MARGIN_RUNS, &glo, &ghi);
	/* floor = top - 6 runs (0x60810000, below the dip at 0x6082d000); the
	 * conn already covers two runs, so the gap is the four below them */
	CHECK(n == 4);
	CHECK(glo == TOP - 6 * RUN);
	CHECK(ghi == TOP - 2 * RUN);		/* stops at existing coverage */
	CHECK(mm.nvma == nv0 + 1);

	/* idempotent: the gap is covered now */
	n = uml_nt_ca_margin_gap(&mm, &ph, UML_NT_CA_MARGIN_RUNS, &glo, &ghi);
	CHECK(n == 0);
	CHECK(mm.nvma == nv0 + 1);

	/* no gap at all: coverage already reaches the floor */
	{
		struct uml_nt_mm m2;
		int r;

		uml_nt_mm_init(&m2);
		m2.stack_top = TOP;
		m2.stack_limit = RES_LO;
		(void)uml_nt_vma_add(&m2, TOP - 8 * RUN, TOP,
				     (unsigned long long)uml_nt_phys_alloc_span(&ph, 8),
				     UML_NT_PAGE_READWRITE, 0);
		r = uml_nt_ca_margin_gap(&m2, &ph, UML_NT_CA_MARGIN_RUNS, 0, 0);
		CHECK(r == 0);
		CHECK(m2.nvma == 1);
	}

	if (fails) { printf("ca_margin_gap: %d failure(s)\n", fails); return 1; }
	printf("ca_margin_gap: 4 runs of gap, one VMA, idempotent\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
