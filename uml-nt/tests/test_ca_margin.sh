#!/usr/bin/env bash
# S34: the margin is committed at conn birth, and the INIT plan carries it.
#
# Ever answer-time reserve needs an answer that carries registers. The conn that
# dies at the PAM dip dies on its FIRST syscall (referee 42047725849: one INIT
# answer, one PROT answer, no trap round at all), so the reserve never ran. The
# margin is therefore committed when the conn is born, from the VMA table alone,
# and the INIT plan maps it — before the guest executes anything.
#
# PAM needs ~0x51000 below the top (dip 0x40028 plus the wrapper frame); the
# margin is six runs = 0x60000, and this test pins that the INIT plan really
# covers the dip region with MAPs.
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
int main(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan scratch, init;
	unsigned long long dip_lo = 0x6082d000ull, dip_hi = 0x6085e000ull;
	unsigned long long lo = ~0ull, hi = 0;
	int r, i, n = 0;

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;
	uml_nt_mm_init(&mm);
	mm.stack_top = TOP;
	mm.stack_limit = TOP - 0x800000ull;
	(void)uml_nt_vma_add(&mm, BOT, TOP, (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READWRITE, 0);

	/* the birth margin: N runs below the stack bottom, table only */
	memset(&scratch, 0, sizeof(scratch));
	for (r = 0; r < UML_NT_CA_MARGIN_RUNS; r++) {
		unsigned long long bot = BOT - (unsigned long long)r * UML_NT_SG_RUN;
		int one = uml_nt_stack_commit_ahead(&mm, &ph, bot, bot, TOP,
						    mm.stack_limit, UML_NT_SG_RUN,
						    &scratch);
		if (one <= 0) break;
		n++;
	}
	CHECK(n == UML_NT_CA_MARGIN_RUNS);
	CHECK(UML_NT_CA_MARGIN_RUNS * UML_NT_SG_RUN >= 0x51000ull);	/* the dip */

	/* the INIT plan the guest receives must map the dip region */
	CHECK(uml_nt_mm_init_plan(&mm, &ph, &init) == 0);
	for (i = 0; i < init.n_ops; i++) {
		unsigned long long a, b;
		if (init.ops[i].op != UML_NT_FOP_MAP) continue;
		a = init.ops[i].va;
		b = a + init.ops[i].len;
		if (a < lo) lo = a;
		if (b > hi) hi = b;
	}
	CHECK(lo <= dip_lo);
	CHECK(hi >= dip_hi);
	if (fails) { printf("ca_margin: %d failure(s)\n", fails); return 1; }
	printf("ca_margin: %d runs at birth, the INIT plan maps 0x%llx..0x%llx\n",
	       n, lo, hi);
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
grep -q "ca-margin" "$S" || { echo "FAIL: no [ca-margin] at the birth site"; exit 1; }
echo "ca_margin: the birth site commits the margin"
