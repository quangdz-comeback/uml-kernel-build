#!/usr/bin/env bash
# S26: a fork child must see the parent's address space, reserve VMA included.
#
# Linux semantics: the child inherits every mapping, and the PAM dip of a forked
# child lands in the very pages the parent's reserve committed. So the child's
# INIT plan has to carry a MAP op for a reserve VMA — if it does not, the child
# has a VMA with no view and its teardown UNMAPs an address the stub never
# mapped (487). This harness pins the emission, not a filter that might skip it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC_OS="$HERE/../kernel/overlay/arch/um/os-Windows/include"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
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
	int i, saw_text = 0, saw_reserve = 0;

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;
	uml_nt_mm_init(&mm);
	mm.stack_top = 0x60870000ull;
	mm.stack_limit = 0x60070000ull;
	(void)uml_nt_vma_add(&mm, 0x60010000ull, 0x60020000ull,
			     (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READONLY, 0);
	/* the reserve VMA: a run-backed VMA nobody has a view for yet */
	(void)uml_nt_vma_add(&mm, 0x60850000ull, 0x60860000ull,
			     (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READWRITE, 0);

	CHECK(uml_nt_mm_init_plan(&mm, &ph, &plan) == 0);
	for (i = 0; i < plan.n_ops; i++) {
		if (plan.ops[i].op != UML_NT_FOP_MAP) continue;
		if (plan.ops[i].va == 0x60010000ull) saw_text = 1;
		if (plan.ops[i].va == 0x60850000ull) saw_reserve = 1;
	}
	/* every VMA of the child's mm gets a MAP — the reserve is not filtered */
	CHECK(saw_text == 1);
	CHECK(saw_reserve == 1);
	if (fails) { printf("seed_init_plan: %d failure(s)\n", fails); return 1; }
	printf("seed_init_plan: the child's INIT maps every VMA incl. the reserve\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
