#!/usr/bin/env bash
# S27: a repair must never reset a stream that still has unsent ops.
#
# A plan is streamed a few ops per answer. When a fault arrives with a tail
# still queued, the old repair reset the plan — and every op in that tail lost
# its MAP while its VMA stayed registered. The run then had no view, and the
# teardown's UNMAP for it was answered 487. The contract: with the tail marked
# kept, the repair APPENDS; and every op the stream carries still maps a VMA
# that exists.
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
static void seed_plan(struct uml_nt_fault_plan *p, int n)
{
	int i;

	memset(p, 0, sizeof(*p));
	for (i = 0; i < n; i++) {
		p->ops[i].op = UML_NT_FOP_MAP;
		p->ops[i].va = 0x60850000ull + (unsigned long long)i * 0x10000ull;
		p->ops[i].len = 0x10000;
		p->ops[i].prot = 0x04;
		p->ops[i].off = 0x100000;
	}
	p->n_ops = n;
}
int main(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	int i, before[4];
	unsigned long long vbefore[4];

	if (uml_nt_phys_init(&ph, 64 * RUN) < 0) return 2;

	/* --- the tail survives a repair that arrives mid-drain --- */
	uml_nt_mm_init(&mm);
	mm.stack_top = 0x60870000ull;
	mm.stack_limit = 0x60070000ull;
	(void)uml_nt_vma_add(&mm, 0x60860000ull, 0x60870000ull,
			     (unsigned long long)uml_nt_phys_alloc(&ph),
			     UML_NT_PAGE_READWRITE, 0);
	seed_plan(&plan, 4);			/* 4 ops, 2 already sent */
	for (i = 0; i < 4; i++) { before[i] = (int)plan.ops[i].op; vbefore[i] = plan.ops[i].va; }
	plan.keep_tail = 1;			/* the caller's mid-drain mark */
	(void)uml_nt_mm_fault(&mm, &ph, 0x60860010ull, UML_NT_FAULT_WRITE, &plan);
	plan.keep_tail = 0;
	CHECK(plan.n_ops >= 5);			/* the repair APPENDED */
	for (i = 0; i < 4; i++) {		/* and touched nothing sent */
		CHECK((int)plan.ops[i].op == before[i]);
		CHECK(plan.ops[i].va == vbefore[i]);
	}

	/* --- and without the mark the reset is still the old one --- */
	seed_plan(&plan, 4);
	(void)uml_nt_mm_fault(&mm, &ph, 0x60860010ull, UML_NT_FAULT_WRITE, &plan);
	CHECK(plan.n_ops == 1);			/* fresh plan, one repair op */

	if (fails) { printf("plan_merge: %d failure(s)\n", fails); return 1; }
	printf("plan_merge: a repair appends to an unsent tail\n");
	return 0;
}
EOF
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c"
"$TMP/t"
