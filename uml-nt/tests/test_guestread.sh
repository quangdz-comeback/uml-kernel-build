#!/usr/bin/env bash
# S88 (report 387 §1): a diagnostic must be able to quote guest bytes without
# driving the uaccess sink. uml_nt_uacc_walk() clobbers the plan of the syscall
# in flight (M3.1 went red); uml_nt_gread() resolves through the VMA table and
# copies out of the run's backend page, touching nothing else.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC_OS="$HERE/../kernel/overlay/arch/um/os-Windows/include"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/t.c" <<'C'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fault.h>
#include <vma.h>
#include <physalloc.h>
#include <guestread.h>
static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); fails++; } } while (0)
static int taken[64];
long long uml_nt_phys_backend_alloc_span(void **page_out, int nruns)
{ (void)nruns; page_out[0] = taken; return 0x100000; }
void uml_nt_phys_backend_free(void *page, int nruns) { (void)page; (void)nruns; }

int main(void)
{
	struct uml_nt_mm mm;
	struct uml_nt_phys ph;
	struct uml_nt_fault_plan plan;
	char *run;
	unsigned long long gen0, epoch0;
	char buf[8];

	memset(&ph, 0, sizeof(ph));
	memset(&plan, 0, sizeof(plan));
	uml_nt_mm_init(&mm);
	run = (char *)calloc(1, (size_t)UML_NT_PHYS_RUN_SIZE);
	if (run == 0) return 2;
	memcpy(run + 0x40, "root\n", 5);
	ph.size = UML_NT_PHYS_RUN_SIZE;
	ph.refs[0] = 1;
	ph.pages[0] = run;
	ph.span_len[0] = 1;
	ph.span_back[0] = 0;
	gen0 = ph.gen[0];
	epoch0 = ph.epoch;
	/* one VMA: VA 0x60000000 -> run 0 */
	CHECK(uml_nt_vma_add(&mm, 0x60000000ull, 0x60000000ull + UML_NT_PHYS_RUN_SIZE,
			     0, UML_NT_PAGE_READWRITE, 0) == 0);
	/* inside: the bytes come out, and nothing else moves */
	CHECK(uml_nt_gread(&mm, &ph, 0x60000040ull, buf, 5) == 0);
	CHECK(memcmp(buf, "root\n", 5) == 0);
	CHECK(plan.n_ops == 0);                 /* the plan was not touched */
	CHECK(ph.gen[0] == gen0 && ph.epoch == epoch0);
	CHECK(mm.nvma == 1 && ph.refs[0] == 1);
	/* outside every VMA: a miss, named as such */
	CHECK(uml_nt_gread(&mm, &ph, 0x70000000ull, buf, 1) == -1);
	/* a VMA with no backend page: not a miss in the table, a miss in phys */
	ph.pages[0] = 0;
	CHECK(uml_nt_gread(&mm, &ph, 0x60000040ull, buf, 1) == -2);
	ph.pages[0] = run;
	/* a non-readable VMA refuses instead of pretending */
	mm.vma[0].prot = 0x01u;   /* write-only */
	CHECK(uml_nt_gread(&mm, &ph, 0x60000040ull, buf, 1) == -3);
	free(run);
	if (fails) { printf("test_guestread: %d failure(s)\n", fails); return 1; }
	puts("ok");
	return 0;
}
C
CC="${CC:-clang}"
"$CC" -O1 -Wall -Wextra -Werror -I"$INC_OS" -I"$INC" -o "$TMP/t" "$TMP/t.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/vma.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/fault.c" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/physalloc.c" \
	"$HERE/ans_free_live_fake.c" 2>"$TMP/err" || {
	grep -E "error:|undefined reference" "$TMP/err" | head -5; echo "FAIL: does not compile"; exit 1; }
out="$("$TMP/t")"
[ "$out" = "ok" ] || { echo "FAIL: $out"; exit 1; }
echo "guestread: guest bytes without the sink, and a miss that says 'miss'"
