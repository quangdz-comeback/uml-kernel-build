/* SPDX-License-Identifier: GPL-2.0 */
/* Red-before-tests for the debug continue map. */
#include <stdio.h>
#include "../kernel/overlay/arch/um/include/shared/dbg_map.h"

static int fails;
#define CHECK(c) do { if (!(c)) { \
	fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } \
} while (0)

int main(void)
{
	int first_bp = 0;

	/* create/load/thread/exit are always continued, or the debuggee
	 * never runs */
	CHECK(uml_nt_dbg_answer(3, 0, &first_bp) == UML_NT_DBG_ANS_CONTINUE);
	CHECK(uml_nt_dbg_answer(6, 0, &first_bp) == UML_NT_DBG_ANS_CONTINUE);
	CHECK(uml_nt_dbg_answer(UML_NT_DBG_EV_EXIT_PROCESS, 0, &first_bp) ==
	      UML_NT_DBG_ANS_CONTINUE);

	/* the loader's breakpoint is continued exactly once */
	CHECK(uml_nt_dbg_answer(UML_NT_DBG_EV_EXCEPTION,
				UML_NT_STATUS_BREAKPOINT, &first_bp) ==
	      UML_NT_DBG_ANS_CONTINUE);
	CHECK(first_bp == 1);
	CHECK(uml_nt_dbg_answer(UML_NT_DBG_EV_EXCEPTION,
				UML_NT_STATUS_BREAKPOINT, &first_bp) ==
	      UML_NT_DBG_ANS_NOT_HANDLED);

	/* everything else is the debuggee's business */
	CHECK(uml_nt_dbg_answer(UML_NT_DBG_EV_EXCEPTION, 0xC0000005u,
				&first_bp) == UML_NT_DBG_ANS_NOT_HANDLED);
	CHECK(uml_nt_dbg_answer(UML_NT_DBG_EV_EXCEPTION, 0xC00000FDu,
				&first_bp) == UML_NT_DBG_ANS_NOT_HANDLED);

	if (fails) {
		fprintf(stderr, "test_dbgmap: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_dbgmap: all checks passed\n");
	return 0;
}
