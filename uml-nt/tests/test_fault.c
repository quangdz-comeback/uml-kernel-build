/* test_fault.c — unit tests for uml_nt_fault_decide (M3.1).
 *
 * Pure logic, compiled with the overlay fault.c as-is on Linux CI
 * (same pattern as test_scan_patch.c): no NT machinery, no kernel
 * headers — fault.h only.
 */
#include <stdio.h>
#include <fault.h>
#include <stub_nt.h> /* mirroring check: UML_STUB_ACTION_* */

static int fails;

#define CHECK(cond) do { if (!(cond)) { \
	fails++; \
	printf("FAIL %d: %s\n", __LINE__, #cond); \
} } while (0)

int main(void)
{
	struct uml_nt_fault_range allow[2] = {
		{ 0x60010000, 0x60011000 },
		{ 0x60020000, 0x60021000 },
	};
	unsigned action = 0, prot = 0;
	unsigned long long page = 0;

	/* Mirroring contract: the standalone constants must equal the
	 * shared stub protocol's (drift breaks both sides silently). */
	CHECK(UML_NT_FAULT_ACTION_PROT == UML_STUB_ACTION_PROT);
	CHECK(UML_NT_FAULT_ACTION_KILL == UML_STUB_ACTION_KILL);
	CHECK(UML_NT_PAGE_READWRITE == 0x04u);
	CHECK(UML_NT_PAGE_EXECUTE_READWRITE == 0x40u);
	CHECK(UML_NT_FAULT_READ == 0u);
	CHECK(UML_NT_FAULT_WRITE == 1u);
	CHECK(UML_NT_FAULT_EXEC == 8u);

	/* Write fault inside range 0: recoverable, page = faulting
	 * page base, protection RW. */
	CHECK(uml_nt_fault_decide(0x60010848, UML_NT_FAULT_WRITE, allow, 2,
				  &action, &prot, &page) == 0);
	CHECK(action == UML_NT_FAULT_ACTION_PROT);
	CHECK(prot == UML_NT_PAGE_READWRITE);
	CHECK(page == 0x60010000);

	/* Read fault: same shape. */
	CHECK(uml_nt_fault_decide(0x60010fff, UML_NT_FAULT_READ, allow, 2,
				  &action, &prot, &page) == 0);
	CHECK(action == UML_NT_FAULT_ACTION_PROT);
	CHECK(prot == UML_NT_PAGE_READWRITE);
	CHECK(page == 0x60010000);

	/* DEP fault: recoverable with exec protections. */
	CHECK(uml_nt_fault_decide(0x60020444, UML_NT_FAULT_EXEC, allow, 2,
				  &action, &prot, &page) == 0);
	CHECK(action == UML_NT_FAULT_ACTION_PROT);
	CHECK(prot == UML_NT_PAGE_EXECUTE_READWRITE);
	CHECK(page == 0x60020000);

	/* Boundary: last byte of the range is fixable... */
	CHECK(uml_nt_fault_decide(0x60010fff, UML_NT_FAULT_WRITE, allow, 2,
				  &action, &prot, &page) == 0);
	/* ...but a page straddling the range end is NOT (the fix-up
	 * would protect memory the allow table does not own). */
	CHECK(uml_nt_fault_decide(0x60010fff + 1, UML_NT_FAULT_WRITE, allow, 2,
				  &action, &prot, &page) == -1);
	CHECK(action == UML_NT_FAULT_ACTION_KILL);

	/* First byte past range 0, inside range 1: range 1 wins. */
	CHECK(uml_nt_fault_decide(0x60020000, UML_NT_FAULT_WRITE, allow, 2,
				  &action, &prot, &page) == 0);
	CHECK(page == 0x60020000);

	/* Wild pointer: outside every range → KILL. */
	CHECK(uml_nt_fault_decide(0x12345678, UML_NT_FAULT_WRITE, allow, 2,
				  &action, &prot, &page) == -1);
	CHECK(action == UML_NT_FAULT_ACTION_KILL);

	/* NULL-ish address: also just "outside". */
	CHECK(uml_nt_fault_decide(0x0, UML_NT_FAULT_READ, allow, 2,
				  &action, &prot, &page) == -1);
	CHECK(action == UML_NT_FAULT_ACTION_KILL);

	/* Unknown access class: never guess — KILL. */
	CHECK(uml_nt_fault_decide(0x60010848, 5u, allow, 2,
				  &action, &prot, &page) == -1);
	CHECK(action == UML_NT_FAULT_ACTION_KILL);

	/* Empty allow table: everything is fatal. */
	CHECK(uml_nt_fault_decide(0x60010848, UML_NT_FAULT_WRITE, allow, 0,
				  &action, &prot, &page) == -1);

	if (fails) {
		printf("test_fault: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_fault: all ok\n");
	return 0;
}
