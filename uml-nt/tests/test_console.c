/* SPDX-License-Identifier: GPL-2.0 */
/*
 * console-status classifier unit test (Shelley's 100-real-alpine
 * freeze): the stdin reader must re-arm on the spurious
 * zero-information statuses (the observed killer = 0x101/WAIT_1)
 * and park only on the real EOF/handle-death statuses.
 */
#include <stdio.h>
#include <console_status.h>

#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s\n", \
	__LINE__, #x); return 1; } } while (0)

int main(void)
{
	/* the spurious wake family — the reader lives */
	CHECK(nt_con_status_class(0x00000000LL) == NT_CON_RETRY);
	CHECK(nt_con_status_class(0x00000101LL) == NT_CON_RETRY);
	CHECK(nt_con_status_class(0x00000102LL) == NT_CON_RETRY);
	CHECK(nt_con_status_class(0x00000103LL) == NT_CON_RETRY);

	/* the real death family — the reader parks loud */
	CHECK(nt_con_status_class(0xC0000011LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0xC0000008LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0xC0000234LL) == NT_CON_FATAL);

	/* anything else is fatal (positive-status garbage included:
	 * NT_SUCCESS would call 0x1ffff fine — the classifier must
	 * NOT, only the four wake statuses retry) */
	CHECK(nt_con_status_class(0x00000104LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0x00000105LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0xC0000005LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0x80000017LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(-1LL) == NT_CON_FATAL);

	printf("test_console: all ok\n");
	return 0;
}
