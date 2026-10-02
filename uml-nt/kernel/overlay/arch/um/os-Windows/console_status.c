// SPDX-License-Identifier: GPL-2.0
/*
 * console_status.c — classify an NtReadFile status on the console
 * stdin handle. Pure integers (no host deps): the host CI unit test
 * compiles this file as-is.
 *
 * Shelley's 100-real-alpine freeze (2/2 reproduces): the reader
 * parked forever on a sporadic 0x101 (STATUS_WAIT_1) with
 * iosb.Information == 0 — a wake, not an EOF. The old test
 * (!NT_SUCCESS || Information == 0) treated every zero-information
 * return as stdin-closed; 0x101 is even NT_SUCCESS-positive, so it
 * died through the Information==0 half.
 */
#include "console_status.h"

int nt_con_status_class(long long status)
{
	switch (status) {
	case 0x00000000LL: /* STATUS_WAIT_0 */
	case 0x00000101LL: /* STATUS_WAIT_1 — the observed killer */
	case 0x00000102LL: /* STATUS_TIMEOUT */
	case 0x00000103LL: /* STATUS_PENDING */
		return NT_CON_RETRY;
	case 0xC0000011LL: /* STATUS_END_OF_FILE */
	case 0xC0000008LL: /* STATUS_INVALID_HANDLE */
	case 0xC0000234LL: /* STATUS_HANDLE_CLOSED */
		return NT_CON_FATAL;
	default:
		return NT_CON_FATAL; /* anything else = loud death */
	}
}
