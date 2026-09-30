/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ntabi_abi_check.c — compiled on BOTH targets by test_ntabi.sh:
 *   - ELF freestanding (clang --target=x86_64-linux-gnu): disassembled to
 *     prove NT calls go through the Microsoft x64 ABI (rcx first arg).
 *   - PE (x86_64-w64-mingw32-gcc): proves the header is mingw-clean.
 *
 * The static asserts pin the documented x64 NT structure layouts; a
 * silent struct drift would corrupt every syscall before any test on
 * Windows could catch it.
 */
#ifdef _WIN64
/* winsock2.h BEFORE windows.h (ntabi.h includes it) — otherwise
 * windows.h drags winsock.h in first and the compile breaks. */
#include <winsock2.h>
#endif
#include <ntabi.h>

/* Materialize a call through the D9 table with 9 arguments so the
 * calling convention is visible in the disassembly. */
NTSTATUS consume(struct uml_nt_api_table *t, HANDLE h, void *buf, ULONG len)
{
	IO_STATUS_BLOCK iosb;
	return t->NtWriteFile(h, 0, 0, 0, &iosb, buf, len, 0, 0);
}

/* Layout pins (x64). */
_Static_assert(sizeof(NTSTATUS) == 4, "NTSTATUS is LONG (32-bit)");
_Static_assert(sizeof(HANDLE) == 8, "HANDLE is pointer-sized");
_Static_assert(sizeof(LARGE_INTEGER) == 8, "LARGE_INTEGER x64");
_Static_assert(sizeof(FILETIME) == 8, "FILETIME x64");
_Static_assert(sizeof(UNICODE_STRING) == 16, "UNICODE_STRING x64");
_Static_assert(sizeof(OBJECT_ATTRIBUTES) == 48, "OBJECT_ATTRIBUTES x64");
_Static_assert(sizeof(IO_STATUS_BLOCK) == 16, "IO_STATUS_BLOCK x64");
_Static_assert(sizeof(MEMORY_BASIC_INFORMATION) == 48, "MBI x64");

/* D9 contract sanity: version+size lead the table; NtWriteFile sits at
 * byte 24 (right after version/size/heap) — the disassembly assertions
 * in test_ntabi.sh rely on this offset. */
_Static_assert(__builtin_offsetof(struct uml_nt_api_table, version) == 0,
	       "table.version first");
_Static_assert(__builtin_offsetof(struct uml_nt_api_table, heap) == 8,
	       "table.heap at 8");
_Static_assert(__builtin_offsetof(struct uml_nt_api_table, NtWriteFile) == 24,
	       "table.NtWriteFile at 24");

/* M3.8 crash-reporter surface (freestanding decls only). */
#ifndef _WIN64
_Static_assert(sizeof(struct uml_nt_exception_record) == 0x98,
	       "EXCEPTION_RECORD x64");
_Static_assert(sizeof(struct uml_nt_exception_pointers) == 16,
	       "EXCEPTION_POINTERS x64");
#endif

/* M5.1a winsock mirrors: identical layout both build sides; the PE
 * side additionally pins them against winsock's own types. */
_Static_assert(sizeof(struct uml_nt_wsadata) == 408, "WSADATA mirror x64");
_Static_assert(sizeof(struct uml_nt_sockaddr_in) == 16,
	       "sockaddr_in mirror x64");
#ifdef _WIN64
_Static_assert(sizeof(struct uml_nt_wsadata) == sizeof(WSADATA),
	       "WSADATA mirror drifts from winsock");
_Static_assert(sizeof(struct uml_nt_sockaddr_in) ==
	       sizeof(struct sockaddr_in),
	       "sockaddr_in mirror drifts from winsock");
#endif
