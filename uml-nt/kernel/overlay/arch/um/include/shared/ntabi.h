/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ntabi.h — freestanding NT API declarations for uml-nt (D1, D9).
 *
 * Why this file exists: the kernel is an ELF built with the SysV target
 * (D2) and may not include windows.h or any host libc (D1), yet it must
 * call ntdll/kernel32 exports. Everything needed is declared here with
 * the Microsoft x64 calling convention forced via ms_abi.
 *
 * D9 (binding): the kernel never resolves these functions itself —
 * launcher.exe resolves them (GetProcAddress) and passes
 * `struct uml_nt_api_table` inside the boot info it places on the stack
 * before jumping to the kernel entry. The kernel checks `version` and
 * `size` first thing and PANICs on mismatch (fail loudly, never guess).
 *
 * ABI notes (x86_64):
 *  - NT calls: args in rcx,rdx,r8,r9 (+32-byte shadow space); ms_abi does
 *    exactly this under both the ELF (SysV) and mingw (PE) compilers.
 *  - NTSTATUS is a 32-bit signed value; >= 0 is success.
 *  - All structures below are the documented x64 layouts — asserted by
 *    tests/test_ntabi.sh on both build targets.
 */
#ifndef __UML_NTABI_H
#define __UML_NTABI_H

/*
 * Two consumer classes:
 *  - Kernel ELF (freestanding, D1): define the whole NT type surface
 *    here (no windows.h exists).
 *  - Host PE (launcher, mingw): windows.h is already included — REUSE
 *    its types instead of redefining them (typedef conflicts, and the
 *    widths agree on LLP64 x64 anyway). ntabi.h then contributes only
 *    the prototypes + macros both sides share.
 */
#if defined(_WIN64)
/* Host-PE mode: adopt the windows.h types. Include them here so this
 * header stays self-contained on both build sides (D9: one header
 * source for launcher and kernel — drift fails to compile). */
#include <windows.h>
#include <winternl.h>
#define UML_NTABI_CC /* ms ABI is the default under mingw/PE */
#else
#define UML_NTABI_CC __attribute__((ms_abi))

/* Freestanding ELF mode has no <stddef.h>; PE mode gets NULL from
 * windows.h — the guard keeps one definition either way. */
#ifndef NULL
#define NULL ((void *)0)
#endif

typedef int NTSTATUS; /* LONG */
typedef unsigned int ACCESS_MASK;
typedef void *PVOID;
typedef PVOID HANDLE;

typedef unsigned int ULONG;
typedef int LONG; /* NT LONG is 32-bit — NOT the SysV 'long' (8 bytes) */
typedef unsigned int DWORD;
typedef unsigned short USHORT;
typedef unsigned short WCHAR;
typedef unsigned char BOOLEAN;
typedef unsigned long long SIZE_T;
typedef unsigned long long ULONG_PTR;
typedef long long LONG64;
typedef int BOOL; /* win32 BOOL (4 bytes) — NOT the 1-byte BOOLEAN */
typedef const char *LPCSTR; /* M5.6b quiet: GetEnvironmentVariableA */
typedef char *LPSTR;

/* CreateProcessW / CreateFileMappingW / CreateEventW plumbing. */
typedef struct {
	ULONG nLength; /* DWORD */
	PVOID lpSecurityDescriptor;
	BOOL bInheritHandle;
} SECURITY_ATTRIBUTES; /* 16 bytes on x64 */

typedef struct {
	ULONG cb; /* DWORD */
	char *lpReserved; /* must be NULL */
	char *lpDesktop;
	char *lpTitle;
	ULONG dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars,
	      dwFillAttribute, dwFlags;
	USHORT wShowWindow, cbReserved2;
	unsigned char *lpReserved2;
	HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOA; /* 104 bytes on x64 (lpReserved included) */

typedef struct {
	HANDLE hProcess, hThread;
	ULONG dwProcessId, dwThreadId;
} PROCESS_INFORMATION; /* 24 bytes on x64 */

typedef union {
	struct {
		ULONG LowPart;
		LONG HighPart;
	};
	LONG64 QuadPart;
} LARGE_INTEGER;

typedef struct {
	ULONG LowPart;
	ULONG HighPart;
} FILETIME; /* 8 bytes */

typedef struct {
	USHORT Length;          /* bytes, excluding NUL */
	USHORT MaximumLength;
	WCHAR *Buffer;
} UNICODE_STRING; /* 16 bytes on x64 */

typedef struct {
	ULONG Length;
	HANDLE RootDirectory;
	UNICODE_STRING *ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES; /* 48 bytes on x64 */

typedef union {
	NTSTATUS Status;
	PVOID Pointer;
} IO_STATUS_BLOCK_STATUS;

typedef struct {
	IO_STATUS_BLOCK_STATUS u;
	ULONG_PTR Information;
} IO_STATUS_BLOCK; /* 16 bytes on x64 */

typedef struct {
	PVOID BaseAddress;
	PVOID AllocationBase;
	ULONG AllocationProtect;
	ULONG _pad0;
	SIZE_T RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION; /* 48 bytes on x64 */
#endif /* !_WIN64 */

/* Status codes (subset used by uml-nt). */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000)
#endif
#ifndef STATUS_PENDING
#define STATUS_PENDING               ((NTSTATUS)0x00000103)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000D)
#endif
#ifndef STATUS_ILLEGAL_INSTRUCTION
#define STATUS_ILLEGAL_INSTRUCTION   ((NTSTATUS)0xC000001D)
#endif
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION      ((NTSTATUS)0xC0000005)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#endif
/* M3.5: NtReadFile at/after EOF (plain data files). */
#ifndef STATUS_END_OF_FILE
#define STATUS_END_OF_FILE           ((NTSTATUS)0xC0000011)
#endif
#ifndef STATUS_DISK_FULL
#define STATUS_DISK_FULL             ((NTSTATUS)0xC0000047)
#endif

/* OBJECT_ATTRIBUTES.Attributes */
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040UL
#endif
/* NtCreateFile DesiredAccess / CreateDisposition / CreateOptions subset */
#ifndef FILE_GENERIC_READ
#define FILE_GENERIC_READ    0x00120089UL
#endif
#ifndef FILE_GENERIC_WRITE
#define FILE_GENERIC_WRITE   0x00120116UL
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ      0x00000001UL
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE     0x00000002UL
#endif
#ifndef FILE_OPEN
#define FILE_OPEN            0x00000001UL
#endif
#ifndef FILE_CREATE
#define FILE_CREATE          0x00000002UL
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF         0x00000003UL
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF    0x00000005UL
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#endif
#ifndef FILE_SKIP_SET_EVENTS_ON_HANDLE
#define FILE_SKIP_SET_EVENTS_ON_HANDLE 0x00000800UL
#endif
/* M3.5: NtCreateFile for plain data files (ubd backing images). */
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080UL
#endif
/* VirtualAlloc/VirtualProtect */
#ifndef MEM_COMMIT
#define MEM_COMMIT   0x00001000UL
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE  0x00002000UL
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE  0x00008000UL
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE           0x00000004UL
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE   0x00000040UL
#endif
#ifndef PAGE_NOACCESS
#define PAGE_NOACCESS            0x00000001UL
#endif
/* CreateWaitableTimerExW flags */
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002UL
#endif
/* NtCreateEvent.EventType */
#ifndef NotificationEvent
#define NotificationEvent    0
#endif
#ifndef SynchronizationEvent
#define SynchronizationEvent 1
#endif
/* RtlAllocateHeap flags */
#ifndef HEAP_ZERO_MEMORY
#define HEAP_ZERO_MEMORY 0x00000008UL
#endif

/* Wait: timeout == NULL means infinite. */
#undef UML_NT_INFINITE
#define UML_NT_INFINITE ((LARGE_INTEGER *)0)

#undef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* Pseudo-handles (x64). */
#undef UML_NT_CURRENT_PROCESS
#define UML_NT_CURRENT_PROCESS ((HANDLE)(long long)-1)
#undef UML_NT_CURRENT_THREAD
#define UML_NT_CURRENT_THREAD  ((HANDLE)(long long)-2)

/*
 * M3.5: build an NT object path from a host-style path (ASCII POC) by
 * prepending the \??\ root and widening to UTF-16. Pure string logic —
 * no syscalls — so test_ntabi.sh exercises it in both build modes.
 *
 * Returns the number of WCHARs written (NUL excluded, prefix included),
 * or a negative code: -1 = non-ASCII byte (M4 will do UTF-8), -2 =
 * output too small, -3 = NULL/empty input.
 */
static inline long long uml_nt_ntpath(const char *path, WCHAR *out,
				      unsigned long long out_wchars)
{
	const char *p = path;
	WCHAR *w = out;

	if (path == NULL || path[0] == 0)
		return -3;
	if (out == NULL || out_wchars < 6)
		return -2;
	*w++ = '\\';
	*w++ = '?';
	*w++ = '?';
	*w++ = '\\';
	for (; *p; p++) {
		if ((unsigned char)*p > 0x7f)
			return -1;
		if ((unsigned long long)(w - out) >= out_wchars - 1)
			return -2;
		*w++ = (WCHAR)(unsigned char)*p;
	}
	*w = 0;
	return (long long)(w - out);
}

/*
 * Winsock mirror structs (M5.1a, D8): the kernel speaks the netstack
 * channel over TCP localhost, so the D9 table carries ws2_32 exports.
 * These are OUR structs — both build sides see the same definition, so
 * the table layout is identical; test_ntabi.sh asserts the layouts
 * against the real winsock types on the PE side (drift fails to
 * compile) and pins the sizes freestanding-side.
 */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
/* Winsock version request: MAKEWORD(2,2). */
#define UML_NT_WSA_VERSION 0x0202u
/* WSAEventSelect network-event bits (subset). */
#define UML_NT_FD_READ  0x1u
#define UML_NT_FD_WRITE 0x2u
#define UML_NT_FD_CLOSE 0x20u

struct uml_nt_wsadata {
	unsigned short wVersion;     /* 0 */
	unsigned short wHighVersion; /* 2 */
	unsigned short iMaxSockets;  /* 4 */
	unsigned short iMaxUdpDg;    /* 6 */
	void *lpVendorInfo;          /* 8 */
	char szDescription[257];     /* 16 */
	char szSystemStatus[129];    /* 273 */
}; /* 402 bytes, sizeof 408 (8-aligned) on x64 */

struct uml_nt_sockaddr_in {
	short sin_family;      /* AF_INET */
	unsigned short sin_port; /* network order */
	unsigned int sin_addr;   /* network order (uml_nt_inet_pton4) */
	char sin_zero[8];
}; /* 16 bytes on x64 — ABI-identical to winsock's sockaddr_in */

#define UML_NT_INVALID_SOCKET (~0ULL)

/*
 * Byte-order + dotted-quad helpers: pure inline logic (no export
 * needed, testable on both build sides — test_ntabi.sh runs them).
 * Network order on a little-endian host means the u32 VALUE holds the
 * wire bytes a,b,c,d as 0xa | b<<8 | c<<16 | d<<24.
 */
static inline unsigned short uml_nt_htons(unsigned short v)
{
	return (unsigned short)((v << 8) | (v >> 8));
}

static inline unsigned int uml_nt_htonl(unsigned int v)
{
	return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) |
	       ((v >> 8) & 0xff00u) | ((v >> 24) & 0xffu);
}

/* 1 = parsed (*out filled, network order), 0 = not a dotted quad.
 * Strict: exactly four decimal octets 0-255, no leading zeros ("01"
 * rejected like inet_pton), no trailing junk. */
static inline int uml_nt_inet_pton4(const char *s, unsigned int *out)
{
	unsigned int oct[4];
	unsigned int v;
	int i, digits;
	const char *p = s;

	if (s == NULL || out == NULL)
		return 0;
	for (i = 0; i < 4; i++) {
		v = 0;
		digits = 0;
		while (*p >= '0' && *p <= '9') {
			if (++digits > 3)
				return 0;
			v = v * 10 + (unsigned int)(*p - '0');
			if (v > 255)
				return 0;
			/* leading zero: a second digit after "0" */
			if (digits == 2 && v < 10 &&
			    p[-1] == '0')
				return 0;
			p++;
		}
		if (digits == 0)
			return 0;
		oct[i] = v;
		if (i < 3) {
			if (*p != '.')
				return 0;
			p++;
		}
	}
	if (*p != 0)
		return 0;
	*out = oct[0] | (oct[1] << 8) | (oct[2] << 16) | (oct[3] << 24);
	return 1;
}

/*
 * The D9 contract. Version bumps must append only (never reorder); the
 * kernel accepts version == UML_NT_API_VERSION exactly (it fails loudly
 * otherwise — silent ABI drift is the failure mode we refuse).
 */
#define UML_NT_API_VERSION 4u

/* ---- function prototypes (ms_abi) — the launcher resolves these ------
 * Kernel-ELF consumers need them declared here (nothing else will).
 * Host-PE consumers get the same functions from winbase.h/winternl.h —
 * redeclaring them here collides with the real (dllimport) prototypes,
 * and the launcher never calls them by name anyway (it resolves into
 * the table below). */
#ifndef _WIN64

NTSTATUS UML_NTABI_CC NtCreateFile(HANDLE *file, ACCESS_MASK desired_access,
				   OBJECT_ATTRIBUTES *obj_attr,
				   IO_STATUS_BLOCK *iosb,
				   LARGE_INTEGER *alloc_size, ULONG attribs,
				   ULONG share, ULONG disposition,
				   ULONG options, PVOID ea_buffer,
				   ULONG ea_length);

NTSTATUS UML_NTABI_CC NtWriteFile(HANDLE file, HANDLE event,
				  PVOID apc_routine, PVOID apc_context,
				  IO_STATUS_BLOCK *iosb, PVOID buffer,
				  ULONG length, LARGE_INTEGER *offset,
				  ULONG *key);

NTSTATUS UML_NTABI_CC NtReadFile(HANDLE file, HANDLE event,
				 PVOID apc_routine, PVOID apc_context,
				 IO_STATUS_BLOCK *iosb, PVOID buffer,
				 ULONG length, LARGE_INTEGER *offset,
				 ULONG *key);

NTSTATUS UML_NTABI_CC NtWaitForSingleObject(HANDLE handle,
					    BOOLEAN alertable,
					    LARGE_INTEGER *timeout);

NTSTATUS UML_NTABI_CC NtClose(HANDLE handle);

NTSTATUS UML_NTABI_CC NtDelayExecution(BOOLEAN alertable,
				       LARGE_INTEGER *interval);

NTSTATUS UML_NTABI_CC NtCreateEvent(HANDLE *event, ACCESS_MASK desired_access,
				    OBJECT_ATTRIBUTES *obj_attr, int event_type,
				    BOOLEAN initial_state);

NTSTATUS UML_NTABI_CC NtSetEvent(HANDLE event, LONG *previous_state);

int UML_NTABI_CC QueryPerformanceCounter(LARGE_INTEGER *counter);

int UML_NTABI_CC QueryPerformanceFrequency(LARGE_INTEGER *frequency);

void UML_NTABI_CC GetSystemTimePreciseAsFileTime(FILETIME *out);

HANDLE UML_NTABI_CC CreateWaitableTimerExW(PVOID sec_attr, WCHAR *name,
					   ULONG flags, ACCESS_MASK access);

BOOLEAN UML_NTABI_CC SetWaitableTimer(HANDLE timer, LARGE_INTEGER *due_time,
				      LONG period, PVOID completion_routine,
				      PVOID completion_arg, BOOLEAN resume);

BOOLEAN UML_NTABI_CC CancelWaitableTimer(HANDLE timer);

PVOID UML_NTABI_CC RtlAllocateHeap(HANDLE heap, ULONG flags, SIZE_T bytes);

BOOLEAN UML_NTABI_CC RtlFreeHeap(HANDLE heap, ULONG flags, PVOID ptr);

PVOID UML_NTABI_CC VirtualAlloc(PVOID address, SIZE_T size, ULONG type,
				ULONG protect);

BOOLEAN UML_NTABI_CC VirtualFree(PVOID address, SIZE_T size, ULONG free_type);

BOOLEAN UML_NTABI_CC VirtualProtect(PVOID address, SIZE_T size, ULONG protect,
				    ULONG *old_protect);

SIZE_T UML_NTABI_CC VirtualQuery(PVOID address,
				 MEMORY_BASIC_INFORMATION *buffer,
				 SIZE_T length);

/* S5 lesson: returns an ERROR CODE (0 = ERROR_SUCCESS), not a BOOL. */
unsigned int UML_NTABI_CC DiscardVirtualMemory(PVOID address, SIZE_T size);

/* M1.7 additions (appended; table members above stay frozen). */
HANDLE UML_NTABI_CC CreateThread(PVOID sec_attr, SIZE_T stack_size,
				 unsigned long (UML_NTABI_CC *start)(PVOID arg),
				 PVOID arg, ULONG create_flags, ULONG *thread_id);
unsigned int UML_NTABI_CC GetCurrentProcessId(void);
NTSTATUS UML_NTABI_CC NtTerminateProcess(HANDLE process, NTSTATUS exit_status);
NTSTATUS UML_NTABI_CC NtMapViewOfSection(HANDLE section, HANDLE process,
					 PVOID *base, ULONG_PTR zero_bits,
					 SIZE_T commit_size,
					 LARGE_INTEGER *section_offset,
					 SIZE_T *view_size,
					 int inherit_disposition,
					 ULONG allocation_type, ULONG protect);
NTSTATUS UML_NTABI_CC NtUnmapViewOfSection(HANDLE process, PVOID base);
NTSTATUS UML_NTABI_CC NtProtectVirtualMemory(HANDLE process, PVOID *base,
					     SIZE_T *size, ULONG protect,
					     ULONG *old_protect);
ULONG UML_NTABI_CC RtlGetLastWin32Error(void);
BOOLEAN UML_NTABI_CC CloseHandle(HANDLE handle);
/* M5.6b quiet: kernel-side reads UML_NT_QUIET host env via this. */
DWORD UML_NTABI_CC GetEnvironmentVariableA(LPCSTR name, LPSTR buf,
		DWORD size);

/* M2 additions (appended; table members above stay frozen). Kernel is
 * the parent of every stub process: it creates the stub_data section
 * + events itself (inheritable) and spawns stub.exe suspended. */
HANDLE UML_NTABI_CC CreateFileMappingW(HANDLE file,
		SECURITY_ATTRIBUTES *sa, ULONG protect, ULONG size_hi,
		ULONG size_lo, WCHAR *name);
HANDLE UML_NTABI_CC CreateEventW(SECURITY_ATTRIBUTES *sa, BOOL manual_reset,
				 BOOL initial_state, WCHAR *name);
PVOID UML_NTABI_CC MapViewOfFileEx(HANDLE mapping, ULONG desired_access,
				   ULONG file_offset_hi, ULONG file_offset_lo,
				   SIZE_T bytes, PVOID base);
BOOLEAN UML_NTABI_CC UnmapViewOfFile(PVOID base);
BOOL UML_NTABI_CC CreateProcessA(char *app_name, char *cmd_line,
				 SECURITY_ATTRIBUTES *pa, SECURITY_ATTRIBUTES *ta,
				 BOOL inherit_handles, ULONG create_flags,
				 PVOID env, char *cwd, STARTUPINFOA *si,
				 PROCESS_INFORMATION *pi);
ULONG UML_NTABI_CC ResumeThread(HANDLE thread);
BOOL UML_NTABI_CC GetExitCodeProcess(HANDLE process, ULONG *exit_code);

/* M5.6b additions (appended; table members above stay frozen). Job
 * membership for spawned children: the launcher owns a kill-on-close
 * job (boot-info v4 carries the handle) — every stub/helper joins it
 * so a launcher/kernel death takes the whole tree down (the
 * zombie-stub report: park_forever outlived a dead kernel on the
 * real machine). Nested jobs = Win8+; the CI runner's parent job
 * combs fine. */
BOOLEAN UML_NTABI_CC AssignProcessToJobObject(HANDLE job, HANDLE process);

/* M3.3 additions (appended; table members above stay frozen). The
 * kernel serves several stub processes: one wait on all their evt_in
 * handles (timeout in ms, INFINITE = 0xFFFFFFFF). */
ULONG UML_NTABI_CC WaitForMultipleObjects(ULONG count, HANDLE *handles,
					  BOOL wait_all, ULONG timeout_ms);
/* M3.5 additions (appended; table members above stay frozen). Real
 * host-file I/O for ubd backing images. */
BOOLEAN UML_NTABI_CC GetFileSizeEx(HANDLE file, LARGE_INTEGER *size);

/* M3.8 additions (appended; table members above stay frozen). The
 * kernel process owns NO exception handling yet — upstream UML
 * installs a SIGSEGV handler that panics loudly on kernel faults;
 * on NT a wild kernel-side deref died with a bare 139 (silent). The
 * crash-reporter VEH restores the loudness: print rip + fault
 * address, then terminate (os_dump_core parity). */
PVOID UML_NTABI_CC AddVectoredExceptionHandler(ULONG first,
					       PVOID handler);

/* Minimal x64 exception surface for the reporter (documented
 * winnt.h layouts; the full CONTEXT is 0x4d0 bytes — the reporter
 * reads only the fault rip through the fixed offset below). */
struct uml_nt_exception_record {
	ULONG code;         /* 0x00 */
	ULONG flags;        /* 0x04 */
	PVOID record;       /* 0x08 */
	PVOID address;      /* 0x10 */
	ULONG nparams;      /* 0x18 */
	ULONG _pad0;        /* 0x1c */
	ULONG_PTR info[15]; /* 0x20 */
}; /* 0x98 bytes */

struct uml_nt_exception_pointers {
	struct uml_nt_exception_record *record;
	PVOID context; /* x64 CONTEXT */
};

/* x64 CONTEXT.Rip offset (P1Home..P6Home 0x00-0x2f, ContextFlags
 * 0x30, MxCsr 0x34, segments 0x38, EFlags 0x44, Dr0-Dr7 0x48-0x77,
 * Rax..R15 0x78-0xf0, Rip 0xf8). */
#define UML_NT_X64_CTX_REG(ctx, off) \
	(*(unsigned long long *)((char *)(ctx) + (off)))
#define UML_NT_X64_CTX_RIP(ctx) UML_NT_X64_CTX_REG(ctx, 0xf8)
#define UML_NT_X64_CTX_RAX(ctx) UML_NT_X64_CTX_REG(ctx, 0x78)
#define UML_NT_X64_CTX_RCX(ctx) UML_NT_X64_CTX_REG(ctx, 0x80)
#define UML_NT_X64_CTX_RDX(ctx) UML_NT_X64_CTX_REG(ctx, 0x88)
#define UML_NT_X64_CTX_RSP(ctx) UML_NT_X64_CTX_REG(ctx, 0x98)
#define UML_NT_X64_CTX_RBP(ctx) UML_NT_X64_CTX_REG(ctx, 0xa0)
#define UML_NT_X64_CTX_RSI(ctx) UML_NT_X64_CTX_REG(ctx, 0xa8)
#define UML_NT_X64_CTX_RDI(ctx) UML_NT_X64_CTX_REG(ctx, 0xb0)

/* M5.1a winsock prototypes (ELF freestanding side only — PE mode gets
 * the real decls from winsock headers, and redeclaring would risk
 * collision; the kernel only calls through the table anyway). SOCKET
 * is UINT_PTR (8 bytes x64); the mirror structs above are
 * ABI-identical to winsock's own types (asserted in ntabi_abi_check.c
 * against the PE headers). */
int UML_NTABI_CC WSAStartup(unsigned short version,
			    struct uml_nt_wsadata *data);
unsigned long long UML_NTABI_CC socket(int af, int type, int protocol);
int UML_NTABI_CC closesocket(unsigned long long s);
int UML_NTABI_CC connect(unsigned long long s,
			 struct uml_nt_sockaddr_in *addr, int namelen);
int UML_NTABI_CC send(unsigned long long s, const char *buf, int len,
		      int flags);
int UML_NTABI_CC recv(unsigned long long s, char *buf, int len, int flags);
void *UML_NTABI_CC WSACreateEvent(void);
int UML_NTABI_CC WSACloseEvent(void *event);
int UML_NTABI_CC WSAEventSelect(unsigned long long s, void *event,
				long net_events);
int UML_NTABI_CC WSAGetLastError(void);
#endif /* !_WIN64 */

/*
 * The D9 contract itself. Launcher fills every member; kernel validates
 * version + size before any use. Append-only evolution.
 */
struct uml_nt_api_table {
	unsigned int version; /* UML_NT_API_VERSION */
	unsigned int size;    /* sizeof(struct uml_nt_api_table), bytes */
	HANDLE heap;          /* process heap, for RtlAllocateHeap */

	/* ---- ntdll ------------------------------------------------------ */
	NTSTATUS (UML_NTABI_CC *NtCreateFile)(HANDLE *file,
			ACCESS_MASK desired_access,
			OBJECT_ATTRIBUTES *obj_attr, IO_STATUS_BLOCK *iosb,
			LARGE_INTEGER *alloc_size, ULONG attribs,
			ULONG share, ULONG disposition, ULONG options,
			PVOID ea_buffer, ULONG ea_length);
	NTSTATUS (UML_NTABI_CC *NtWriteFile)(HANDLE file, HANDLE event,
			PVOID apc_routine, PVOID apc_context,
			IO_STATUS_BLOCK *iosb, PVOID buffer, ULONG length,
			LARGE_INTEGER *offset, ULONG *key);
	NTSTATUS (UML_NTABI_CC *NtReadFile)(HANDLE file, HANDLE event,
			PVOID apc_routine, PVOID apc_context,
			IO_STATUS_BLOCK *iosb, PVOID buffer, ULONG length,
			LARGE_INTEGER *offset, ULONG *key);
	NTSTATUS (UML_NTABI_CC *NtWaitForSingleObject)(HANDLE handle,
			BOOLEAN alertable, LARGE_INTEGER *timeout);
	NTSTATUS (UML_NTABI_CC *NtClose)(HANDLE handle);
	NTSTATUS (UML_NTABI_CC *NtDelayExecution)(BOOLEAN alertable,
			LARGE_INTEGER *interval);
	NTSTATUS (UML_NTABI_CC *NtCreateEvent)(HANDLE *event,
			ACCESS_MASK desired_access,
			OBJECT_ATTRIBUTES *obj_attr, int event_type,
			BOOLEAN initial_state);
	NTSTATUS (UML_NTABI_CC *NtSetEvent)(HANDLE event, LONG *previous_state);

	/* ---- kernel32 --------------------------------------------------- */
	int (UML_NTABI_CC *QueryPerformanceCounter)(LARGE_INTEGER *counter);
	int (UML_NTABI_CC *QueryPerformanceFrequency)(LARGE_INTEGER *frequency);
	void (UML_NTABI_CC *GetSystemTimePreciseAsFileTime)(FILETIME *out);
	HANDLE (UML_NTABI_CC *CreateWaitableTimerExW)(PVOID sec_attr,
			WCHAR *name, ULONG flags, ACCESS_MASK access);
	BOOLEAN (UML_NTABI_CC *SetWaitableTimer)(HANDLE timer,
			LARGE_INTEGER *due_time, LONG period,
			PVOID completion_routine, PVOID completion_arg,
			BOOLEAN resume);
	BOOLEAN (UML_NTABI_CC *CancelWaitableTimer)(HANDLE timer);

	/* ---- ntdll (Rtl) + kernel32 (memory) ---------------------------- */
	PVOID (UML_NTABI_CC *RtlAllocateHeap)(HANDLE heap, ULONG flags,
			SIZE_T bytes);
	BOOLEAN (UML_NTABI_CC *RtlFreeHeap)(HANDLE heap, ULONG flags,
			PVOID ptr);
	PVOID (UML_NTABI_CC *VirtualAlloc)(PVOID address, SIZE_T size,
			ULONG type, ULONG protect);
	BOOLEAN (UML_NTABI_CC *VirtualFree)(PVOID address, SIZE_T size,
			ULONG free_type);
	BOOLEAN (UML_NTABI_CC *VirtualProtect)(PVOID address, SIZE_T size,
			ULONG protect, ULONG *old_protect);
	SIZE_T (UML_NTABI_CC *VirtualQuery)(PVOID address,
			MEMORY_BASIC_INFORMATION *buffer, SIZE_T length);
	unsigned int (UML_NTABI_CC *DiscardVirtualMemory)(PVOID address,
			SIZE_T size);

	/* ---- appended for M1.7 (append-only evolution of v1) ------------ */
	HANDLE (UML_NTABI_CC *CreateThread)(PVOID sec_attr, SIZE_T stack_size,
			unsigned long (UML_NTABI_CC *start)(PVOID arg),
			PVOID arg, ULONG create_flags, ULONG *thread_id);
	unsigned int (UML_NTABI_CC *GetCurrentProcessId)(void);
	NTSTATUS (UML_NTABI_CC *NtTerminateProcess)(HANDLE process,
			NTSTATUS exit_status);
	NTSTATUS (UML_NTABI_CC *NtMapViewOfSection)(HANDLE section,
			HANDLE process, PVOID *base, ULONG_PTR zero_bits,
			SIZE_T commit_size, LARGE_INTEGER *section_offset,
			SIZE_T *view_size, int inherit_disposition,
			ULONG allocation_type, ULONG protect);
	NTSTATUS (UML_NTABI_CC *NtUnmapViewOfSection)(HANDLE process,
			PVOID base);
	NTSTATUS (UML_NTABI_CC *NtProtectVirtualMemory)(HANDLE process,
			PVOID *base, SIZE_T *size, ULONG protect,
			ULONG *old_protect);
	ULONG (UML_NTABI_CC *RtlGetLastWin32Error)(void);
	BOOLEAN (UML_NTABI_CC *CloseHandle)(HANDLE handle);

	/* ---- appended for M2 -------------------------------------------- */
	HANDLE (UML_NTABI_CC *CreateFileMappingW)(HANDLE file,
			SECURITY_ATTRIBUTES *sa, ULONG protect,
			ULONG size_hi, ULONG size_lo, WCHAR *name);
	HANDLE (UML_NTABI_CC *CreateEventW)(SECURITY_ATTRIBUTES *sa,
			BOOL manual_reset, BOOL initial_state, WCHAR *name);
	PVOID (UML_NTABI_CC *MapViewOfFileEx)(HANDLE mapping,
			ULONG desired_access, ULONG file_offset_hi,
			ULONG file_offset_lo, SIZE_T bytes, PVOID base);
	BOOLEAN (UML_NTABI_CC *UnmapViewOfFile)(PVOID base);
	BOOL (UML_NTABI_CC *CreateProcessA)(char *app_name, char *cmd_line,
			SECURITY_ATTRIBUTES *pa, SECURITY_ATTRIBUTES *ta,
			BOOL inherit_handles, ULONG create_flags, PVOID env,
			char *cwd, STARTUPINFOA *si, PROCESS_INFORMATION *pi);
	ULONG (UML_NTABI_CC *ResumeThread)(HANDLE thread);
	BOOL (UML_NTABI_CC *GetExitCodeProcess)(HANDLE process,
			ULONG *exit_code);

	/* ---- appended for M3.3 ------------------------------------------ */
	ULONG (UML_NTABI_CC *WaitForMultipleObjects)(ULONG count,
			HANDLE *handles, BOOL wait_all, ULONG timeout_ms);

	/* ---- appended for M3.5 (ubd host files) -------------------------- */
	BOOLEAN (UML_NTABI_CC *GetFileSizeEx)(HANDLE file,
			LARGE_INTEGER *size);

	/* ---- appended for M3.8 (kernel crash reporter) ------------------- */
	/* Handler param stays PVOID: PE mode has the real
	 * PVECTORED_EXCEPTION_HANDLER typedef, the kernel casts its
	 * freestanding handler — same signature either way. */
	PVOID (UML_NTABI_CC *AddVectoredExceptionHandler)(ULONG first,
			PVOID handler);

	/* ---- appended for M5.1 (winsock — the D8 TCP channel) ------------
	 * SOCKET typed as unsigned long long (UINT_PTR x64): keeps the
	 * table definition identical on both build sides without pulling
	 * winsock headers into PE mode. Mirror structs above are
	 * ABI-identical to winsock's own (asserted in ntabi_abi_check.c). */
	int (UML_NTABI_CC *WSAStartup)(unsigned short version,
			struct uml_nt_wsadata *data);
	unsigned long long (UML_NTABI_CC *socket)(int af, int type,
			int protocol);
	int (UML_NTABI_CC *closesocket)(unsigned long long s);
	int (UML_NTABI_CC *connect)(unsigned long long s,
			struct uml_nt_sockaddr_in *addr, int namelen);
	int (UML_NTABI_CC *send)(unsigned long long s, const char *buf,
			int len, int flags);
	int (UML_NTABI_CC *recv)(unsigned long long s, char *buf, int len,
			int flags);
	void *(UML_NTABI_CC *WSACreateEvent)(void);
	int (UML_NTABI_CC *WSACloseEvent)(void *event);
	int (UML_NTABI_CC *WSAEventSelect)(unsigned long long s,
			void *event, long net_events);
	int (UML_NTABI_CC *WSAGetLastError)(void);

	/* ---- appended for M5.6b (job object — the zombie-stub fix) -------
	 * The launcher dies for ANY reason (panic/crash/taskkill/exit)
	 * → Windows kills every stub+helper in the job. The handle
	 * travels in boot-info v4 (job_object). */
	BOOLEAN (UML_NTABI_CC *AssignProcessToJobObject)(HANDLE job,
			HANDLE process);

	/* ---- appended for M5.6b quiet (osinfo-quiet patch, Shelley) ------
	 * Kernel-side os_info reads UML_NT_QUIET through this (cached
	 * flag; os_warn/os_err stay loud). APPENDED at the struct end —
	 * the append-only ABI contract (mid-table inserts would shift
	 * every later member's offset). */
	DWORD (UML_NTABI_CC *GetEnvironmentVariableA)(LPCSTR name,
			LPSTR buf, DWORD size);
};

#endif /* __UML_NTABI_H */
