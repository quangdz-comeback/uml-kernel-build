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

#if defined(_WIN64)
#define UML_NTABI_CC /* ms ABI is the default under mingw/PE */
#else
#define UML_NTABI_CC __attribute__((ms_abi))
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

/* Status codes (subset used by uml-nt). */
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000)
#define STATUS_PENDING               ((NTSTATUS)0x00000103)
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000D)
#define STATUS_ILLEGAL_INSTRUCTION   ((NTSTATUS)0xC000001D)
#define STATUS_ACCESS_VIOLATION      ((NTSTATUS)0xC0000005)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)

/* OBJECT_ATTRIBUTES.Attributes */
#define OBJ_CASE_INSENSITIVE 0x00000040UL
/* NtCreateFile DesiredAccess / CreateDisposition / CreateOptions subset */
#define FILE_GENERIC_READ    0x00120089UL
#define FILE_GENERIC_WRITE   0x00120116UL
#define FILE_SHARE_READ      0x00000001UL
#define FILE_SHARE_WRITE     0x00000002UL
#define FILE_OPEN            0x00000001UL
#define FILE_CREATE          0x00000002UL
#define FILE_OPEN_IF         0x00000003UL
#define FILE_OVERWRITE_IF    0x00000005UL
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#define FILE_SKIP_SET_EVENTS_ON_HANDLE 0x00000800UL
/* VirtualAlloc/VirtualProtect */
#define MEM_COMMIT   0x00001000UL
#define MEM_RESERVE  0x00002000UL
#define MEM_RELEASE  0x00008000UL
#define PAGE_READWRITE           0x00000004UL
#define PAGE_EXECUTE_READWRITE   0x00000040UL
#define PAGE_NOACCESS            0x00000001UL
/* CreateWaitableTimerExW flags */
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002UL
/* NtCreateEvent.EventType */
#define NotificationEvent    0
#define SynchronizationEvent 1
/* RtlAllocateHeap flags */
#define HEAP_ZERO_MEMORY 0x00000008UL

/* Wait: timeout == NULL means infinite. */
#define UML_NT_INFINITE ((LARGE_INTEGER *)0)

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* Pseudo-handles (x64). */
#define UML_NT_CURRENT_PROCESS ((HANDLE)(long long)-1)
#define UML_NT_CURRENT_THREAD  ((HANDLE)(long long)-2)

/*
 * The D9 contract. Version bumps must append only (never reorder); the
 * kernel accepts version == UML_NT_API_VERSION exactly (it fails loudly
 * otherwise — silent ABI drift is the failure mode we refuse).
 */
#define UML_NT_API_VERSION 1u

/* ---- function prototypes (ms_abi) — the launcher resolves these ------ */

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
};

#endif /* __UML_NTABI_H */
