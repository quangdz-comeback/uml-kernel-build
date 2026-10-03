/* launcher.c — uml-nt M1.8: launch the freestanding UML kernel (D2/D9).
 *
 * The launcher is a plain mingw PE program. It:
 *   1. resolves every NT API the kernel may call into a versioned
 *      `struct uml_nt_api_table` (D9) — the kernel itself never parses
 *      PE/PEB;
 *   2. maps vmlinux.elf (ELF64 ET_EXEC) at its fixed vaddrs (S3 recipe:
 *      one 64K-granularity reservation, per-segment commit+protect);
 *   3. creates the pagefile-backed guest-RAM section (kernel maps views
 *      of it on demand, see os-Windows/process.c os_map_memory);
 *   4. builds `struct uml_boot_info` + argv/envp ON the fresh kernel
 *      stack, then switches rsp and jumps to the ELF entry with
 *      [rsp] = boot-info pointer — the handoff _start consumes.
 *
 * Same process afterwards: the kernel IS the process image now; when it
 * panics ("no rootfs" at M1) it terminates the process itself.
 *
 * Includes ntabi.h + boot-info.h straight from the kernel overlay —
 * one header source for launcher and kernel, so ABI drift fails to
 * compile here instead of failing silently at boot.
 */
#include <windows.h>
/* ntdll-types: OBJECT_ATTRIBUTES + IO_STATUS_BLOCK live here, not in
 * winnt.h. ntabi.h (below) reuses the host types in PE mode (D9). */
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ntabi.h"
#include "boot-info.h"

/* ---- tiny ELF64 reader (S3 recipe) ------------------------------------ */
typedef struct {
	uint8_t e_ident[16];
	uint16_t e_type, e_machine;
	uint32_t e_version;
	uint64_t e_entry, e_phoff, e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
		 e_shstrndx;
} elf64_ehdr;

typedef struct {
	uint32_t p_type, p_flags;
	uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} elf64_phdr;

#define PT_LOAD 1
#define GRAN    0x10000ULL /* NT allocation granularity (64K, S3 lesson) */

/* Shadow VA for the full physmem section — above wine's low/dos zone
 * and its preloads, well below the 0x60000000 kernel image area. */
#define UML_PHYSMEM_SHADOW_VA 0x48000000ULL

static void die(const char *what, unsigned long gle)
{
	fprintf(stderr, "launcher: %s failed (gle=%lu)\n", what, gle);
	exit(2);
}

/* ---- D9: resolve the whole table, fail loudly on any miss ------------- */
static struct uml_nt_api_table g_api;

/* M5.6b: the launcher's own kill-on-close job. The kernel runs IN
 * this process and hands the handle to every spawn (stub.exe,
 * netstack) — the launcher dying for ANY reason (panic, crash,
 * taskkill, normal exit) makes Windows take the whole tree down.
 * Before this, a dead kernel left stub.exe park_forever-ing on the
 * real machine (nobody left to terminate it). */
static HANDLE g_job;

static void create_boot_job(void)
{
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;

	g_job = CreateJobObjectW(NULL, NULL);
	if (g_job == NULL)
		die("CreateJobObjectW", GetLastError());
	memset(&li, 0, sizeof(li));
	li.BasicLimitInformation.LimitFlags =
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(g_job,
				     JobObjectExtendedLimitInformation,
				     &li, sizeof(li)))
		die("SetInformationJobObject", GetLastError());
	/* Nested jobs (Win8+): a runner-owned parent job combs fine —
	 * this process ends up in both, our kill-on-close still fires
	 * on OUR handle's closure. Warn-and-continue (not die): the
	 * property is a real-machine guarantee; wine's job support is
	 * best-effort and the wine boot gate must stay green. */
	if (!AssignProcessToJobObject(g_job, GetCurrentProcess()))
		fprintf(stderr, "[launcher] job self-assign failed "
			"(gle=%lu) — zombie children possible on this "
			"host\n", GetLastError());
}

#define RESOLVE(field, mod, name)                                          \
	do {                                                               \
		g_api.field = (typeof(g_api.field))GetProcAddress(mod, name); \
		if (g_api.field == NULL) {                              \
			fprintf(stderr, "launcher: missing export %s\n",\
				name);                                   \
			exit(2);                                         \
		}                                                        \
	} while (0)

static void resolve_api_table(void)
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HMODULE k32 = GetModuleHandleA("kernel32.dll");

	if (ntdll == NULL || k32 == NULL)
		die("GetModuleHandle", GetLastError());

	g_api.version = UML_NT_API_VERSION;
	g_api.size = sizeof(g_api);
	g_api.heap = GetProcessHeap();

	RESOLVE(NtCreateFile, ntdll, "NtCreateFile");
	RESOLVE(NtWriteFile, ntdll, "NtWriteFile");
	RESOLVE(NtReadFile, ntdll, "NtReadFile");
	RESOLVE(NtWaitForSingleObject, ntdll, "NtWaitForSingleObject");
	RESOLVE(NtClose, ntdll, "NtClose");
	RESOLVE(NtDelayExecution, ntdll, "NtDelayExecution");
	RESOLVE(NtCreateEvent, ntdll, "NtCreateEvent");
	RESOLVE(NtSetEvent, ntdll, "NtSetEvent");

	RESOLVE(QueryPerformanceCounter, k32, "QueryPerformanceCounter");
	RESOLVE(QueryPerformanceFrequency, k32, "QueryPerformanceFrequency");
	RESOLVE(GetSystemTimePreciseAsFileTime, k32,
		"GetSystemTimePreciseAsFileTime");
	RESOLVE(CreateWaitableTimerExW, k32, "CreateWaitableTimerExW");
	RESOLVE(SetWaitableTimer, k32, "SetWaitableTimer");
	RESOLVE(CancelWaitableTimer, k32, "CancelWaitableTimer");

	RESOLVE(RtlAllocateHeap, ntdll, "RtlAllocateHeap");
	RESOLVE(RtlFreeHeap, ntdll, "RtlFreeHeap");
	RESOLVE(VirtualAlloc, k32, "VirtualAlloc");
	RESOLVE(VirtualFree, k32, "VirtualFree");
	RESOLVE(VirtualProtect, k32, "VirtualProtect");
	RESOLVE(VirtualQuery, k32, "VirtualQuery");
	RESOLVE(DiscardVirtualMemory, k32, "DiscardVirtualMemory");

	/* M1.7 additions */
	RESOLVE(CreateThread, k32, "CreateThread");
	RESOLVE(GetCurrentProcessId, k32, "GetCurrentProcessId");
	RESOLVE(NtTerminateProcess, ntdll, "NtTerminateProcess");
	RESOLVE(NtMapViewOfSection, ntdll, "NtMapViewOfSection");
	RESOLVE(NtUnmapViewOfSection, ntdll, "NtUnmapViewOfSection");
	RESOLVE(NtProtectVirtualMemory, ntdll, "NtProtectVirtualMemory");
	RESOLVE(RtlGetLastWin32Error, ntdll, "RtlGetLastWin32Error");
	RESOLVE(CloseHandle, k32, "CloseHandle");
	RESOLVE(CreateFileMappingW, k32, "CreateFileMappingW");
	RESOLVE(CreateEventW, k32, "CreateEventW");
	RESOLVE(MapViewOfFileEx, k32, "MapViewOfFileEx");
	RESOLVE(UnmapViewOfFile, k32, "UnmapViewOfFile");

	/* M5.6b: the kernel assigns spawned children to the launcher's
	 * kill-on-close job (boot-info v4) — see create_boot_job(). */
	RESOLVE(AssignProcessToJobObject, k32, "AssignProcessToJobObject");
	RESOLVE(CreateProcessA, k32, "CreateProcessA");
	RESOLVE(ResumeThread, k32, "ResumeThread");
	RESOLVE(GetExitCodeProcess, k32, "GetExitCodeProcess");
	RESOLVE(WaitForMultipleObjects, k32, "WaitForMultipleObjects");

	/* M3.5 additions (ubd host files) */
	RESOLVE(GetFileSizeEx, k32, "GetFileSizeEx");

	/* M3.8: kernel crash reporter (loud native faults) */
	RESOLVE(AddVectoredExceptionHandler, k32,
		"AddVectoredExceptionHandler");

	/* M5.1a: winsock for the kernel's TCP channel (D8 — no AF_UNIX).
	 * Loaded at runtime (LoadLibrary + GetProcAddress): no link-time
	 * ws2_32 dependency, same D9 shape as every other export. */
	{
		HMODULE ws2 = LoadLibraryA("ws2_32.dll");

		if (ws2 == NULL)
			die("LoadLibraryA(ws2_32.dll)", GetLastError());
		RESOLVE(WSAStartup, ws2, "WSAStartup");
		RESOLVE(socket, ws2, "socket");
		RESOLVE(closesocket, ws2, "closesocket");
		RESOLVE(connect, ws2, "connect");
		RESOLVE(send, ws2, "send");
		RESOLVE(recv, ws2, "recv");
		RESOLVE(WSACreateEvent, ws2, "WSACreateEvent");
		RESOLVE(WSACloseEvent, ws2, "WSACloseEvent");
		RESOLVE(WSAEventSelect, ws2, "WSAEventSelect");
		RESOLVE(WSAGetLastError, ws2, "WSAGetLastError");
	}

	fprintf(stderr, "[launcher] D9 table v%u: %u bytes, all exports "
			"resolved\n", g_api.version, g_api.size);
}

/* ---- guest physmem: pagefile-backed section --------------------------- */
#define DEFAULT_PHYSMEM (128ULL << 20) /* section is the ceiling; the
					* kernel's mem= picks the size */

/* Guest RAM lives at [GUEST_RAM_VA, GUEST_RAM_VA + physmem) — ONE view
 * of the section covering the whole bank, image loaded straight into
 * it. This is the memfd analogue: guest physical X == GUEST_RAM_VA+X,
 * so os_map_memory is identity and fd-style r/w is a memcpy. */
#define GUEST_RAM_VA 0x60000000ULL

static HANDLE create_physmem_section(unsigned long long size, void **base)
{
	/* PAGE_EXECUTE_READWRITE on the section: guest RAM is mapped
	 * RWX (guest code lives in it) — a PAGE_READWRITE section makes
	 * execute views fail with STATUS_ACCESS_DENIED (c0000022,
	 * verified under wine at M1.8).
	 *
	 * M2: inheritable — the kernel passes the handle value on the
	 * stub.exe command line (S5 bootstrap pattern). */
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
	HANDLE sec = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa,
					PAGE_EXECUTE_READWRITE,
					(DWORD)(size >> 32), (DWORD)size,
					NULL);
	PVOID at = (PVOID)(uintptr_t)GUEST_RAM_VA;
	SIZE_T view_size = 0;
	NTSTATUS s;

	if (sec == NULL)
		die("CreateFileMapping (physmem)", GetLastError());

	s = g_api.NtMapViewOfSection(sec, UML_NT_CURRENT_PROCESS, &at, 0, 0,
				     NULL, &view_size, 1 /* ViewShare */, 0,
				     PAGE_EXECUTE_READWRITE);
	if (s < 0 || (uintptr_t)at != GUEST_RAM_VA) {
		fprintf(stderr, "launcher: map guest RAM at 0x%llx failed "
			"%08x (base=%p)\n", GUEST_RAM_VA, s, at);
		exit(2);
	}
	*base = at;
	return sec;
}

/* ---- the kernel's out-of-RAM VA band (vmalloc) -------------------------
 * Reserve EARLY — before any CRT heap allocation can claim the free
 * region right above the section view. The kernel's out-of-RAM maps
 * back into this band with private 64K blocks (os_map_memory), and
 * the band's base is upstream-fixed: VMALLOC_START = mem-end +
 * VMALLOC_OFFSET (8MiB) — with mem=120M that is 0x68000000,
 * immediately above the flat view. Run 36793426224: an unplaced
 * allocation (heap-segment class) squatted there, every block commit
 * failed and the timer thread wrote an unbacked page. Reserved here
 * the band is exclusive: address space only, no commit charge; see
 * band_size below for the sizing vs the 2GiB line. */
static void reserve_vmalloc_band(void)
{
	unsigned long long band = GUEST_RAM_VA + DEFAULT_PHYSMEM;
	/* 256MiB: the free gap under the 2GiB line is 384MiB minus the
	 * KUSER_SHARED_DATA page at 0x7FFE0000 (a 512MiB request
	 * crossed it — gle=487, run 36794554367); 256MiB covers band
	 * ends for any mem= up to the section ceiling (mem=128M: band
	 * [0x68800000, 0x70800000)) with 120MiB spare. */
	SIZE_T band_size = 256ULL << 20;
	PVOID r = g_api.VirtualAlloc((PVOID)(uintptr_t)band, band_size,
				     MEM_RESERVE, PAGE_NOACCESS);

	if (r != NULL) {
		fprintf(stderr, "[launcher] vmalloc band reserved "
			"[0x%llx, 0x%llx)\n",
			band, band + (unsigned long long)band_size);
		return;
	}

	/* Name the squatter before dying: the region containing the
	 * band base (State/Protect/Type tell heap vs section vs
	 * free-but-refusing). */
	{
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T n = g_api.VirtualQuery((PVOID)(uintptr_t)band,
					      &mbi, sizeof(mbi));

		fprintf(stderr, "launcher: vmalloc band reserve @0x%llx "
			"failed (gle=%lu)", band, GetLastError());
		if (n == sizeof(mbi))
			fprintf(stderr, " — region base=%p size=%#zx "
				"state=%#lx protect=%#lx type=%#lx",
				mbi.BaseAddress, (size_t)mbi.RegionSize,
				(unsigned long)mbi.State,
				(unsigned long)mbi.Protect,
				(unsigned long)mbi.Type);
		fprintf(stderr, "\n");
	}
	exit(2);
}

/* ---- ELF mapping (S3 recipe, simplified: the guest-RAM view already
 * covers every image VA — segments load straight into it) ------------- */
static void *map_elf(const char *path, uint64_t *entry_out,
		     uint64_t *image_base_out, uint64_t *image_size_out)
{
	FILE *f = fopen(path, "rb");
	elf64_ehdr eh;
	elf64_phdr *ph;
	int i;
	uintptr_t lo = ~(uintptr_t)0, hi = 0;

	if (f == NULL)
		die("open kernel image", 0);
	if (fread(&eh, sizeof(eh), 1, f) != 1 ||
	    memcmp(eh.e_ident, "\x7f" "ELF", 4) != 0 ||
	    eh.e_ident[4] != 2 /* 64-bit */ || eh.e_type != 2 /* ET_EXEC */) {
		fprintf(stderr, "launcher: %s is not a static ELF64 "
				"ET_EXEC\n", path);
		exit(2);
	}

	ph = calloc(eh.e_phnum, eh.e_phentsize);
	if (fseek(f, (long)eh.e_phoff, SEEK_SET) != 0 ||
	    fread(ph, eh.e_phentsize, eh.e_phnum, f) != eh.e_phnum)
		die("read phdrs", 0);

	for (i = 0; i < eh.e_phnum; i++) {
		elf64_phdr *p = (elf64_phdr *)((char *)ph +
					       (size_t)i * eh.e_phentsize);
		uintptr_t s, e;

		if (p->p_type != PT_LOAD || p->p_memsz == 0)
			continue;
		s = p->p_vaddr & ~0xFFFULL;
		e = (p->p_vaddr + p->p_memsz + 0xFFFULL) & ~0xFFFULL;
		if (s < lo)
			lo = s;
		if (e > hi)
			hi = e;
	}
	lo &= ~(GRAN - 1);
	hi = (hi + GRAN - 1) & ~(GRAN - 1);
	if (lo != GUEST_RAM_VA) {
		fprintf(stderr, "launcher: image at 0x%llx does not start "
				"at guest RAM base 0x%llx\n",
			(unsigned long long)lo, GUEST_RAM_VA);
		exit(2);
	}

	/* The guest-RAM view already covers every image VA — load the
	 * segments straight into it (memcpy, no per-segment commit;
	 * everything is RWX for M1, per-segment protect at M4). */
	for (i = 0; i < eh.e_phnum; i++) {
		elf64_phdr *p = (elf64_phdr *)((char *)ph +
					       (size_t)i * eh.e_phentsize);

		if (p->p_type != PT_LOAD || p->p_filesz == 0)
			continue;
		if (fseek(f, (long)p->p_offset, SEEK_SET) != 0 ||
		    fread((void *)(uintptr_t)p->p_vaddr, 1, p->p_filesz, f) !=
		    p->p_filesz)
			die("read segment bytes", 0);
	}
	fclose(f);

	/* memsz tail (bss) is already zero: the section view starts
	 * zero-filled and the loader wrote no bytes there. */
	free(ph);

	*entry_out = eh.e_entry;
	*image_base_out = (uint64_t)lo;
	*image_size_out = (uint64_t)(hi - lo);
	return (void *)lo;
}

/* ---- guest exec image (M3.4): uml_nt_exec=<file> → section --------
 * The launcher path is the M3.4 source for the kernel-side guest ELF
 * loader (the execveat(memfd) source analogue): the kernel cannot
 * open host files yet (file.c opens only the physmem pseudo-fd), so
 * the launcher reads the file and hands a read-back section in the
 * boot info. From M3.5 (ubd) real rootfs blobs take over. */
static HANDLE load_exec_section(const char *path, unsigned long long *size_out)
{
	FILE *f = fopen(path, "rb");
	unsigned long long size;
	void *buf;
	HANDLE sec;
	void *view;

	if (f == NULL) {
		fprintf(stderr, "launcher: uml_nt_exec: cannot open %s\n",
			path);
		exit(2);
	}
	if (fseek(f, 0, SEEK_END) != 0 ||
	    (size = (unsigned long long)ftell(f)) == 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		fprintf(stderr, "launcher: uml_nt_exec: %s unreadable\n",
			path);
		exit(2);
	}
	buf = malloc(size);
	if (buf == NULL || fread(buf, 1, size, f) != size)
		die("read exec image", 0);
	fclose(f);

	sec = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
				 PAGE_READWRITE, (DWORD)(size >> 32),
				 (DWORD)size, NULL);
	if (sec == NULL)
		die("CreateFileMapping (exec image)", GetLastError());
	view = MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 0);
	if (view == NULL)
		die("MapViewOfFile (exec image)", GetLastError());
	memcpy(view, buf, size);
	UnmapViewOfFile(view);
	free(buf);

	*size_out = size;
	return sec;
}

/* ---- kernel stack + boot info + jump ---------------------------------- */
#define KERNEL_STACK_SIZE (4ULL << 20)

/* D19: pending-only alarms mean no async tick can interrupt a tight
 * IRQ-enabled loop — calibrate_delay's jiffies wait would hang the
 * boot. Pin the loops_per_jiffy the native runner measured
 * (8252.62 BogoMIPS → lpj=41263104, run 36642510991 boot log); the
 * kernel prints it and skips calibration. Revisit with M4's real
 * preemption work. */
#define UML_NT_LPJ "lpj=41263104"

int main(int argc, char **argv)
{
	uint64_t entry;
	uint64_t img_base, img_size;
	void *image_base;
	HANDLE section;
	void *physmem_base;
	void *stack;
	uintptr_t top;
	char *kargv[64];
	char *kenv[4];
	size_t i;
	int nargs = argc - 2; /* argv[1]=image, argv[2..]=UML cmdline */
	struct uml_boot_info *bi;
	char **kargv_p;
	char **kenv_p;
	uintptr_t cur;
	HANDLE std_out, std_err;
	HANDLE exec_sec = NULL;
	unsigned long long exec_size = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: launcher.exe vmlinux.elf "
				"[UML args...]\n");
		return 2;
	}

	/* FIRST acts: the API table (no heap — GetProcAddress only),
	 * then the vmalloc band — claimed BEFORE any CRT/heap segment
	 * can grow into the free region above the (yet unmapped)
	 * guest-RAM window (load_exec_section's fopen below allocates;
	 * see the function comment). */
	resolve_api_table();
	create_boot_job();
	reserve_vmalloc_band();

	/* M3.4: uml_nt_exec=<file> names the guest ELF the kernel-side
	 * loader will run (the launcher reads it, the kernel parses —
	 * the file path itself never crosses into kernel code). */
	for (int ai = 2; ai < argc; ai++) {
		const char *a = argv[ai];
		const char *pfx = "uml_nt_exec=";

		if (strncmp(a, pfx, strlen(pfx)) == 0)
			exec_sec = load_exec_section(a + strlen(pfx),
						     &exec_size);
	}
	if (exec_sec != NULL)
		fprintf(stderr, "[launcher] exec image: %llu bytes\n",
			exec_size);

	/* console handles travel to the kernel (early console, D9;
	 * M3.6 adds stdin for the console reader thread). */
	std_out = GetStdHandle(STD_OUTPUT_HANDLE);
	std_err = GetStdHandle(STD_ERROR_HANDLE);

	/* Section + shadow first: map_elf mirrors the loaded image into
	 * the shadow (guest RAM backing for image pages). */
	section = create_physmem_section(DEFAULT_PHYSMEM, &physmem_base);
	image_base = map_elf(argv[1], &entry, &img_base, &img_size);
	fprintf(stderr, "[launcher] image mapped at %p [%llu KiB], "
			"entry=0x%llx; physmem section %llu MiB "
			"(shadow %p)\n", image_base,
		(unsigned long long)img_size >> 10,
		(unsigned long long)entry, DEFAULT_PHYSMEM >> 20,
		physmem_base);

	/* Fresh stack; everything the kernel reads at boot sits at its
	 * top: strings, argv/envp arrays, boot_info, then the single
	 * pointer slot [rsp] _start consumes. */
	stack = VirtualAlloc(NULL, KERNEL_STACK_SIZE, MEM_RESERVE |
			     MEM_COMMIT, PAGE_READWRITE);
	if (stack == NULL)
		die("VirtualAlloc (kernel stack)", GetLastError());
	top = (uintptr_t)stack + KERNEL_STACK_SIZE;

	cur = top;
#define PUSH_BYTES(n) ((cur -= ((n) + 15ULL) & ~15ULL))
#define PUSH_PTR(n)   ((cur -= (n) * sizeof(void *)))

	/* kernel argv: argv[0]="vmlinux", earlyprintk (boot console →
	 * um_early_printk → NtWriteFile — the only console until the
	 * channel drivers return at M3), lpj= (D19: the alarm is
	 * pending-only — no async tick interrupts a tight loop, so
	 * calibrate_delay would hang forever waiting for jiffies; pin
	 * the native-measured value and skip calibration), then the
	 * UML args; env is a minimal PATH (get_top_address scans env
	 * strings upstream). */
	{
		/* UML_NT_NO_EARLYPRINTK=1 (host env): drop the earlyprintk
		 * arg so a quiet home boot shows only the console driver
		 * output (pair with kernel loglevel=0 + 2>nul). CI never
		 * sets it — the default argv is byte-identical. */
		int no_early = getenv("UML_NT_NO_EARLYPRINTK") != NULL;
		int n = nargs > 60 ? 60 : nargs;
		size_t need = strlen("vmlinux") + 1 +
			      (no_early ? 0 : strlen("earlyprintk") + 1) +
			      strlen(UML_NT_LPJ) + 1 +
			      strlen("PATH=C:\\Windows\\System32") + 1;
		int ni;

		/* fix dd5531e: the generic packer copies the USER args
		 * into the packed block too (the old code kept the
		 * launcher's-stack pointers) — their bytes were never
		 * in `need` and the push overflowed (M3 segfault,
		 * run 37043758107). Count them. */
		for (ni = 0; ni < n; ni++)
			need += strlen(argv[2 + ni]) + 1;
		char *strs2;
		char *w;

		kargv[0] = "vmlinux";
		kargv[1] = no_early ? UML_NT_LPJ : "earlyprintk";
		kargv[2] = no_early ? NULL : UML_NT_LPJ;
		if (no_early) {
			for (i = 0; i < (size_t)n; i++)
				kargv[2 + i] = argv[2 + i];
			kargv[2 + n] = NULL;
		} else {
			for (i = 0; i < (size_t)n; i++)
				kargv[3 + i] = argv[2 + i];
			kargv[3 + n] = NULL;
		}
		kenv[0] = "PATH=C:\\Windows\\System32";
		kenv[1] = NULL;

		strs2 = (char *)PUSH_BYTES(need);
		w = strs2;
		/* pack argv strings up to (and including) the first NULL,
		 * then the one env string — pointers rewritten below */
		{
			char *cur2 = w;
			int ai;
			for (ai = 0; kargv[ai]; ai++) {
				size_t l = strlen(kargv[ai]) + 1;
				memcpy(cur2, kargv[ai], l);
				cur2 += l;
			}
			memcpy(cur2, kenv[0], strlen(kenv[0]) + 1);
		}
		kargv[0] = w = strs2;
		for (i = 1; kargv[i]; i++) {
			w += strlen(w) + 1;
			kargv[i] = w;
		}
		w += strlen(w) + 1;
		kenv[0] = w;
		nargs = n + 1 + (no_early ? 0 : 1); /* lpj (+earlyprintk) */
	}

	kargv_p = (char **)PUSH_PTR(63 + 1);
	memcpy(kargv_p, kargv, sizeof(kargv));
	kenv_p = (char **)PUSH_PTR(4);
	memcpy(kenv_p, kenv, sizeof(kenv));

	bi = (struct uml_boot_info *)PUSH_BYTES(sizeof(*bi));
	bi->magic = UML_BOOT_MAGIC;
	bi->version = UML_BOOT_VERSION;
	bi->api = &g_api;
	bi->physmem_section = section;
	bi->physmem_base = physmem_base;
	bi->physmem_size = DEFAULT_PHYSMEM;
	bi->image_base = (void *)(uintptr_t)img_base;
	bi->image_size = img_size;
	bi->stdio_out = std_out;
	bi->stdio_err = std_err;
	bi->stdio_in = GetStdHandle(STD_INPUT_HANDLE);
	bi->argc = nargs + 1; /* argv[0] + args (earlyprintk unless env-off) */
	bi->argv = kargv_p;
	bi->envp = kenv_p;
	bi->exec_section = exec_sec;
	bi->exec_size = exec_size;
	bi->job_object = g_job; /* v4: the kernel joins its spawns */
	/* Raw console: drop ENABLE_PROCESSED_INPUT so Ctrl-C is a 0x03
	 * byte the guest tty turns into SIGINT — the processed mode
	 * would let Windows swallow the key (and with it any chance
	 * the guest sees it); Shelley's 100-real-alpine freeze asks
	 * the interrupt to REACH the guest, not the host. */
	{
		HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
		DWORD m;

		if (in != INVALID_HANDLE_VALUE && GetConsoleMode(in, &m))
			SetConsoleMode(in,
				       m & ~(DWORD)ENABLE_PROCESSED_INPUT);
	}

	/* The slot _start reads: [rsp] = boot_info pointer. Keep rsp
	 * 16-aligned here; _start bumps by 8 to mimic call alignment. */
	cur -= 16;
	*(struct uml_boot_info **)cur = bi;

	fprintf(stderr, "[launcher] jumping to kernel: entry=0x%llx "
			"rsp=0x%llx\n", (unsigned long long)entry,
		(unsigned long long)cur);
	fflush(stderr);

#ifdef __x86_64__
	{
		uintptr_t e = (uintptr_t)entry, s = cur;

		__asm__ volatile(
			"movq %0, %%rsp\n\t"
			"jmp *%1\n\t"
			: : "r"(s), "r"(e) : "memory");
	}
#else
	fprintf(stderr, "launcher: x86_64 only\n");
	return 2;
#endif
}
