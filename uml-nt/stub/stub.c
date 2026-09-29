/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub.c — uml-nt stub process (M3).
 *
 * Upstream analogue: arch/um/kernel/skas/stub.c (+ stub_exe.c loader) —
 * the code that runs "on behalf of" guest userland inside a process the
 * UML kernel controls. On Linux that stub is a raw blob execveat'd from
 * a memfd, talking futex+socket. On NT (D3/D6) it is a real PE process:
 *
 *   1. Bootstrap (S5 pattern): CreateProcess(suspended, inherit) with
 *      the stub_data section handle value on the command line; the
 *      kernel duplicates... no — it creates every shared handle
 *      inheritable, so the values are valid here as-is. Map the
 *      section, validate the bootstrap block the kernel wrote before
 *      ResumeThread, map the physmem section, register VEH, signal
 *      ready by jumping to the guest entry.
 *   2. Guest code runs natively. Every guest `syscall` instruction was
 *      patched to ud2 (0F 0B) by the kernel (central patch in the
 *      shared physmem section). The VEH handler below catches the
 *      resulting STATUS_ILLEGAL_INSTRUCTION, snapshots the GP regs,
 *      publishes the request, waits for the kernel answer, folds the
 *      return value in, and resumes past the ud2.
 *   3. Guest page faults (M3.1): the same VEH catches
 *      STATUS_ACCESS_VIOLATION from guest code, publishes the fault
 *      (address + access class), and the kernel answers with an
 *      ACTION: PROTECT (the stub VirtualProtects the page in its own
 *      view — upstream lets the stub run mmap ops the same way) or
 *      KILL (wild pointer; the stub parks and the kernel terminates
 *      it — M2.2 parity, ExitProcess from a VEH frame lies about the
 *      exit code). The guest then re-executes the faulting
 *      instruction: rip stays UNCHANGED and every register is
 *      restored verbatim — the faulting instruction's live state
 *      (e.g. rax) must survive the round-trip.
 *
 * VEH resume semantics (M0/S1 4/4): modify the CONTEXT Windows hands
 * us and return EXCEPTION_CONTINUE_EXECUTION; RIP redirect + reg
 * writes stick. Syscall resume advances rip past the ud2; fault
 * resume replays the faulting instruction verbatim.
 *
 * This is PE-land code: windows.h + ntdll imports are fine (D9 keeps
 * only the kernel ELF free of that).
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kernel/overlay/arch/um/include/shared/stub_nt.h"

static struct uml_nt_stub_data *d;
static unsigned char *ram; /* physmem view base == UML_STUB_RAM_BASE */
static HANDLE evt_in, evt_out; /* stub->kernel, kernel->stub */

static void die(const char *what, DWORD err)
{
	fprintf(stderr, "stub: %s failed (%lu)\n", what,
		(unsigned long)err);
	ExitProcess(120);
}

/* ---- VEH: the syscall/fault interception point --------------------- */

static int gp_from_context(const CONTEXT *c, struct uml_nt_gp_regs *g)
{
	g->rax = c->Rax; g->rcx = c->Rcx; g->rdx = c->Rdx;
	g->rbx = c->Rbx; g->rsp = c->Rsp; g->rbp = c->Rbp;
	g->rsi = c->Rsi; g->rdi = c->Rdi;
	g->r8 = c->R8;  g->r9 = c->R9;  g->r10 = c->R10; g->r11 = c->R11;
	g->r12 = c->R12; g->r13 = c->R13; g->r14 = c->R14; g->r15 = c->R15;
	g->rip = c->Rip; g->rflags = c->EFlags;
	return 0;
}

/* Apply the (kernel-audited) register snapshot verbatim; the caller
 * fixes rax/rip per trap class. Fault resume depends on rax being
 * restored exactly — the faulting instruction's live state. */
static void gp_to_context(CONTEXT *c, const struct uml_nt_gp_regs *g)
{
	c->Rax = g->rax;
	/* rcx/r11 are syscall-clobbered by contract; the kernel may
	 * have written them via regs — apply the full set to be honest. */
	c->Rcx = g->rcx; c->Rdx = g->rdx; c->Rbx = g->rbx;
	c->Rsp = g->rsp; c->Rbp = g->rbp; c->Rsi = g->rsi; c->Rdi = g->rdi;
	c->R8 = g->r8; c->R9 = g->r9; c->R10 = g->r10; c->R11 = g->r11;
	c->R12 = g->r12; c->R13 = g->r13; c->R14 = g->r14; c->R15 = g->r15;
	c->EFlags = (DWORD)g->rflags;
	c->Rip = g->rip;
}

static void publish(unsigned cmd)
{
	d->cmd = cmd;
	MemoryBarrier();
	InterlockedExchange64((volatile LONG64 *)&d->req_seq,
			      d->done_seq + 1);
	SetEvent(evt_in);
}

static void wait_answer(void)
{
	if (WaitForSingleObject(evt_out, INFINITE) != WAIT_OBJECT_0)
		ExitProcess(121);
}

static void park_forever(void)
{
	/* The kernel owns the kill (upstream parity: it terminates the
	 * stub after reading the exit code). ExitProcess from inside a
	 * VEH frame produced a bogus native exit code (0xC000013D,
	 * M2.1 CI) — never call it from here on the normal path. */
	for (;;)
		Sleep(INFINITE);
}

static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep)
{
	EXCEPTION_RECORD *er = ep->ExceptionRecord;
	CONTEXT *c = ep->ContextRecord;
	int is_syscall = (er->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION);
	int is_fault = (er->ExceptionCode == STATUS_ACCESS_VIOLATION);

	if (!is_syscall && !is_fault)
		return EXCEPTION_CONTINUE_SEARCH;

	/* Only traps from the guest RAM view belong to us. */
	if ((uintptr_t)c->Rip < (uintptr_t)ram ||
	    (uintptr_t)c->Rip >= (uintptr_t)ram + d->ram_size)
		return EXCEPTION_CONTINUE_SEARCH;

	gp_from_context(c, &d->regs);
	if (is_syscall) {
		d->args[0] = d->regs.rdi; /* guest syscall ABI */
		d->args[1] = d->regs.rsi;
		d->args[2] = d->regs.rdx;
		d->args[3] = d->regs.r10;
		d->args[4] = d->regs.r8;
		d->args[5] = d->regs.r9;
		/* syscall nr in rax: the kernel dispatches on regs.rax. */
		publish(UML_STUB_CMD_SYSCALL);
	} else {
		/* M3.1 fault round-trip: ExceptionInformation[0] =
		 * access class (0 read / 1 write / 8 DEP-execute),
		 * [1] = faulting VA. */
		d->fault_addr = (unsigned long long)er->ExceptionInformation[1];
		d->fault_type = (u32_nt)er->ExceptionInformation[0];
		publish(UML_STUB_CMD_FAULT);
	}

	wait_answer();

	/* Execute the kernel's action chain. PROTECT reports back
	 * (a failed protect would re-fault forever — the kernel must
	 * see it and kill us loudly instead, pitfall "loud fails"). */
	for (;;) {
		if (d->action == UML_STUB_ACTION_PROT) {
			void *page = (void *)(uintptr_t)
				(d->fault_addr & ~(uintptr_t)0xFFF);
			ULONG old_prot;
			BOOL ok;

			ok = VirtualProtect(page, 4096, d->prot, &old_prot);
			if (!ok)
				fprintf(stderr,
					"stub: VirtualProtect(%p, %#x) "
					"failed (%lu)\n", page,
					(unsigned)d->prot, GetLastError());
			d->retval = ok ? 1 : 0;
			d->err = ok ? 0 : 1;
			publish(UML_STUB_CMD_PROT_DONE);
			wait_answer();
			continue; /* answer is NONE (resume) or KILL */
		}
		if (d->action == UML_STUB_ACTION_KILL)
			park_forever();
		break; /* ACTION_NONE: handled — resume the guest */
	}

	/* Kernel answered. Syscall: retval in rax, resume past the ud2.
	 * Fault: every register verbatim, rip unchanged — the faulting
	 * instruction re-executes on the now-fixed page. */
	gp_to_context(c, &d->regs);
	if (is_syscall) {
		c->Rax = (DWORD64)d->retval;
		c->Rip = d->regs.rip + 2; /* past 0F 0B (ud2) */
	}
	MemoryBarrier();
	InterlockedExchange64((volatile LONG64 *)&d->done_seq, d->req_seq);

	if (is_syscall && d->halt)
		park_forever(); /* guest exit(): kernel terminates us */

	return EXCEPTION_CONTINUE_EXECUTION;
}

/* ---- bootstrap ------------------------------------------------------ */

static unsigned long long parse_ull(const char *s)
{
	return strtoull(s, NULL, 0);
}

int main(int argc, char **argv)
{
	unsigned long long data_h = 0, phys_h = 0, in_h = 0, out_h = 0;
	int i;
	HANDLE data_sec, phys_sec;
	MEMORY_BASIC_INFORMATION mbi;

	for (i = 1; i + 1 < argc; i += 2) {
		if (!strcmp(argv[i], "--data"))
			data_h = parse_ull(argv[i + 1]);
		else if (!strcmp(argv[i], "--phys"))
			phys_h = parse_ull(argv[i + 1]);
		else if (!strcmp(argv[i], "--evt-in"))
			in_h = parse_ull(argv[i + 1]);
		else if (!strcmp(argv[i], "--evt-out"))
			out_h = parse_ull(argv[i + 1]);
	}
	if (!data_h || !phys_h || !in_h || !out_h) {
		fprintf(stderr, "usage: stub.exe --data H --phys H "
			"--evt-in H --evt-out H\n");
		return 2;
	}

	data_sec = (HANDLE)(uintptr_t)data_h;
	phys_sec = (HANDLE)(uintptr_t)phys_h;
	evt_in = (HANDLE)(uintptr_t)in_h;
	evt_out = (HANDLE)(uintptr_t)out_h;

	d = MapViewOfFile(data_sec, FILE_MAP_ALL_ACCESS, 0, 0,
			  UML_STUB_SECTION_SIZE);
	if (d == NULL)
		die("MapViewOfFile(stub_data)", GetLastError());
	if (d->magic != UML_STUB_MAGIC || d->version != UML_STUB_VERSION) {
		fprintf(stderr, "stub: bad handshake magic=%08x ver=%u\n",
			d->magic, d->version);
		ExitProcess(111);
	}

	/* FILE_MAP_EXECUTE (0x20) is mandatory: FILE_MAP_ALL_ACCESS alone
	 * yields a non-executable view — first fetch dies with a DEP
	 * AV (info[0]=8, found under wine). */
	ram = MapViewOfFileEx(phys_sec, FILE_MAP_ALL_ACCESS | 0x20, 0, 0, 0,
			      (PVOID)(uintptr_t)UML_STUB_RAM_BASE);
	if (ram == NULL)
		die("MapViewOfFileEx(physmem @fixed base)", GetLastError());
	if (!VirtualQuery(ram, &mbi, sizeof(mbi)))
		die("VirtualQuery", GetLastError());

	if (!AddVectoredExceptionHandler(1, veh_handler))
		die("AddVectoredExceptionHandler", GetLastError());

	/* Bootstrap v2 (M3.1): seed guard pages NOACCESS before the
	 * guest runs — the kernel picks the offsets and answers the
	 * resulting faults. In the M3.2 VMA model this grows into real
	 * demand mapping (guest VA starts unmapped, not NOACCESS). */
	for (i = 0; i < 2; i++) {
		ULONG old_prot;

		if (d->guard_off[i] == 0)
			continue;
		if (!VirtualProtect(ram + d->guard_off[i], 4096,
				    PAGE_NOACCESS, &old_prot))
			die("VirtualProtect(guard page)", GetLastError());
	}

	/* Guest stack lives in the physmem view (below the init image);
	 * rsp/entry from the bootstrap block. No argv — the static init
	 * takes none (M3 wires real execve machinery). */
	{
		unsigned long long entry =
			UML_STUB_RAM_BASE + d->entry_off;
		unsigned long long sp = UML_STUB_RAM_BASE + d->stack_off;

		__asm__ volatile(
			"movq %0, %%rsp\n\t"
			"xorl %%ebp, %%ebp\n\t"
			"jmp *%1\n\t"
			: : "r"(sp), "r"(entry) : "memory");
	}
	/* not reached */
	ExitProcess(122);
}
