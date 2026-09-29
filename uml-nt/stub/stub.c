/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub.c — uml-nt stub process (M2).
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
 *   3. Guest exit: same round-trip with cmd=EXIT, then ExitProcess —
 *      the kernel reads the exit code from the process handle.
 *
 * VEH resume semantics (M0/S1 4/4): modify the CONTEXT Windows hands
 * us and return EXCEPTION_CONTINUE_EXECUTION; RIP redirect + reg
 * writes stick. Here resume is the trivial in-frame case (rip += 2).
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

static void gp_to_context(CONTEXT *c, const struct uml_nt_gp_regs *g,
			  unsigned long long retval, int advance_rip)
{
	c->Rax = (DWORD64)retval; /* syscall return */
	/* rcx/r11 are syscall-clobbered by contract; kernel may have
	 * written them via regs — apply the full set to be honest. */
	c->Rcx = g->rcx; c->Rdx = g->rdx; c->Rbx = g->rbx;
	c->Rsp = g->rsp; c->Rbp = g->rbp; c->Rsi = g->rsi; c->Rdi = g->rdi;
	c->R8 = g->r8; c->R9 = g->r9; c->R10 = g->r10; c->R11 = g->r11;
	c->R12 = g->r12; c->R13 = g->r13; c->R14 = g->r14; c->R15 = g->r15;
	c->EFlags = (DWORD)g->rflags;
	if (advance_rip)
		c->Rip = g->rip + 2; /* past 0F 0B (ud2) */
	else
		c->Rip = g->rip;
}

static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep)
{
	EXCEPTION_RECORD *er = ep->ExceptionRecord;
	CONTEXT *c = ep->ContextRecord;

	if (er->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION &&
	    er->ExceptionCode != STATUS_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;

	/* Only traps from the guest RAM view belong to us. */
	if ((uintptr_t)c->Rip < (uintptr_t)ram ||
	    (uintptr_t)c->Rip >= (uintptr_t)ram + d->ram_size)
		return EXCEPTION_CONTINUE_SEARCH;

	gp_from_context(c, &d->regs);
	d->args[0] = d->regs.rdi; /* guest syscall ABI */
	d->args[1] = d->regs.rsi;
	d->args[2] = d->regs.rdx;
	d->args[3] = d->regs.r10;
	d->args[4] = d->regs.r8;
	d->args[5] = d->regs.r9;
	/* syscall nr in rax: let the kernel see it via regs. */
	d->cmd = UML_STUB_CMD_WRITE; /* provisional; kernel dispatches on rax */

	/* Publish + wait (auto-reset events, monotonic seq — see
	 * stub_nt.h; pitfall 4.4: the seq IS the dedupe). */
	MemoryBarrier();
	InterlockedExchange64((volatile LONG64 *)&d->req_seq,
			      d->done_seq + 1);
	SetEvent(evt_in);
	if (WaitForSingleObject(evt_out, INFINITE) != WAIT_OBJECT_0)
		ExitProcess(121);

	/* Kernel answered. Fold retval in and resume past the ud2. */
	gp_to_context(c, &d->regs, d->retval, 1);
	MemoryBarrier();
	InterlockedExchange64((volatile LONG64 *)&d->done_seq, d->req_seq);

	if (d->halt) {
		/* Guest exit(): the KERNEL owns the kill (upstream parity:
		 * kernel terminates the stub). Park forever — ExitProcess
		 * from inside a VEH frame gave a bogus native exit code
		 * (0xC000013D, M2.1 CI). */
		for (;;)
			Sleep(INFINITE);
	}

	if (er->ExceptionCode == STATUS_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH; /* M3: fault round-trip */
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
	fprintf(stderr, "[stub] data view %p\n", d);
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
	fprintf(stderr, "[stub] ram view %p (want 0x%llx), entry=0x%llx "
		"sp=0x%llx\n", ram, UML_STUB_RAM_BASE,
		UML_STUB_RAM_BASE + d->entry_off,
		UML_STUB_RAM_BASE + d->stack_off);
	if (!VirtualQuery(ram, &mbi, sizeof(mbi)))
		die("VirtualQuery", GetLastError());

	if (!AddVectoredExceptionHandler(1, veh_handler))
		die("AddVectoredExceptionHandler", GetLastError());

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
