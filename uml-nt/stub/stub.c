/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stub.c — uml-nt stub process (M3, per-VMA views).
 *
 * Upstream analogue: arch/um/kernel/skas/stub.c (+ stub_exe.c loader) —
 * the code that runs "on behalf of" guest userland inside a process the
 * UML kernel controls. On Linux that stub is a raw blob execveat'd from
 * a memfd, talking futex+socket. On NT (D3/D6) it is a real PE process:
 *
 *   1. Bootstrap: CreateProcess(suspended, inherit) with the stub_data
 *      section handle value on the command line; the kernel creates
 *      every shared handle inheritable, so the values are valid here
 *      as-is. stub_data maps at the FIXED va 0x10000000 — below the
 *      guest span — so no untyped NT allocation ever lands inside the
 *      guest VA range (empirically: an untyped MapViewOfFile picked
 *      0x6926f471, M2; MapViewOfFileEx into a MEM_RESERVE span fails
 *      with 487 and re-reserving around a view fails too, M3.3 —
 *      reservation is not usable, fixed placement is).
 *   2. Address space = per-VMA views (M3 model): the stub publishes
 *      CMD_INIT and the kernel streams UNMAP/MAP/PROTECT ops; the
 *      stub applies each and reports PROT_DONE. On ACTION_NONE it
 *      jumps to the guest entry with the kernel-provided init_regs
 *      (fork hands the child the parent's snapshot with rax = 0).
 *   3. Guest code runs natively. Every guest `syscall` instruction
 *      was patched to ud2 (0F 0B) by the kernel (central patch in the
 *      shared physmem section). The VEH catches the resulting
 *      STATUS_ILLEGAL_INSTRUCTION, snapshots the GP regs, publishes
 *      the request, waits for the kernel answer, folds the retval
 *      in, and resumes past the ud2.
 *   4. Guest page faults: the same VEH catches STATUS_ACCESS_VIOLATION
 *      from guest code, publishes fault_addr/type, and the kernel
 *      answers with an action chain (PROTECT/MAP/UNMAP — the COW
 *      run-copy itself is kernel-side, through its own flat view).
 *      Fault resume replays the faulting instruction verbatim (rip
 *      UNCHANGED, every register restored — the instruction's live
 *      state e.g. rax must survive); syscall resume advances rip by 2
 *      and puts retval in rax.
 *   5. Exit/halt/kill: the stub parks (Sleep forever) and the KERNEL
 *      terminates it — ExitProcess from a VEH frame lies about the
 *      exit code (0xC000013D, M2.1 CI).
 *
 * VEH resume semantics (M0/S1 4/4): modify the CONTEXT Windows hands
 * us and return EXCEPTION_CONTINUE_EXECUTION; RIP redirect + reg
 * writes stick.
 *
 * This is PE-land code: windows.h + ntdll imports are fine (D9 keeps
 * only the kernel ELF free of that).
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kernel/overlay/arch/um/include/shared/stub_nt.h"

/* Fixed stub_data placement: BELOW the guest span, mapped before
 * anything else — see the bootstrap comment. */
#define STUB_DATA_VA 0x10000000ULL

static struct uml_nt_stub_data *d;
static HANDLE evt_in, evt_out; /* stub->kernel, kernel->stub */
static HANDLE phys_sec; /* physmem section (per-VMA views, do_action) */

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

/* D18 (S4c2): guest TLS base. Windows does not preserve a user-set
 * FS base across ANY kernel transition — scheduling AND the
 * EXCEPTION_CONTINUE_EXECUTION context restore (the x64 CONTEXT
 * carries the FS selector, not the base; KeContextToKernelMode
 * reloads it from the flat GDT → 0. The FSGSBASE probe's
 * "VEH-preserved yes" only measured INSIDE the handler). So the base
 * published by arch_prctl(ARCH_SET_FS) is applied by a TRAMPOLINE
 * that runs AFTER the restore: the VEH redirects rip to it, it
 * wrfsbase's and jumps to the real target. The trampolines touch
 * NOTHING but r11 (and globals): the first S4c2a version pushed the
 * scratch on the guest stack and the stub died STATUS_STACK_OVERFLOW
 * (0xC00000FD) before the guest ran a single instruction. Upstream
 * never does any of this: Linux keeps the base in the task regs
 * across the ptrace round-trip. */
static volatile unsigned long long fs_tramp_base, fs_tramp_target,
	fs_save_r11;

/* D18 CPUID gate (Shelley's ARCHITECTURE.md 44d710e note): wrfsbase
 * #UDs on a CPU without FSGSBASE — the S4c probe measured the runner
 * (leaf 7 ebx bit 0 = yes) but the stub must not assume. Without the
 * feature the TLS path is simply not armed: resumes stay the plain
 * rip+2, fs-prefixed faults fall through to the guest's fault path. */
static int have_fsgsbase;

static void fsgsbase_detect(void)
{
	unsigned int a = 0, b = 0, c = 0, d = 0;

	__asm__ volatile ("cpuid"
			  : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
			  : "a" (7), "c" (0));
	have_fsgsbase = (b & 1) ? 1 : 0;
}

/* syscall resume: rcx/r11 are clobbered by the syscall contract —
 * r11 is free scratch, no register restoration needed. */
__attribute__((naked)) static void fs_trampoline_sys(void)
{
	__asm__ volatile (
		"movq	fs_tramp_base(%rip), %r11\n\t"
		"wrfsbase %r11\n\t"
		"movq	fs_tramp_target(%rip), %r11\n\t"
		"jmp	*%r11\n\t"
	);
}

/* fault repair: every guest register is live mid-instruction — r11
 * serves as scratch and is restored from the snapshot the VEH took;
 * the jump target is memory-indirect so no other register is used. */
__attribute__((naked)) static void fs_trampoline_fault(void)
{
	__asm__ volatile (
		"movq	fs_tramp_base(%rip), %r11\n\t"
		"wrfsbase %r11\n\t"
		"movq	fs_save_r11(%rip), %r11\n\t"
		"jmp	*fs_tramp_target(%rip)\n\t"
	);
}

/* FILE_MAP_* bits for a view with `prot` protection. FILE_MAP_EXECUTE
 * (0x20) must ride along on every executable view (M2.1 pitfall 9:
 * without it the first fetch dies with a DEP AV, info[0]=8).
 *
 * Hazard-3 slice: EVERY view maps with full RWX access regardless of
 * the requested page protection, and the protection is applied (down)
 * with VirtualProtect right after the map. Native Windows refuses to
 * RAISE a page protection past the view's map access — a view mapped
 * FILE_MAP_READ (the old map_access(READONLY)) can never be
 * VirtualProtect'ed PAGE_READWRITE later, so a fault-repair PROTECT
 * on a read-only piece (COW split pre/post, fork re-protect) failed
 * silently on the native runner: the guest's retry faulted, the stub
 * died 0xC00000FD. Wine allows the raise — that is why the wine smoke
 * stayed green. RWX views are raisable in both directions; the guest
 * never runs inside the map→protect window (it is parked in the
 * dispatch until the action chain completes). */
static ULONG map_access(unsigned prot)
{
	(void)prot;
	return 0x26u; /* FILE_MAP_EXECUTE | READ | WRITE */
}

/* Execute one ACTION_* against this stub's views. Returns 1 = ok,
 * 0 = failed (the kernel sees it and kills us loudly — a silent
 * resume would loop the guest fault forever). */
static int do_action(void)
{
	ULONG old_prot;

	switch (d->action) {
	case UML_STUB_ACTION_PROT: {
		void *page = (void *)(uintptr_t)d->map_va;

		if (!VirtualProtect(page, (SIZE_T)d->map_len, d->prot,
				    &old_prot)) {
			fprintf(stderr, "stub: VirtualProtect(%p, %#x) "
				"failed (%lu)\n", page,
				(unsigned)d->prot, GetLastError());
			return 0;
		}
		return 1;
	}
	case UML_STUB_ACTION_MAP: {
		void *base = MapViewOfFileEx(phys_sec,
					     map_access(d->map_prot),
					     (DWORD)((d->map_off >> 32) &
						     0xFFFFFFFFu),
					     (DWORD)(d->map_off &
						     0xFFFFFFFFu),
					     (SIZE_T)d->map_len,
					     (PVOID)(uintptr_t)d->map_va);

		if (base == NULL) {
			fprintf(stderr, "stub: MapViewOfFileEx(va=%#llx "
				"len=%#llx off=%#llx) failed (%lu)\n",
				d->map_va, d->map_len, d->map_off,
				GetLastError());
			return 0;
		}
		/* The view came in RWX (raisable, see map_access): drop
		 * the page protection to what the kernel asked for. A
		 * later PROTECT op can move it either way. */
		if (!VirtualProtect(base, (SIZE_T)d->map_len, d->map_prot,
				    &old_prot)) {
			fprintf(stderr, "stub: map VirtualProtect(%p, "
				"%#x) failed (%lu)\n", base,
				(unsigned)d->map_prot, GetLastError());
			return 0;
		}
		return 1;
	}
	case UML_STUB_ACTION_UNMAP:
		/* UnmapViewOfFile releases a WHOLE view — the kernel
		 * plans exact view ranges only (fault.h geometry). */
		if (!UnmapViewOfFile((PVOID)(uintptr_t)d->map_va)) {
			fprintf(stderr, "stub: UnmapViewOfFile(%#llx) "
				"failed (%lu)\n", d->map_va,
				GetLastError());
			return 0;
		}
		return 1;
	default:
		fprintf(stderr, "stub: unknown action %u\n",
			(unsigned)d->action);
		return 0;
	}
}

/* The request → answer → action-chain loop shared by the VEH handler
 * and the pre-entry INIT stream. */
static void action_chain(void)
{
	wait_answer();
	for (;;) {
		if (d->action == UML_STUB_ACTION_KILL)
			park_forever();
		if (d->action != UML_STUB_ACTION_NONE) {
			d->retval = do_action() ? 1 : 0;
			d->err = d->retval ? 0 : 1;
			publish(UML_STUB_CMD_PROT_DONE);
			wait_answer();
			continue; /* answer: NONE (resume) or next op */
		}
		break; /* ACTION_NONE: handled */
	}
}

static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep)
{
	EXCEPTION_RECORD *er = ep->ExceptionRecord;
	CONTEXT *c = ep->ContextRecord;
	int is_syscall = (er->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION);
	int is_fault = (er->ExceptionCode == STATUS_ACCESS_VIOLATION);

	if (!is_syscall && !is_fault)
		return EXCEPTION_CONTINUE_SEARCH;

	/* Only traps from the guest VA span belong to us (guest code
	 * executes in per-VMA views inside [ram_base, ram_base+size)). */
	if ((uintptr_t)c->Rip < (uintptr_t)d->ram_base ||
	    (uintptr_t)c->Rip >=
		    (uintptr_t)d->ram_base + d->ram_size)
		return EXCEPTION_CONTINUE_SEARCH;

	/* D18 fast path: an fs-prefixed guest access that faults below
	 * the guest span means the TLS base was wiped while the guest
	 * ran. Redirect through the fault trampoline (which re-applies
	 * the base AFTER the context restore) back to the SAME rip —
	 * the instruction re-executes with the base live. A genuine
	 * guest null/low deref is not fs-prefixed and keeps its
	 * SIGSEGV round-trip. */
	if (is_fault && d->fs_base != 0 && have_fsgsbase &&
	    (uintptr_t)er->ExceptionInformation[1] <
		    (uintptr_t)d->ram_base &&
	    *(const unsigned char *)(uintptr_t)c->Rip == 0x64 /* fs: */) {
		fs_tramp_base = d->fs_base;
		fs_save_r11 = c->R11;
		fs_tramp_target = c->Rip;
		c->Rip = (DWORD64)(uintptr_t)&fs_trampoline_fault;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

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
		/* Fault round-trip: ExceptionInformation[0] = access
		 * class (0 read / 1 write / 8 DEP-execute), [1] = the
		 * faulting VA. */
		d->fault_addr = (unsigned long long)er->ExceptionInformation[1];
		d->fault_type = (u32_nt)er->ExceptionInformation[0];
		publish(UML_STUB_CMD_FAULT);
	}

	action_chain();

	/* Kernel answered. Syscall: retval in rax, resume past the ud2.
	 * Fault: every register verbatim, rip unchanged — the faulting
	 * instruction re-executes on the now-fixed view. */
	gp_to_context(c, &d->regs);
	if (is_syscall) {
		c->Rax = (DWORD64)d->retval;
		/* D18: with a TLS base live, resume THROUGH the
		 * trampoline — the context restore on the way out has
		 * already zeroed the base, and rcx/r11 are clobbered
		 * by the syscall contract anyway (the trampoline uses
		 * r11 as scratch and touches nothing else). Without
		 * TLS this stays the plain rip+2 resume the
		 * M1.9–M3.7 gates have always run. */
		if (d->fs_base != 0 && have_fsgsbase) {
			fs_tramp_base = d->fs_base;
			fs_tramp_target = d->regs.rip + 2; /* past ud2 */
			c->Rip = (DWORD64)(uintptr_t)&fs_trampoline_sys;
		} else {
			c->Rip = d->regs.rip + 2; /* past 0F 0B (ud2) */
		}
	}
	MemoryBarrier();
	InterlockedExchange64((volatile LONG64 *)&d->done_seq, d->req_seq);

	if (is_syscall && d->halt)
		park_forever(); /* guest exit(): kernel terminates us */

	return EXCEPTION_CONTINUE_EXECUTION;
}

/* ---- guest entry ---------------------------------------------------- */

/* Jump to the guest: apply the init register snapshot, switch to the
 * guest stack, jump to the guest rip. Naked: no prologue may touch
 * either stack. MS x64 ABI: rcx = &init_regs, rdx = stack_va,
 * r8 = entry_va. rflags is not restored (POC: the fork/begin states
 * run with a fresh flags set — sigreturn-grade fidelity is M4). */
static void jump_to_guest(struct uml_nt_gp_regs *ir,
			  unsigned long long stack_va,
			  unsigned long long entry_va)
	__attribute__((naked));

static void jump_to_guest(struct uml_nt_gp_regs *ir,
			  unsigned long long stack_va,
			  unsigned long long entry_va)
{
	__asm__ volatile(
		"movq	%r8, %r15\n\t"	/* entry, saved first */
		"movq	%rdx, %rsp\n\t"	/* switch stack now */
		"movq	0(%rcx), %rax\n\t"
		"movq	16(%rcx), %rdx\n\t"
		"movq	24(%rcx), %rbx\n\t"
		"movq	40(%rcx), %rbp\n\t"
		"movq	48(%rcx), %rsi\n\t"
		"movq	56(%rcx), %rdi\n\t"
		"movq	64(%rcx), %r8\n\t"
		"movq	72(%rcx), %r9\n\t"
		"movq	80(%rcx), %r10\n\t"
		"movq	88(%rcx), %r11\n\t"
		"movq	96(%rcx), %r12\n\t"
		"movq	104(%rcx), %r13\n\t"
		"movq	112(%rcx), %r14\n\t"
		"movq	8(%rcx), %rcx\n\t"
		"jmp	*%r15\n\t"
	);
	(void)ir;
	(void)stack_va;
	(void)entry_va;
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

	phys_sec = (HANDLE)(uintptr_t)phys_h;
	evt_in = (HANDLE)(uintptr_t)in_h;
	evt_out = (HANDLE)(uintptr_t)out_h;

	/* stub_data at the FIXED va (below the guest span) — the NT
	 * allocator never places anything inside the guest range after
	 * this point: every later map is a fixed-va MAP op. */
	d = MapViewOfFileEx((HANDLE)(uintptr_t)data_h, FILE_MAP_ALL_ACCESS,
			    0, 0, UML_STUB_SECTION_SIZE,
			    (PVOID)(uintptr_t)STUB_DATA_VA);
	if (d == NULL)
		die("MapViewOfFileEx(stub_data @fixed va)", GetLastError());
	if (d->magic != UML_STUB_MAGIC || d->version != UML_STUB_VERSION) {
		fprintf(stderr, "stub: bad handshake magic=%08x ver=%u\n",
			d->magic, d->version);
		ExitProcess(111);
	}

	if (!AddVectoredExceptionHandler(1, veh_handler))
		die("AddVectoredExceptionHandler", GetLastError());

	fsgsbase_detect();

	/* M3 model: publish INIT, stream the kernel's per-VMA map plan
	 * (action_chain applies ops until ACTION_NONE), then jump. */
	publish(UML_STUB_CMD_INIT);
	action_chain();

	jump_to_guest(&d->init_regs, d->stack_va, d->entry_va);
	/* not reached */
	ExitProcess(122);
}
