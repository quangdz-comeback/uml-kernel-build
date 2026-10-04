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
#include <io.h>

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
	fs_save_r11, fs_tramp_eflags;

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
 * r11 is free scratch, but WHAT it holds still matters: it exits
 * every VEH dispatch into the CONTEXT Windows builds on the guest
 * stack, and the kernel pulls that slot back as fork-seed state
 * (the r15/entry-rip poison chain of M5.4 c3, caef34f). Leaving the
 * resume target in r11 (the pre-fix value) re-created the same
 * residue class one run later. Real hardware leaves RFLAGS in r11
 * across syscall — the VEH snapshot's EFlags IS that value, so
 * reload it here for exact parity (the S4c2a overflow bans pushing
 * on the guest stack, hence the third global). */
__attribute__((naked)) static void fs_trampoline_sys(void)
{
	__asm__ volatile (
		"movq	fs_tramp_base(%rip), %r11\n\t"
		"wrfsbase %r11\n\t"
		"movq	fs_tramp_eflags(%rip), %r11\n\t"
		"jmp	*fs_tramp_target(%rip)\n\t"
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

/* TF variant (stub_nt.h v10, the replay single-step): identical, but
 * TF rises right before the jump — a TF in the VEH context would
 * #DB on wrfsbase, inside the trampoline, before the guest store.
 * With TF set here, the first guest instruction (the replayed
 * store) executes and the #DB lands AFTER it: the handler re-arms
 * the page NOACCESS, so the NEXT writer (the reverter, if any) is
 * caught by the kernel's cowtrap. */
__attribute__((naked)) static void fs_trampoline_fault_tf(void)
{
	__asm__ volatile (
		"movq	fs_tramp_base(%rip), %r11\n\t"
		"wrfsbase %r11\n\t"
		"movq	fs_save_r11(%rip), %r11\n\t"
		"pushfq\n\t"
		"orq	$0x100, (%rsp)\n\t"
		"popfq\n\t"
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

/* D23 (a) verify: the protection the guest will actually fault on
 * must equal what the kernel asked. A silent mismatch = a writable
 * view over a COW-shared run (the fork re-protect window) with no
 * fault to catch the parent's write — the heap-trasher shape. The
 * region is uniform (one protect per op), so query the first page;
 * guard/nocache attribute bits do not change the fault verdict. */
static int verify_prot(void *base, ULONG want)
{
	MEMORY_BASIC_INFORMATION mb;
	ULONG have;

	if (!VirtualQuery(base, &mb, sizeof(mb))) {
		fprintf(stderr, "stub: verify VirtualQuery(%p) failed "
			"(%lu)\n", base, GetLastError());
		return 0;
	}
	have = mb.Protect & ~(ULONG)(PAGE_GUARD | PAGE_NOCACHE);
	if (have != want) {
		fprintf(stderr, "stub: verify va=%p want=%#lx have=%#lx "
			"(state %#x) — protect MISMATCH\n", base, want,
			have, (unsigned)mb.State);
		return 0;
	}
	return 1;
}

/* Execute one ACTION_* against this stub's views. Returns 1 = ok,
 * 0 = failed (the kernel sees it and kills us loudly — a silent
 * resume would loop the guest fault forever). */
static volatile LONG guest_read_site; /* 1=viewprobe 2=ss-got */


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
		/* viewprobe (stub_nt.h v9): the page is readable again
		 * — snapshot the kernel's chosen qword THROUGH this
		 * view so the kernel can compare it against the VMA
		 * table's run. A divergence here is the wrong-backed
		 * view itself. */
		if (d->viewprobe_addr != 0) {
			if (d->prot != 0 /* not NOACCESS */) {
				guest_read_site = 1;
				d->viewprobe_got =
					*(volatile unsigned long long *)
					(uintptr_t)d->viewprobe_addr;
				guest_read_site = 0;
			}
			d->viewprobe_addr = 0;
		}
		return verify_prot(page, d->prot);
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
		/* mapcanary (stub_nt.h v7): read the view's tail-8
		 * THROUGH the fresh mapping so the kernel can prove the
		 * view is backed by the VMA table's run (a stale-off
		 * MAP passes verify_prot and serves the wrong run —
		 * the lost-metadata-store shape). The kernel planted
		 * the nonce flat-side; a mismatch here names the op. */
		if (d->mapcanary != 0 && d->map_len >= 16)
			d->mapcanary_got = *(volatile unsigned long long *)
				((char *)base + d->map_len - 8);
		return verify_prot(base, d->map_prot);
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

/* An error-class exception the VEH does not own is about to kill the
 * stub (no SEH frame catches anything here): the kernel only sees the
 * exit code ("died silently"). Say where it happened, once — a static
 * buffer and one WriteFile, because the stack under us may be the
 * reason. */
static void report_unowned(const EXCEPTION_RECORD *er, const CONTEXT *c)
{
	static volatile LONG reported;
	static char line[512];
	MEMORY_BASIC_INFORMATION mbi;
	unsigned long long slot = 0, above = 0;
	uintptr_t sva = (uintptr_t)c->Rsp - 8;
	DWORD wrote;
	int n;

	if ((er->ExceptionCode & 0xC0000000u) != 0xC0000000u ||
	    InterlockedExchange(&reported, 1) != 0)
		return;
	/* The stub's own view of the qword just below rsp (a `ret` into
	 * a bad target popped it) — compared with the kernel's view of
	 * the same VA, it separates a real write from a stale view. */
	memset(&mbi, 0, sizeof(mbi));
	if (VirtualQuery((void *)sva, &mbi, sizeof(mbi)) == sizeof(mbi) &&
	    mbi.State == MEM_COMMIT &&
	    !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
	    sva + 16 <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize) {
		memcpy(&slot, (const void *)sva, 8);
		memcpy(&above, (const void *)(sva + 8), 8);
	}
	n = snprintf(line, sizeof(line),
		     "stub: UNOWNED exception %08lx rip=%llx rsp=%llx "
		     "op=%llu addr=%llx fs_base=%llx last_cmd=%u — "
		     "process dies; view [rsp-8]=%llx [rsp]=%llx "
		     "region base=%p alloc=%p size=%llx prot=%lx type=%lx\n",
		     (unsigned long)er->ExceptionCode,
		     (unsigned long long)c->Rip, (unsigned long long)c->Rsp,
		     er->NumberParameters > 0 ?
			     (unsigned long long)er->ExceptionInformation[0] : 0,
		     er->NumberParameters > 1 ?
			     (unsigned long long)er->ExceptionInformation[1] : 0,
		     (unsigned long long)d->fs_base, (unsigned)d->cmd,
		     slot, above, mbi.BaseAddress, mbi.AllocationBase,
		     (unsigned long long)mbi.RegionSize,
		     (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
	n = snprintf(line + (n > 0 ? n : 0),
		     sizeof(line) - (n > 0 ? n : 0),
		     " guest_read_site=%ld", (long)guest_read_site);
	if (n > 0)
		WriteFile(GetStdHandle(STD_ERROR_HANDLE), line,
			  (DWORD)(n < (int)sizeof(line) ? n :
				  (int)sizeof(line) - 1),
			  &wrote, NULL);
}

static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep)
{
	EXCEPTION_RECORD *er = ep->ExceptionRecord;
	CONTEXT *c = ep->ContextRecord;
	int is_syscall = (er->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION);
	int is_fault = (er->ExceptionCode == STATUS_ACCESS_VIOLATION);
	int verbatim;

	/* Replay single-step (stub_nt.h v10): the repaired store just
	 * executed; re-arm its page NOACCESS so the NEXT writer faults
	 * into the kernel's cowtrap. Pure stub-local: no publish. */
	if (er->ExceptionCode == STATUS_SINGLE_STEP && d->ss_page != 0) {
		/* The trampoline's popfq raises TF one instruction early:
		 * the first #DB lands after the trampoline's JUMP, with
		 * the store not yet executed (rip == fs_tramp_target).
		 * Re-arming there loops forever (NOACCESS -> fault ->
		 * repair -> TF -> #DB-after-jmp -> ... — referee
		 * 37201007185 died in exactly that loop). Keep TF and
		 * let the store run; the NEXT #DB (rip past the store)
		 * is the real one. */
		if ((unsigned long long)c->Rip == fs_tramp_target ||
		    ((unsigned long long)c->Rip >=
				(unsigned long long)(uintptr_t)
					&fs_trampoline_fault_tf &&
		     (unsigned long long)c->Rip <
				(unsigned long long)(uintptr_t)
					&fs_trampoline_fault_tf + 32)) {
			/* Mid-trampoline or at the store's door. TF does
			 * NOT survive the exception return (local wine
			 * probe: the #DB-after-jmp's context return
			 * drops TF — the store then ran untraced);
			 * re-raise it at every hop until the store has
			 * executed. */
			c->EFlags |= (DWORD)0x100;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		{
			ULONG old_prot;
			void *pg = (void *)(uintptr_t)d->ss_page;

			/* The store JUST executed — read its target
			 * through THIS view before anything else can
			 * run. The kernel compares against the VMA
			 * table's run: a match-less pair is the
			 * wrong-backed twin at the qword. */
			guest_read_site = 2;
			d->ss_got = *(volatile unsigned long long *)
				(uintptr_t)d->ss_va;
			guest_read_site = 0;
			c->EFlags &= ~(DWORD)0x100;
			VirtualProtect(pg, (SIZE_T)0x1000, PAGE_NOACCESS,
				       &old_prot);
			d->ss_page = 0;
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (!is_syscall && !is_fault) {
		report_unowned(er, c);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	/* Only traps from the guest VA span belong to us (guest code
	 * executes in per-VMA views inside [ram_base, ram_base+size)). */
	if ((uintptr_t)c->Rip < (uintptr_t)d->ram_base ||
	    (uintptr_t)c->Rip >=
		    (uintptr_t)d->ram_base + d->ram_size) {
		report_unowned(er, c);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	/* S4d: snapshot the at-exception FP state (upstream parity:
	 * get_fp_registers at every trap). The CONTEXT copy is the
	 * ONLY at-exception snapshot — probes/xstate measured the
	 * dispatcher clobbering the live XMMs before this handler
	 * runs. Plain integer copy: the state is already captured by
	 * Windows, nothing here may perturb it. */
	if (c->ContextFlags & CONTEXT_FLOATING_POINT) {
		memcpy(d->xstate, &c->FloatSave, UML_STUB_XS_SIZE);
		d->xstate_flags |= UML_STUB_XS_CAPTURED;
	}

	gp_from_context(c, &d->regs);

	/* D18 fast path: an fs-prefixed guest access that faults below
	 * the guest span — or WRAPPED — means the TLS base was wiped
	 * while the guest ran. The trampoline re-applies the base at
	 * every resume, but the base only lives in the CPU: a preemption
	 * between wrfsbase and the guest's next %fs access makes Windows
	 * restore fs=0 (it never saw the wrfsbase), and glibc's struct
	 * pthread sits at NEGATIVE fs offsets — the fault signs in at
	 * the TOP of the VA space (0 + -0x150 = 0xfff...feb0), which no
	 * unsigned "below ram_base" test can see (init died exactly
	 * there, run 36785701760). Both windows route through the fault
	 * trampoline (which re-applies the base AFTER the context
	 * restore) back to the SAME rip — the instruction re-executes
	 * with the base live. A genuine guest null/low deref is not
	 * fs-prefixed and keeps its SIGSEGV round-trip; the guest's own
	 * base is always a validated mapped VA (arch_prctl), so an
	 * fs-prefixed wrapped access is never a real guest address. */
	{
		uintptr_t fa = (uintptr_t)er->ExceptionInformation[1];

		if (is_fault && d->fs_base != 0 && have_fsgsbase &&
		    (fa < (uintptr_t)d->ram_base ||
		     fa >= (uintptr_t)0xFFFFFFFF00000000ull) &&
		    *(const unsigned char *)(uintptr_t)c->Rip ==
			    0x64 /* fs: */) {
			fs_tramp_base = d->fs_base;
			fs_save_r11 = c->R11;
			fs_tramp_target = c->Rip;
			d->resume_rip = c->Rip;
			c->Rip = (DWORD64)(uintptr_t)&fs_trampoline_fault;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

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

	/* Kernel answered. Syscall: retval in rax, resume past the ud2
	 * — UNLESS the kernel installed a signal handler over the trap
	 * regs (VERBATIM: d->regs.rip is already the exact target, rax
	 * is already what the guest must see). Fault: every register
	 * verbatim, rip unchanged — the faulting instruction
	 * re-executes on the now-fixed view (the kernel-pushed SIGSEGV
	 * handler state from S4d rides the same verbatim shape). */
	gp_to_context(c, &d->regs);

	/* S4d: apply the kernel's FP/XSTATE (upstream parity:
	 * put_fp_registers before every continue). Today the bytes
	 * are the capture's own (identity round-trip — probes/xstate:
	 * the CONTEXT restore is faithful anyway); the kernel-written
	 * sigreturn restore lands here too. The flags are consumed
	 * fresh every round: read them before clearing. */
	verbatim = (d->xstate_flags & UML_STUB_XS_VERBATIM) ? 1 : 0;
	if (d->xstate_flags & UML_STUB_XS_RESTORE) {
		memcpy(&c->FloatSave, d->xstate, UML_STUB_XS_SIZE);
		c->ContextFlags |= CONTEXT_FLOATING_POINT;
	}
	d->xstate_flags &= ~(u32_nt)(UML_STUB_XS_RESTORE |
				     UML_STUB_XS_VERBATIM);

	if (verbatim) {
		/* A signal delivery rewrote the register file INCLUDING
		 * RSP (the sigframe, placed deep by the kernel to keep
		 * wine's dispatch context un-clobbered). Return the
		 * context UNTOUCHED: wine 9.0's NtContinue restores the
		 * full context faithfully ONLY while the wine-saved
		 * ContextFlags stay intact — stripping
		 * CONTEXT_DEBUG_REGISTERS|CONTEXT_XSTATE (the first
		 * attempt, meant to dodge a wineserver round-trip)
		 * pushes NtContinue down a partial-restore path that
		 * resurrects the STALE volatile registers from its own
		 * syscall frame: the guest handler came up with
		 * rdx=0xD (the NtContinue dispatch id) instead of the
		 * &frame->uc argument and died on its first frame read
		 * (test-matrix: G?F?S1W? = RDX-FLIP, S0 = rdx-ok).
		 * Native Windows restores the wine-saved Dr values
		 * harmlessly (they are the thread's own), and the
		 * CONTEXT_XSTATE claim is backed by the CONTEXT_EX the
		 * dispatcher itself built next to this context. */
		/* D18: the restore on the way out still wipes the TLS
		 * base — the signal state rides through the same
		 * trampoline (r11 is guest-live here, preserved). */
		if (d->fs_base != 0 && have_fsgsbase) {
			fs_save_r11 = c->R11;
			fs_tramp_base = d->fs_base;
			fs_tramp_target = d->regs.rip;
			c->Rip = (DWORD64)(uintptr_t)&fs_trampoline_fault;
		}
		d->resume_rip = fs_tramp_target ? fs_tramp_target
			: (unsigned long long)c->Rip;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (is_syscall) {
		unsigned long long target;

		c->Rax = (DWORD64)d->retval;
		target = d->regs.rip + 2; /* past 0F 0B (ud2) */
		/* D18: with a TLS base live, resume THROUGH the
		 * trampoline — the context restore on the way out has
		 * already zeroed the base, and rcx/r11 are clobbered
		 * by the syscall contract anyway (the trampoline uses
		 * r11 as scratch and touches nothing else). Without
		 * TLS this stays the plain resume the
		 * M1.9–M3.7 gates have always run. */
		if (d->fs_base != 0 && have_fsgsbase) {
			fs_tramp_base = d->fs_base;
			fs_tramp_target = target;
			fs_tramp_eflags = c->EFlags;
			c->Rip = (DWORD64)(uintptr_t)&fs_trampoline_sys;
		} else {
			c->Rip = (DWORD64)target;
		}
		d->resume_rip = target;
	} else {
		/* D18: the fault-repair resume re-executes the faulting
		 * instruction with every register live — and the
		 * context restore wiped the TLS base on its way out
		 * (Windows does not preserve user FS bases across
		 * exception dispatch). glibc's struct pthread lives at
		 * NEGATIVE fs offsets, so the re-execute faulted at a
		 * huge wrapped VA (0 + (-0x198) = 0xfff...feb0) that
		 * missed the wiped-base fast path above and killed the
		 * guest (systemd's executor, run 36779376375). The
		 * fault trampoline restores r11 from the VEH snapshot
		 * and replays the same rip with the base live. */
		if (d->fs_base != 0 && have_fsgsbase) {
			fs_save_r11 = c->R11;
			fs_tramp_base = d->fs_base;
			fs_tramp_target = d->regs.rip;
			c->Rip = (DWORD64)(uintptr_t)
				(d->ss_page != 0 ? &fs_trampoline_fault_tf
						 : &fs_trampoline_fault);
		} else if (d->ss_page != 0) {
			c->EFlags |= 0x100; /* TF: #DB after the store */
		}
		d->resume_rip = d->regs.rip;
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
		/* D18: the fork child's FIRST guest code is the fork
		 * return — no arch_prctl is coming (the base was
		 * inherited through the conn), so apply the recorded
		 * base here or the first %fs access faults at a
		 * wrapped negative offset. The raw jmp crosses no
		 * Windows context state, so a base set here survives
		 * into the guest. r11 is scratch (ir reloads it). */
		"movq	fs_tramp_base(%rip), %r11\n\t"
		"testq	%r11, %r11\n\t"
		"jz	1f\n\t"
		"wrfsbase %r11\n\t"
		"1:\n\t"
		/* M5.4 c3 (map 059, ROOT CAUSE): the entry target lives
		 * in MEMORY, not in %r15. The first version kept it in
		 * r15 and NEVER loaded init_regs.r15 — every conn was
		 * born with its entry rip in a CALLEE-SAVED register.
		 * For a fork child that entry rip IS the fork-resume
		 * rip (_Fork+0x23): libc preserves r15 all the way to
		 * the child's first trap, whose VEH dispatch CONTEXT
		 * (written on the guest stack, see signal_check's
		 * exc_stack note) then carries the poison at its R15
		 * slot — residue-watch run 36860061327: seed r15=0x40,
		 * first-trap r15=0x606a4353 = the watched value. Apply
		 * the seed's r15 (true fork parity — upstream
		 * copy_thread memcpy's pt_regs) and jump memory-
		 * indirect like the trampolines do. */
		"movq	%r8, fs_tramp_target(%rip)\n\t"
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
		"movq	120(%rcx), %r15\n\t"
		"movq	8(%rcx), %rcx\n\t"
		"jmp	*fs_tramp_target(%rip)\n\t"
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

	/* D18: jump_to_guest applies the recorded base when nonzero —
	 * the fork child's first guest code is the fork return and no
	 * arch_prctl is coming (the base was inherited via the conn;
	 * conn_bootstrap published it into d->fs_base). */
	fs_tramp_base = d->fs_base;
	jump_to_guest(&d->init_regs, d->stack_va, d->entry_va);
	/* not reached */
	ExitProcess(122);
}
