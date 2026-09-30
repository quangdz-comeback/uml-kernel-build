/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/guardtest.c — M4 slice 5 proof: page-granular MAP_FIXED
 * guard materialized for real (runs as PID 1 via init=/bin/guardtest).
 *
 * The musl mallocng brk guard is mmap(4K, PROT_NONE, MAP_FIXED)
 * inside the heap VMA — with slice 5 that arms a REAL NOACCESS
 * region: kernel guard state + NOACCESS stub view, and a fault
 * inside one is a REAL SIGSEGV (SEGV_ACCERR), never auto-repaired.
 *
 * The proof is the full tripwire lifecycle, the way a real user
 * would drive it:
 *   1. mmap(heap_base, 4096, PROT_NONE, MAP_FIXED) — placed
 *      (GUARD-PLACE-OK: the exact VA came back).
 *   2. Store into the guard page → the kernel's guard state kills
 *      the fault ('g') → force_sig_fault(SIGSEGV, SEGV_ACCERR) →
 *      the handler runs and verifies si_code + si_addr
 *      (GUARD-TRIP-OK).
 *   3. The handler answers like a real allocator: mprotect(guard,
 *      4096, PROT_READ|PROT_WRITE) — the SUB-RUN mprotect path
 *      (guard killed kernel-side, view op streams) — then returns;
 *      sigreturn restores the faulting rip unchanged (GUARD-REPLAY
 *      setup).
 *   4. The store REPLAYS and succeeds (GUARD-REPLAY-OK: the value
 *      reads back), heap data next to the guard is untouched
 *      (GUARD-NEIGHBOR-OK), GUARDTEST-OK + exit 0.
 *
 * Freestanding static, linked INSIDE the guest window (Makefile).
 */
#include <stdint.h>

/* ---- x86_64 signal ABI (mirrors sigtest.c) ------------------------ */

struct sc64 {
	unsigned long long r8, r9, r10, r11, r12, r13, r14, r15;
	unsigned long long rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip;
	unsigned long long eflags;
	unsigned short cs, gs, fs, ss;
	unsigned long long err, trapno, oldmask, cr2, fpstate;
	unsigned long long reserved[8];
};

struct ucontext64 {
	unsigned long long uc_flags;
	struct ucontext64 *uc_link;
	unsigned long long uc_stack[3];
	struct sc64 uc_mcontext;
	unsigned long long uc_sigmask[16];
};

struct siginfo64 {
	int si_signo, si_errno, si_code;
	unsigned long long _addr; /* _sigfault._addr */
};

struct sa64 {
	void *handler;
	unsigned long long flags;
	void *restorer;
	unsigned long long mask;
};

#define SA_SIGINFO  0x00000004ull
#define SA_RESTORER 0x04000000ull

#define SEGV_ACCERR 2

/* ---- syscalls ------------------------------------------------------ */

static long sys_write(int fd, const void *buf, unsigned long len)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (1L), "D" ((long)fd), "S" (buf),
			    "d" (len)
			  : "rcx", "r11", "memory");
	return ret;
}

static void __attribute__((noreturn)) sys_exit(int code)
{
	__asm__ volatile ("syscall"
			  :
			  : "a" (60L), "D" ((long)code)
			  : "rcx", "r11");
	__builtin_unreachable();
}

static long sys_rt_sigaction(int sig, const struct sa64 *act,
			     struct sa64 *oact, unsigned long sigsetsize)
{
	long ret;
	register long r10 __asm__ ("r10") = (long)sigsetsize;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (13L), "D" ((long)sig), "S" (act),
			    "d" (oact), "r" (r10)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_brk(long addr)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (12L), "D" (addr)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_mmap(long addr, unsigned long len, unsigned long prot,
		     unsigned long flags, long fd, unsigned long off)
{
	long ret;
	register long r10 __asm__ ("r10") = (long)flags;
	register long r8 __asm__ ("r8") = fd;
	register long r9 __asm__ ("r9") = (long)off;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (9L), "D" (addr), "S" (len), "d" (prot),
			    "r" (r10), "r" (r8), "r" (r9)
			  : "rcx", "r11", "memory");
	return ret;
}

static long sys_mprotect(long addr, unsigned long len, unsigned long prot)
{
	long ret;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (10L), "D" (addr), "S" (len), "d" (prot)
			  : "rcx", "r11", "memory");
	return ret;
}

/* ---- state --------------------------------------------------------- */

#define PROT_NONE        0x0ul
#define PROT_READ        0x1ul
#define PROT_WRITE       0x8ul
#define MAP_PRIVATE      0x02ul
#define MAP_FIXED        0x10ul
#define MAP_ANONYMOUS    0x20ul

static unsigned long long guard_va;
static volatile int tripped;

/* x86-64 must always use SA_RESTORER (sigtest.c note): the kernel
 * patches this rt_sigreturn syscall to ud2 like every other. */
void guardtest_restorer(void);
__asm__ (
	".text\n"
	".globl guardtest_restorer\n"
	"guardtest_restorer:\n\t"
	"movq	$15, %rax\n\t"
	"syscall\n\t"
);

static void guard_handler(int sig, struct siginfo64 *si, void *uuc)
{
	struct ucontext64 *uc = uuc;
	long rc;

	(void)sig;
	(void)uc;
	if (si->si_signo == 11 && si->si_code == SEGV_ACCERR &&
	    si->_addr >= guard_va && si->_addr < guard_va + 0x1000) {
		/* Unprotect like a real allocator would (the sub-run
		 * mprotect kills the guard + fixes the view); the
		 * faulting store then replays — rip stays put. */
		rc = sys_mprotect((long)guard_va, 0x1000,
				  PROT_READ | PROT_WRITE);
		if (rc == 0) {
			tripped = 1;
			sys_write(1, "GUARD-TRIP-OK\n", 14);
		}
	}
}

/* ---- proof --------------------------------------------------------- */

static void put(const char *s)
{
	unsigned n = 0;

	while (s[n])
		n++;
	sys_write(1, s, n);
}

/* Process entry (naked — no prologue may run before the realign):
 * the loader sets rsp 16-byte-aligned pointing at argc (the SysV
 * PROCESS-entry convention), but clang compiles _start as a NORMAL
 * callee (rsp+8 ≡ 0 mod 16 at entry) — guardtest's prologue movaps's
 * the sa64 initializer onto the stack and died on the misalignment
 * (the exact sigtest.c lesson: latent in every guest whose prologue
 * emits 16-aligned SSE before an adjustment). Realign to the callee
 * convention and jump. */
void guardtest_main(void);
void _start(void) __attribute__((naked, noreturn));
void _start(void)
{
	__asm__ volatile (
		"andq	$-16, %rsp\n\t"
		"subq	$8, %rsp\n\t"
		"xorl	%ebp, %ebp\n\t"
		"jmp	guardtest_main\n\t"
	);
}

void guardtest_main(void)
{
	struct sa64 act = {
		.handler = (void *)guard_handler,
		.flags = SA_SIGINFO | SA_RESTORER,
		.restorer = (void *)guardtest_restorer,
		.mask = 0,
	};
	unsigned long long heap_base, *nbr;
	long rc;
	volatile unsigned long *gp;

	if (sys_rt_sigaction(11, &act, 0, 8) != 0)
		goto fail;

	heap_base = (unsigned long long)sys_brk(0);
	if (!heap_base || (heap_base & 0xfffful))
		goto fail;

	/* The mallocng call shape, at the heap's first page. */
	rc = sys_mmap((long)heap_base, 0x1000, PROT_NONE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if ((unsigned long long)rc != heap_base)
		goto fail;
	guard_va = heap_base;
	put("GUARD-PLACE-OK\n");

	/* A neighbour page stays live (the guard is really 4K). */
	nbr = (unsigned long long *)(heap_base + 0x1000);
	*nbr = 0x1234;

	/* The trip: a plain store into the NOACCESS page. */
	gp = (unsigned long *)(guard_va + 0x40);
	*gp = 0x2a;

	if (!tripped)
		goto fail;

	/* The replay landed: the store's value is there. */
	if (*gp != 0x2a)
		goto fail;
	put("GUARD-REPLAY-OK\n");

	if (*nbr != 0x1234)
		goto fail;
	put("GUARD-NEIGHBOR-OK\n");

	put("GUARDTEST-OK\n");
	sys_exit(0);

fail:
	put("GUARDTEST-FAIL\n");
	sys_exit(9);
}
