// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/util.c — misc host utilities + early console.
 * Upstream: linux v6.18.37 arch/um/os-Linux/util.c
 *
 * The early console is the M1 lifeline: um_early_printk writes straight
 * to the inherited stdout handle via NtWriteFile (no channel stack —
 * drivers/ returns at M3). os_info/os_warn format with the kernel's
 * vscnprintf and ride the same path.
 */
#include <linux/stdarg.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <ntabi.h>
#include <os.h>
#include "internal.h"
#include <diag_record.h>
#include <feedgate.h>

/* um_arch.c page-offset anchors (PAGE_OFFSET / RAM top) — the D19
 * canary in uml_nt_physmem_check below compares against them. */
extern unsigned long uml_physmem;
extern unsigned long high_physmem;

/* HANDOFF §4.1 #13: NtWriteFile to the same console handle from two
 * threads races output (printk from any thread vs tty writes vs
 * stub-ctl diagnostics). Every console write funnels here, so the
 * spinlock lives at the funnel. __sync CAS lowers to lock cmpxchg on
 * both ELF (freestanding) and PE builds — no SRWLock needed in the
 * D9 table. */
static volatile int g_con_lock;

static void con_lock(void)
{
	for (;;) {
		if (__sync_val_compare_and_swap(&g_con_lock, 0, 1) == 0)
			return;
		/* 1-tick alertable delay = yield; FALSE is a PE-ism. */
		nt->NtDelayExecution(0,
				     &(LARGE_INTEGER){ .QuadPart = -1 });
	}
}

static void con_unlock(void)
{
	__sync_lock_release(&g_con_lock); /* store-release */
}

extern struct uml_nt_feed_gate uml_nt_console_gate;

/* S48: the writer says who it is. The gate used to guess from the text (a
 * leading '['), and "binfmt_umlnt:" is the port's own voice without a bracket —
 * so kernel lines filled the guest's buffer and the prompt never stood alone.
 * Default is the guest: only the port's own log paths set this. */
static int g_con_src;		/* 0 = guest console, 1 = port log */

void uml_nt_console_src_log(int on)
{
	g_con_src = on ? 1 : 0;
}

void uml_nt_console_src_guest(void)
{
	g_con_src = 0;
}

int uml_nt_console_src(void)
{
	return g_con_src;
}

/* S46: the console's single choke point. Every path that prints — the tty
 * driver, the printk sink, the guest's write(2), a stub panic — ends here, so
 * the feed gate reads the console here and nowhere else. The struct is
 * zero-initialised (file scope), so a call before the console is up is safe. */
static void feed_gate_sink(const char *s, unsigned int n)
{
	/* Which door? A diagnostic record starts with '[' at the head of the
	 * write — the port's own voice. Everything else is the guest's console,
	 * whatever path carried it. Keeping the two apart is what lets a prompt
	 * assemble while the kernel's lines interleave with it. */
	int src = g_con_src;

	uml_nt_feed_gate_scan(&uml_nt_console_gate, s, n, src);
	if (uml_nt_console_gate.armed &&
	    uml_nt_console_gate.stage != uml_nt_console_gate.last_armed_stage) {
		uml_nt_console_gate.last_armed_stage = uml_nt_console_gate.stage;
		os_info("[feedgate] arm stage=%d src=%s line=\"%.64s\"\n",
			uml_nt_console_gate.stage,
			uml_nt_console_gate.match_src ? "kernel" : "console",
			uml_nt_console_gate.line[uml_nt_console_gate.match_src]);
	}
	/* S47 tail-colon: a guest write that ends in ':' or carries "logi" is
	 * almost certainly a prompt fragment — print it, whatever the buffer
	 * state says. */
	if (src == 0 && n > 0 &&
	    (s[n - 1] == ':' || uml_nt_feed_find(s, n, "logi")))
		os_info("[feedgate] frag=\"%.32s\" len=%u\n", s, n);
	{
		int b;

		for (b = 0; b < 2; b++) {
			if (uml_nt_console_gate.truncated[b])
				continue;
			if (uml_nt_feed_find(uml_nt_console_gate.line[b],
					     uml_nt_console_gate.len[b], "ogin") ||
			    uml_nt_feed_find(uml_nt_console_gate.line[b],
					     uml_nt_console_gate.len[b], "assword"))
				os_info("[feedgate] line=%.64s src=%s len=%u\n",
					uml_nt_console_gate.line[b],
					b ? "kernel" : "console",
					uml_nt_console_gate.len[b]);
		}
	}
}

void nt_console_write(const char *s, unsigned int n)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS st;

	if (nt == NULL || uml_boot.stdio_out == NULL || n == 0)
		return;
	feed_gate_sink(s, n);
	con_lock();
	st = nt->NtWriteFile(uml_boot.stdio_out, NULL, NULL, NULL, &iosb,
			     (void *)s, n, NULL, NULL);
	if (st == (NTSTATUS)0x00000103 /* STATUS_PENDING */)
		nt->NtWaitForSingleObject(uml_boot.stdio_out, 0,
					  UML_NT_INFINITE);
	con_unlock();
}

void um_early_printk(const char *s, unsigned int n)
{
	int was = g_con_src;

	uml_nt_console_src_log(1);
	nt_console_write(s, n);
	uml_nt_console_src_log(was);
}

/* Shelley 295 (Astra S8): one diagnostic record, one host write.
 *
 * The body and its newline used to be two NtWriteFile calls, and the console
 * is append-shared with the stub process — so another writer could land
 * between them and cut the record in half. The framing now happens inside the
 * buffer (diag_record.h) and the record goes out once. nt_console_write has no
 * completion status, so the sink reports "unknown" rather than claiming
 * delivery, and this path does not pretend otherwise. */
static int diag_console_format(char *buf, unsigned int cap, const char *fmt,
			       va_list ap)
{
	return vsnprintf(buf, cap, fmt, ap);
}

/* S8b-ADAPTER-BEGIN (extracted verbatim by tests/test_diag_record.sh) */
static int diag_console_sink(const char *buf, unsigned int len)
{
	nt_console_write(buf, len);
	return UML_NT_DIAG_SINK_UNKNOWN_VALUE;
}
/* S8b-ADAPTER-END */

static const struct uml_nt_diag_ops diag_console_ops = {
	diag_console_format, diag_console_sink
};

/* S48: every port log goes out with the log flag set, so the console's feed gate
 * keeps those bytes out of the guest's line buffer. */
#define DIAG_EMIT_LOGGED(buf, cap, fmt, args, lenp)			\
	do {								\
		int was_ = g_con_src;					\
									\
		uml_nt_console_src_log(1);				\
		(void)uml_nt_diag_emit((buf), (cap), &diag_console_ops,	\
				       (fmt), (args), (lenp));		\
		uml_nt_console_src_log(was_);				\
	} while (0)

void os_info(const char *fmt, ...)
{
	/* M5.6b: host env UML_NT_QUIET=any-value silences the diag firehose
	 * (real-machine UX; CI never sets it). os_warn/os_err stay loud. */
	static int quiet = -1;
	char buf[UML_NT_DIAG_CAP];
	va_list args;
	unsigned int len = 0;

	if (quiet < 0)
		quiet = nt && nt->GetEnvironmentVariableA &&
			nt->GetEnvironmentVariableA("UML_NT_QUIET", buf, 1);
	if (quiet)
		return;
	va_start(args, fmt);
	DIAG_EMIT_LOGGED(buf, sizeof(buf), fmt, args, &len);
	va_end(args);
}

void os_warn(const char *fmt, ...)
{
	char buf[UML_NT_DIAG_CAP];
	va_list args;
	unsigned int len = 0;

	va_start(args, fmt);
	DIAG_EMIT_LOGGED(buf, sizeof(buf), fmt, args, &len);
	va_end(args);
}

void os_dump_core(void)
{
	/* Upstream: dump logs + core file via host tools. NT M1: flush
	 * the console and terminate the process (dump-to-file at M4). */
	uml_nt_console_src_log(1);
	nt_console_write("\numl-nt: os_dump_core — terminating\n", 37);
	if (nt != NULL)
		nt->NtTerminateProcess(UML_NT_CURRENT_PROCESS, 1);
	for (;;)
		;
}

void stack_protections(unsigned long address)
{
	/* Upstream: mprotect the IRQ stack non-exec/no-access guards. The
	 * NT kernel image has no per-stack guard pages yet (M4 hardening).
	 * Deliberate no-op — must not PANIC, boot calls it. */
}

int raw(int fd)
{
	/* tty raw mode — console on NT is always 8-bit-clean; the fd
	 * abstraction arrives with the chan port (M3). */
	return 0;
}

void setup_machinename(char *machine_out)
{
	/* Upstream: host uname -m. The guest kernel arch is fixed x86_64. */
	strcpy(machine_out, "x86_64");
}

void setup_hostinfo(char *buf, int len)
{
	snprintf(buf, len, "%s", "uml-nt (Windows NT host)");
}

ssize_t os_getrandom(void *buf, size_t len, unsigned int flags)
{
	/* NT: ProcessPrng (bcryptprimitives) — not in the D9 table yet;
	 * the guest entropy story lands with the network stack (M5).
	 * Filling with a weak-but-nonzero pattern keeps boot unblocked. */
	memset(buf, 0xA5, len);
	return len;
}

void os_fix_helper_signals(void)
{
	/* helper threads use NT threads, no signals to fix (D7). */
}

void os_flush_stdout(void)
{
	/* Console writes are synchronous NtWriteFile — nothing buffered
	 * to flush (upstream: fflush(stdout)). */
}

/* ---- D19 physmem canary ------------------------------------------------
 * uml_physmem IS page_offset (asm/page.h: PAGE_OFFSET) and high_physmem
 * tops the guest RAM with it. The S4c2 busybox crash ran with
 * uml_physmem = 0x400000001 and high_physmem = 0x62000200 (DETERMINISTIC
 * across runs = logic bug, not a race) while physmem_size stayed clean —
 * every virt_to_page/kmem_cache_free after that computes a wild memmap
 * index and faults far from the write that did it. The os-I/O funnel
 * (pread/pwrite/open) checks on every call and dies loud AT the
 * corrupting window, printing the offending call (fd/len/off) plus two
 * return addresses so the writer names itself. Snapshot at first use
 * (the values are set in linux_main, before any host I/O). */
void uml_nt_physmem_check(const char *what, int fd, long len,
			  unsigned long long off)
{
	static unsigned long want_phys, want_high;
	static int snapped;

	if (!snapped) {
		want_phys = uml_physmem;
		want_high = high_physmem;
		snapped = 1;
		return;
	}
	if (uml_physmem != want_phys || high_physmem != want_high) {
		/* ra0 only: __builtin_return_address(1) needs a frame-
		 * pointer chain the freestanding -O2 build doesn't keep
		 * — it faulted (NULL+0x1008) before the print landed. */
		os_info("PHYSMEM TRASHED at %s (fd=%d len=%ld off=%llx): "
			"physmem=%llx (want %llx) high=%llx (want %llx) "
			"ra0=%llx\n", what, fd, len, off,
			(unsigned long long)uml_physmem,
			(unsigned long long)want_phys,
			(unsigned long long)high_physmem,
			(unsigned long long)want_high,
			(unsigned long long)__builtin_return_address(0));
		os_dump_core();
	}
}
