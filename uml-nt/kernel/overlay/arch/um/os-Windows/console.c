// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/console.c — the real console TTY (M3.6).
 * Upstream: linux v6.18.37 arch/um/drivers/{stdio_console,chan_kern,
 * chan_user,line}.c
 *
 * Upstream's console stack routes tty I/O through the chan layer
 * (channel specs on the con= cmdline, poll-fed IRQs, per-line
 * buffers) — ~1900 lines, mostly generic, and its os seam is
 * fd/poll-shaped: exactly what this backend cannot provide (no
 * poll-able pipes). The M3.6 port keeps the parts the tty core
 * already owns and replaces the chan layer with the boot-info stdio
 * handles (D14):
 *
 *   - one tty_driver (major 4, /dev/tty0) over one tty_port, ops =
 *     open/close via tty_port_open/tty_port_close, write straight
 *     into the console write path;
 *   - one struct console (name "tty", index 0) — printk lands here
 *     once it registers (CON_PRINTBUFFER replays the early log; the
 *     kernel's own "console=tty0" default binds it);
 *   - input: a dedicated NT thread blocks in NtReadFile on
 *     boot.stdio_in (boot-info v3) and feeds the port's flip buffer.
 *     A closed/invalid stdin parks the thread after one log line;
 *     input loss is loud, never silent.
 *
 * M5.6a slice A (to-shelley 141-A — the D19 violation, referee
 * co-factor): the reader thread ran tty_insert_flip_string() itself
 * — kernel context CONCURRENT with the vCPU, zero exclusion on the
 * port/flip/n_tty state on the UP build (the 5cb22f8 S4c2 class,
 * console edition; the referee's login feed keeps stdin open, so
 * the thread was live inside every CI boot's tear window). The
 * reader is now EDGE-CAPTURE ONLY, the timer's pending-only pattern
 * (5cb22f8): NtReadFile -> push the bytes into a lock-free SPSC
 * ring (con_ring.c) -> SetEvent the wake multiplex. The vCPU drains
 * the ring into the tty core at the safe points — the userspace()
 * wait wake (skas/process.c) and the unblock_signals flush
 * (signal.c). No kernel code runs on the reader thread, and every
 * console input path now enters through the one vCPU-side door
 * (which also closes the queued console-termios input work — the
 * steer 108/123 job#2 shape).
 * HANDOFF §4.1 #13: NtWriteFile to the same console handle from two
 * threads races output — every write funnels through
 * nt_console_write() (util.c), serialized by a spinlock at that
 * funnel; the tty write path here just rides it.
 */
#include <linux/console.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <ntabi.h>
#include <os.h>
#include "console_status.h"
#include "con_ring.h"
#include "internal.h"

/* ---- tty driver -------------------------------------------------------- */
static struct tty_driver *g_driver;
/* Two ports: index 0 = /dev/tty0 (used by getty@tty0.service),
 * index 1 = /dev/console (returned by nt_con_device for major 5, minor 1).
 * Separating them prevents getty@tty0's TIOCVHANGUP/session-exit from
 * hanging up console-getty's /dev/console tty_struct. */
static struct tty_port g_port[2];

static const struct tty_port_operations nt_con_port_ops = { };

static int nt_con_tty_open(struct tty_struct *tty, struct file *filp)
{
	int idx = (tty->index == 1) ? 1 : 0;

	return tty_port_open(&g_port[idx], tty, filp);
}

static void nt_con_tty_close(struct tty_struct *tty, struct file *filp)
{
	int idx = (tty->index == 1) ? 1 : 0;

	tty_port_close(&g_port[idx], tty, filp);
}

static ssize_t nt_con_tty_write(struct tty_struct *tty, const u8 *buf,
				size_t len)
{
	nt_console_write(buf, len);
	return len;
}

static unsigned int nt_con_tty_write_room(struct tty_struct *tty)
{
	return 4096;
}

static const struct tty_operations nt_con_ops = {
	.open		= nt_con_tty_open,
	.close		= nt_con_tty_close,
	.write		= nt_con_tty_write,
	.write_room	= nt_con_tty_write_room,
};

/* ---- console (printk sink) --------------------------------------------- */
static void nt_con_printk(struct console *co, const char *s, unsigned int n)
{
	nt_console_write(s, n);
}

static struct tty_driver *nt_con_device(struct console *c, int *index)
{
	(void)c;
	*index = 1;
	return g_driver;
}

static struct console nt_cons = {
	.name		= "tty",
	.write		= nt_con_printk,
	.device		= nt_con_device,
	.flags		= CON_PRINTBUFFER | CON_ANYTIME,
	.index		= 0,
};

/* ---- stdin reader (the input half) -------------------------------------- */
/* The edge-capture handoff: the ring + the wake event. g_con_live
 * gates the vCPU-side flush until the tty port exists (a feed byte
 * landing before late_initcall completes must not touch an uninit
 * port). */
static struct uml_nt_con_ring g_con_ring;
static HANDLE g_con_wake;
static int g_con_live;
static int g_con_armed = 1;

HANDLE uml_nt_console_wake_event(void)
{
	return g_con_wake;
}

static int console_reader_waiting(void)
{
	struct tty_struct *tty;

	if (!g_con_live)
		return 0;
	if (work_pending(&g_port[1].buf.work))
		return 0;
	tty = READ_ONCE(g_port[1].itty);
	if (tty == NULL || test_bit(TTY_HUPPED, &tty->flags) ||
	    test_bit(TTY_HUPPING, &tty->flags)) {
		g_con_armed = 1;
		return 0;
	}
	if (!waitqueue_active(&tty->read_wait)) {
		g_con_armed = 1;
		return 0;
	}
	return g_con_armed;
}

int uml_nt_console_pending(void)
{
	return console_reader_waiting() &&
	       uml_nt_con_ring_pending(&g_con_ring);
}

/* vCPU-side drain (D19): move at most one line from the ring into
 * the /dev/console port's flip buffer on the kernel thread when a
 * reader is actively sleeping on tty->read_wait, then push. Pacing
 * one line per read_wait sleep prevents early boot opens/closes and
 * login/bash tcsetattr(TCSAFLUSH) from wiping queued command lines. */
void uml_nt_console_flush(void)
{
	unsigned char ch;
	unsigned int total = 0;

	if (!console_reader_waiting())
		return;
	while (total < 256 &&
	       uml_nt_con_ring_pop(&g_con_ring, &ch, 1) == 1) {
		tty_insert_flip_string(&g_port[1], &ch, 1);
		total++;
		if (ch == '\n' || ch == '\r')
			break;
	}
	if (total != 0) {
		g_con_armed = 0;
		tty_flip_buffer_push(&g_port[1]);
	}
}

static unsigned long __attribute__((ms_abi)) nt_con_reader(void *arg)
{
	static unsigned char buf[512];
	static unsigned int status_seen[8][2]; /* status, count */
	static unsigned int nstatus_seen;
	IO_STATUS_BLOCK iosb;
	NTSTATUS s;

	(void)arg;
	for (;;) {
		int cls, i, found = 0;

		s = nt->NtReadFile(uml_boot.stdio_in, NULL, NULL, NULL,
				   &iosb, buf, sizeof(buf), NULL, NULL);
		cls = nt_con_status_class((long long)s);
		/* (3) log every status once, re-log at x1000. */
		for (i = 0; i < (int)nstatus_seen; i++)
			if (status_seen[i][0] == (unsigned int)s) {
				found = 1;
				status_seen[i][1]++;
				if (status_seen[i][1] == 1000)
					os_info("console: stdin status "
						"%08x seen x1000\n", s);
				break;
			}
		if (!found && nstatus_seen < 8) {
			os_info("console: stdin status %08x (class=%s)",
				s, cls == NT_CON_RETRY ? "retry" :
				"fatal");
			status_seen[nstatus_seen][0] = (unsigned int)s;
			status_seen[nstatus_seen][1] = 1;
			nstatus_seen++;
		}
		if (cls == NT_CON_RETRY) {
			if (iosb.Information == 0) {
				/* (1) a spurious wake (WAIT_1 class) —
				 * re-arm the read; the 100µs yield
				 * keeps a pathological repeat from
				 * spinning a core. */
				nt->NtDelayExecution(0, &(LARGE_INTEGER)
					{ .QuadPart = -1000 });
				continue;
			}
		} else {
			/* stdin closed/EOF (CI: no input): park loud. */
			os_info("console: stdin reader stopped (status "
				"%08x)", s);
			return 0;
		}
		/* D19 edge-capture (M5.6a slice A): NO tty calls on
		 * this thread — stage the bytes, then wake the vCPU.
		 * A short push means the ring filled (a stalled vCPU
		 * with a fed stdin); the loss is loud, never silent. */
		{
			unsigned int want = (unsigned int)iosb.Information;
			unsigned int put =
				uml_nt_con_ring_push(&g_con_ring, buf, want);
			static unsigned int drop_said;

			if (put < want && drop_said < 8) {
				drop_said++;
				os_info("console: input ring FULL — "
					"dropped %u byte(s) (total %u); "
					"the vCPU drain is stalled\n",
					want - put, g_con_ring.drops);
			}
		}
		if (g_con_wake != NULL)
			nt->NtSetEvent(g_con_wake, NULL);
	}
	return 0;
}

/* ---- registration -------------------------------------------------------- */
static int __init nt_con_init(void)
{
	ULONG tid;
	int err;

	tty_port_init(&g_port[0]);
	g_port[0].ops = &nt_con_port_ops;
	tty_port_init(&g_port[1]);
	g_port[1].ops = &nt_con_port_ops;

	g_driver = tty_alloc_driver(2, TTY_DRIVER_REAL_RAW |
				       TTY_DRIVER_DYNAMIC_DEV);
	if (IS_ERR(g_driver))
		return PTR_ERR(g_driver);

	g_driver->driver_name = "uml-nt console";
	g_driver->name = "tty";
	g_driver->major = TTY_MAJOR;
	g_driver->minor_start = 0;
	g_driver->type = TTY_DRIVER_TYPE_CONSOLE;
	g_driver->subtype = SYSTEM_TYPE_CONSOLE;
	g_driver->init_termios = tty_std_termios;
	/* The NT host conhost sends Backspace as BS (0x08), while
	 * tty_std_termios carries VERASE=0x7f (DEL) — canonical N_TTY
	 * echoes the unmatched byte raw (^H) and never erases. Match
	 * what the host actually emits; apps may still stty over it. */
	g_driver->init_termios.c_cc[VERASE] = 0x08;
	tty_set_operations(g_driver, &nt_con_ops);

	/* Wire the port into the device slot BEFORE registering: it is
	 * driver->ports[idx] that alloc_tty_struct copies into
	 * tty->port. The raw tty_register_device left it NULL — the
	 * "tty driver does not set tty->port" WARN on every console
	 * open, and the real VFS write path (writev from musl stdio)
	 * had no port-backed tty. */
	g_driver->ports[0] = &g_port[0];
	g_driver->ports[1] = &g_port[1];
	err = tty_register_driver(g_driver);
	if (err) {
		printk(KERN_ERR "uml-nt: can't register console tty driver"
		       " (err %d)\n", err);
		tty_driver_kref_put(g_driver);
		tty_port_destroy(&g_port[0]);
		tty_port_destroy(&g_port[1]);
		return err;
	}
	tty_register_device(g_driver, 0, NULL); /* /dev/tty0 */
	tty_register_device(g_driver, 1, NULL); /* /dev/console target */

	register_console(&nt_cons);
	printk(KERN_INFO "uml-nt: stdio console ready (stdin %s)\n",
	       uml_boot.stdio_in != NULL ? "attached" : "absent");

	if (uml_boot.stdio_in != NULL) {
		/* The wake event + ring exist BEFORE the reader can
		 * produce (single-threaded init; the vCPU wait and the
		 * flush read them only after g_con_live). Handle
		 * leaked deliberately: the reader lives for the UML
		 * run (os_timer_create pattern). */
		uml_nt_con_ring_init(&g_con_ring);
		g_con_wake = nt->CreateEventW(NULL, 0 /*auto-reset*/, 0,
					      NULL);
		if (g_con_wake == NULL)
			os_info("console: wake event creation failed — "
				"stdin input flushes only at signal "
				"unblocks\n");
		g_con_live = 1;
		nt->CreateThread(NULL, 0, nt_con_reader, NULL, 0, &tid);
	}
	return 0;
}
late_initcall(nt_con_init);
