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
 *     boot.stdio_in (boot-info v3) and feeds the port's flip buffer —
 *     the deliver_alarm() pattern (a host thread calling straight
 *     into kernel context). A closed/invalid stdin parks the thread
 *     after one log line; input loss is loud, never silent.
 *
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
#include "internal.h"

/* ---- tty driver -------------------------------------------------------- */
static struct tty_driver *g_driver;
static struct tty_port g_port;

static const struct tty_port_operations nt_con_port_ops = { };

static int nt_con_tty_open(struct tty_struct *tty, struct file *filp)
{
	return tty_port_open(&g_port, tty, filp);
}

static void nt_con_tty_close(struct tty_struct *tty, struct file *filp)
{
	tty_port_close(&g_port, tty, filp);
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
	*index = 0;
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
		tty_insert_flip_string(&g_port, buf, iosb.Information);
		tty_flip_buffer_push(&g_port);
	}
	return 0;
}

/* ---- registration -------------------------------------------------------- */
static int __init nt_con_init(void)
{
	ULONG tid;
	int err;

	tty_port_init(&g_port);
	g_port.ops = &nt_con_port_ops;

	g_driver = tty_alloc_driver(1, TTY_DRIVER_REAL_RAW |
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
	tty_set_operations(g_driver, &nt_con_ops);

	/* Wire the port into the device slot BEFORE registering: it is
	 * driver->ports[idx] that alloc_tty_struct copies into
	 * tty->port. The raw tty_register_device left it NULL — the
	 * "tty driver does not set tty->port" WARN on every console
	 * open, and the real VFS write path (writev from musl stdio)
	 * had no port-backed tty. */
	g_driver->ports[0] = &g_port;
	err = tty_register_driver(g_driver);
	if (err) {
		printk(KERN_ERR "uml-nt: can't register console tty driver"
		       " (err %d)\n", err);
		tty_driver_kref_put(g_driver);
		tty_port_destroy(&g_port);
		return err;
	}
	tty_register_device(g_driver, 0, NULL); /* /dev/tty0 */

	register_console(&nt_cons);
	printk(KERN_INFO "uml-nt: stdio console ready (stdin %s)\n",
	       uml_boot.stdio_in != NULL ? "attached" : "absent");

	if (uml_boot.stdio_in != NULL) {
		/* Handle leaked deliberately: the reader lives for the
		 * UML run (os_timer_create pattern). */
		nt->CreateThread(NULL, 0, nt_con_reader, NULL, 0, &tid);
	}
	return 0;
}
late_initcall(nt_con_init);
