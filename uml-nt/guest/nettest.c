/* SPDX-License-Identifier: GPL-2.0 */
/*
 * guest/nettest.c — M5.1d: the NAT acceptance, no shell layers.
 *
 * Runs as /bin/nettest (PID 1's /net.sh forks+execs it after the
 * lease + ping). Raw syscalls only: socket/connect/write/read/close
 * ride the REAL sys_call_table into the guest kernel's inet stack,
 * out through the vector driver, the D8 channel and the helper's
 * NAT44 — which maps the gateway address 10.0.2.2 to host loopback,
 * where the CI step serves /netok.txt. The response body must equal
 * the marker; NET-GET-OK is the gate's evidence (the mismatch branch
 * prints what arrived — never grepped as the marker, the M3.8
 * read-back lesson).
 *
 * Why not busybox wget in a command substitution: the ash $() capture
 * fork/dup/pipe round-trip came back EMPTY in the first gate run
 * (len=0) while the transport itself was proven (server logged the
 * GET + 200) — the shell capture layer gets its own investigation;
 * this binary IS the acceptance (and exercises the socket syscalls
 * wget would).
 */
#include <stdint.h>

#define AF_INET     2
#define SOCK_STREAM 1

static long sys_call6(long nr, long a, long b, long c, long d, long e)
{
	long ret;
	register long r10 __asm__ ("r10") = d;
	register long r8  __asm__ ("r8")  = e;

	__asm__ volatile ("syscall"
			  : "=a" (ret)
			  : "a" (nr), "D" (a), "S" (b), "d" (c),
			    "r" (r10), "r" (r8)
			  : "rcx", "r11", "memory");
	return ret;
}

#define sys_call(nr, a, b, c, d, e) sys_call6((nr), (a), (b), (c), (d), (e))

static void __attribute__((noreturn)) sys_exit(int code)
{
	sys_call(60, code, 0, 0, 0, 0);
	__builtin_unreachable();
}

static void out(const char *s, unsigned long len)
{
	sys_call(1, 1, (long)s, len, 0, 0);
}

static unsigned long slen(const char *s)
{
	unsigned long n = 0;

	while (s[n])
		n++;
	return n;
}

/* sin_family + sin_port (BE) + sin_addr (BE) + pad = 16 bytes */
static unsigned char sockaddr[16];

static void fill_addr(unsigned char a, unsigned char b, unsigned char c,
		      unsigned char d, unsigned port)
{
	sockaddr[0] = AF_INET;
	sockaddr[1] = 0;
	sockaddr[2] = (unsigned char)(port >> 8);
	sockaddr[3] = (unsigned char)port;
	sockaddr[4] = a;
	sockaddr[5] = b;
	sockaddr[6] = c;
	sockaddr[7] = d;
}

static const char req[] = "GET /netok.txt HTTP/1.0\r\nHost: gw\r\n\r\n";
static const char marker[] = "uml-nt-net-ok";
static const char ok[] = "NET-GET-OK\n";
static const char fail[] = "NETTEST-FAIL\n";
static char buf[4096];

void _start(void)
{
	long fd, n, total, i;

	fd = sys_call(41 /*socket*/, AF_INET, SOCK_STREAM, 0, 0, 0);
	if (fd < 0)
		goto die;
	fill_addr(10, 0, 2, 2, 19293);
	if (sys_call(42 /*connect*/, fd, (long)sockaddr, 16, 0, 0) < 0)
		goto die;
	if (sys_call(1 /*write on the socket*/, fd, (long)req,
		     sizeof(req) - 1, 0, 0) != sizeof(req) - 1)
		goto die;

	total = 0;
	for (;;) {
		n = sys_call(0 /*read*/, fd, (long)(buf + total),
			     sizeof(buf) - 1 - total, 0, 0);
		if (n < 0)
			goto die;
		if (n == 0)
			break; /* server closed: response complete */
		total += n;
		if (total >= sizeof(buf) - 1)
			break;
	}
	sys_call(3 /*close*/, fd, 0, 0, 0, 0);
	buf[total] = '\0';

	/* the body starts after the CRLF CRLF header terminator */
	for (i = 0; i + slen(marker) <= total; i++) {
		unsigned long k;

		for (k = 0; marker[k] && buf[i + k] == marker[k]; k++)
			;
		if (!marker[k]) {
			out(ok, sizeof(ok) - 1);
			sys_exit(0);
		}
	}
	/* mismatch — dump what arrived (one line, never the marker) */
	out("NET-BODY-MISMATCH: len=", 22);
	if (total == 0)
		out("0", 1);
	else
		out(buf, (unsigned long)total);
	out("\n", 1);
	sys_exit(1);

die:
	out(fail, sizeof(fail) - 1);
	sys_exit(1);
}
