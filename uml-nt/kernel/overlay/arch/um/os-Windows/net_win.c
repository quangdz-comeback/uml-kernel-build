// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/net_win.c — winsock seam for the netstack channel (M5.1a).
 *
 * Upstream: UML's vector VDE transport opens a SOCK_SEQPACKET unix
 * socketpair and EXECs the vde_plug helper (vector_user.c
 * user_init_vde_fds). NT has neither AF_UNIX sockets nor a socketpair
 * (D8), so the channel is TCP localhost with the helper as the
 * LISTEN side and the kernel dialing in: same frame-per-message
 * contract, carried as 2-byte big-endian length-prefixed buffers —
 * the wire protocol vdeplug-go's own TCP transport speaks
 * (internal/transport tcpConn). The helper keeps the ENTIRE socket
 * side (its netstack NAT/DHCP runs there); the kernel only speaks
 * frames through this one connection.
 *
 * Everything here goes through the D9 table (ntabi v2, launcher
 * resolves ws2_32.dll) — the kernel never links against winsock.
 *
 * The M5.1a probe (`uml_nt_netprobe=<host:port>`) proves the seam
 * end to end: dial, framed round-trip, marker. The vector transport
 * (M5.1c) reuses uml_nt_ws_init/dial/net_send_frame/net_recv_frame.
 */
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <init.h>
#include <ntabi.h>
#include <os.h>
#include "internal.h"

/* Matches vdeplug-go link.FrameMax = 9216 + 14 + 4. */
#define UML_NT_NET_FRAME_MAX 9234

static struct uml_nt_wsadata g_wsa;
static int g_ws_ready;

/* One-time WSAStartup. Guarded by CAS: the probe runs on its own
 * thread and the vector transport will call from another; winsock
 * init is process-global. Returns 0 = ready. */
int uml_nt_ws_init(void)
{
	int old;

	if (g_ws_ready)
		return 0;
	old = __sync_val_compare_and_swap(&g_ws_ready, 0, 1);
	if (old == 0) {
		if (nt->WSAStartup(UML_NT_WSA_VERSION, &g_wsa) != 0) {
			os_warn("net: WSAStartup failed, code %d\n",
				nt->WSAGetLastError());
			g_ws_ready = 0;
			return -EINVAL;
		}
		os_info("net: winsock ready (requested 2.2, got %u.%u)\n",
			g_wsa.wVersion >> 8, g_wsa.wVersion & 0xffu);
	}
	/* Another thread won the race and may still be in WSAStartup —
	 * winsock init is process-global and idempotent per refcount;
	 * by the time any caller dials, the first WSAStartup returned
	 * (dialers come from initcalls after the probe joined). */
	return 0;
}

/* "127.0.0.1:9100" → sockaddr. Dotted-quad only (the helper binds
 * loopback; names would need DNS on the kernel side — out of scope). */
static int uml_nt_parse_addr(const char *host_port,
			     struct uml_nt_sockaddr_in *sa)
{
	char buf[64];
	char *colon;
	unsigned int addr;
	long port = 0;
	int i;

	if (host_port == NULL || strlen(host_port) >= sizeof(buf))
		return -EINVAL;
	for (i = 0; host_port[i]; i++)
		buf[i] = host_port[i];
	buf[i] = 0;

	colon = NULL;
	for (i = 0; buf[i]; i++)
		if (buf[i] == ':')
			colon = &buf[i];
	if (colon == NULL || *colon == 0)
		return -EINVAL;
	*colon = 0;
	for (i = 0; colon[1 + i]; i++) {
		if (colon[1 + i] < '0' || colon[1 + i] > '9' ||
		    port > 65535)
			return -EINVAL;
		port = port * 10 + (colon[1 + i] - '0');
	}
	if (port < 1 || port > 65535)
		return -EINVAL;
	if (!uml_nt_inet_pton4(buf, &addr))
		return -EINVAL;

	sa->sin_family = AF_INET;
	sa->sin_port = uml_nt_htons((unsigned short)port);
	sa->sin_addr = addr;
	for (i = 0; i < 8; i++)
		sa->sin_zero[i] = 0;
	return 0;
}

/* Dial host:port (blocking connect — loopback returns in µs; the
 * retry-around-not-listening case lives at the transport layer). */
unsigned long long uml_nt_net_dial(const char *host_port)
{
	struct uml_nt_sockaddr_in sa;
	unsigned long long s;

	if (uml_nt_parse_addr(host_port, &sa) != 0) {
		os_warn("net: bad address %s (want a.b.c.d:port)\n",
			host_port);
		return UML_NT_INVALID_SOCKET;
	}
	s = nt->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == UML_NT_INVALID_SOCKET) {
		os_warn("net: socket() failed, code %d\n",
			nt->WSAGetLastError());
		return UML_NT_INVALID_SOCKET;
	}
	if (nt->connect(s, &sa, sizeof(sa)) != 0) {
		os_warn("net: connect %s failed, code %d\n", host_port,
			nt->WSAGetLastError());
		nt->closesocket(s);
		return UML_NT_INVALID_SOCKET;
	}
	return s;
}

/* Framed send: 2-byte BE length prefix + payload (tcpConn parity).
 * Returns 0 or a negative errno-ish code. */
int uml_nt_net_send_frame(unsigned long long s, const void *buf,
			  unsigned int len)
{
	unsigned char head[2];
	int sent, total;

	if (len == 0 || len > UML_NT_NET_FRAME_MAX)
		return -EINVAL;
	head[0] = (unsigned char)(len >> 8);
	head[1] = (unsigned char)len;
	total = 0;
	while (total < 2) {
		sent = nt->send(s, (const char *)head + total, 2 - total, 0);
		if (sent <= 0)
			return -EIO;
		total += sent;
	}
	total = 0;
	while ((unsigned int)total < len) {
		sent = nt->send(s, (const char *)buf + total,
				(int)(len - (unsigned int)total), 0);
		if (sent <= 0)
			return -EIO;
		total += sent;
	}
	return 0;
}

/* Framed recv: read the prefix, then exactly len bytes. Returns the
 * frame length or a negative code (-ECONNRESET on clean EOF). */
int uml_nt_net_recv_frame(unsigned long long s, void *buf,
			  unsigned int maxlen)
{
	unsigned char head[2];
	unsigned int need;
	int got, total;

	total = 0;
	while (total < 2) {
		got = nt->recv(s, (char *)head + total, 2 - total, 0);
		if (got <= 0)
			return -ECONNRESET;
		total += got;
	}
	need = ((unsigned int)head[0] << 8) | head[1];
	if (need == 0)
		return -ECONNRESET;
	if (need > maxlen)
		return -EINVAL;
	total = 0;
	while ((unsigned int)total < need) {
		got = nt->recv(s, (char *)buf + total,
			       (int)(need - (unsigned int)total), 0);
		if (got <= 0)
			return -ECONNRESET;
		total += got;
	}
	return (int)need;
}

/* ---- M5.1a probe: kernel-side TCP round-trip ----------------------- */

static char netprobe_target[64];

static int __init uml_nt_netprobe_setup(char *str, int *add)
{
	*add = 0; /* consumed: never leaks into the guest cmdline */
	if (!str || !*str || strlen(str) >= sizeof(netprobe_target))
		return 0;
	strcpy(netprobe_target, str);
	return 0;
}
__uml_setup("uml_nt_netprobe=", uml_nt_netprobe_setup,
"uml_nt_netprobe=<host:port>\n"
"    M5.1a probe: the freestanding kernel dials a framed TCP echo\n"
"    server and round-trips a payload through winsock via the D9\n"
"    table (ntabi v2).\n");

/* The payload is sent once and must come back byte-identical: winsock
 * is a byte stream, so a lost/duplicated byte anywhere in the D9
 * call chain shows up as a compare failure, not silence. */
static unsigned char probe_payload[512];
static unsigned char probe_rxbuf[512];

static unsigned long __attribute__((ms_abi)) netprobe_thread(void *arg)
{
	unsigned long long s;
	unsigned int i;
	int n, rc;

	(void)arg;
	for (i = 0; i < sizeof(probe_payload); i++)
		probe_payload[i] = (unsigned char)(i * 7 + 0x40);

	if (uml_nt_ws_init() != 0)
		goto fail;

	s = uml_nt_net_dial(netprobe_target);
	if (s == UML_NT_INVALID_SOCKET)
		goto fail;
	os_info("NETPROBE-DIAL-OK %s\n", netprobe_target);

	rc = uml_nt_net_send_frame(s, probe_payload, sizeof(probe_payload));
	if (rc != 0) {
		os_warn("NETPROBE-FAIL: send %d, code %d\n", rc,
			nt->WSAGetLastError());
		nt->closesocket(s);
		goto fail;
	}
	n = uml_nt_net_recv_frame(s, probe_rxbuf, sizeof(probe_rxbuf));
	if (n < 0) {
		os_warn("NETPROBE-FAIL: recv %d, code %d\n", n,
			nt->WSAGetLastError());
		nt->closesocket(s);
		goto fail;
	}
	if ((unsigned int)n != sizeof(probe_payload) ||
	    __builtin_memcmp(probe_payload, probe_rxbuf,
			     sizeof(probe_payload)) != 0) {
		os_warn("NETPROBE-FAIL: echo mismatch (got %d bytes)\n", n);
		nt->closesocket(s);
		goto fail;
	}
	nt->closesocket(s);
	os_info("NETPROBE-TCP-OK %u bytes round-trip (framed, D9 v%u)\n",
		(unsigned int)sizeof(probe_payload), UML_NT_API_VERSION);
	return 0;

fail:
	os_warn("NETPROBE-FAIL: target %s\n", netprobe_target);
	return 1;
}

static int __init uml_nt_netprobe_init(void)
{
	HANDLE th;
	ULONG tid;

	if (netprobe_target[0] == 0)
		return 0; /* not armed */

	/* Own thread, joined before the boot continues: the marker must
	 * be deterministic in the log (the stubtest pattern — the boot
	 * stack is a UML THREAD_SIZE stack; keep fat-thread habits). */
	th = nt->CreateThread(NULL, 1 << 20, netprobe_thread, NULL, 0, &tid);
	if (th == NULL) {
		os_warn("NETPROBE-FAIL: cannot spawn probe thread\n");
		return 0;
	}
	nt->NtWaitForSingleObject(th, 0, UML_NT_INFINITE);
	nt->CloseHandle(th);
	return 0;
}
__initcall(uml_nt_netprobe_init);
