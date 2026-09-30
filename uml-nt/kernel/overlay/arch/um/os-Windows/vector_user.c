// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/vector_user.c — the vector driver's user half, NT edition.
 * Upstream: linux v6.18.37 arch/um/drivers/vector_user.c (942 lines of
 * unix-land: /dev/net/tun, AF_PACKET, AF_UNIX socketpairs, exec'd
 * helpers with inherited fds — none of that exists on NT).
 *
 * The transport uml-nt speaks is the D8 channel: the netstack helper
 * (vdeplug-go, M5.1b direct mode) LISTENS on TCP localhost
 * (tcplisten://HOST:PORT); the kernel dials in and the two exchange
 * ETHERNET FRAMES as 2-byte big-endian length-prefixed buffers — the
 * exact wire contract of vdeplug-go's tcpConn and of upstream's
 * SOCK_SEQPACKET VDE socketpair (one message == one frame), flattened
 * onto a byte stream.
 *
 * Roles are inverted vs upstream (upstream execs vde_plug with one end
 * of a socketpair; NT has no socketpair — the audit's decision): the
 * kernel SPAWNS the helper (the stub.exe spawn pattern: fat thread,
 * CreateProcessA drinks >2MB of stack) and then dials with retry.
 *
 * RX IRQ per D19: a per-device aux reader thread does BLOCKING framed
 * recvs into a small SPSC ring and hands off (ring publish → registry
 * ready flag → mark_sigio_pending → SetEvent(wake)). It runs ZERO
 * kernel code; the vCPU drains the ring in the napi poll path
 * (sigio_handler → registry flush → vector_rx_interrupt → napi).
 *
 * TX: the vCPU alone sends (framed) — no locking beyond winsock's own.
 *
 * fd convention: struct vector_fds (vector_user.h) is upstream's int
 * pair; the NT SOCKET (UINT_PTR) is stored cast to int. Windows socket
 * handles are small positive values (kernel handle-table indexes), so
 * the cast is lossless in practice; the registry (irq.c) keys these
 * same ints.
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/socket.h> /* user_msghdr, mmsghdr, iovec */
#include <linux/string.h>
#include <linux/types.h>
#include <init.h> /* __uml_setup — the UML cmdline param machinery */
#include <ntabi.h>
#include <um_malloc.h>
#include <os.h>
/* The contract header is a sibling dir (ubd_user.c redeclares its two
 * symbols instead, but this surface is 14 functions + 2 structs — one
 * source of truth beats a drift-catching assert pile). */
#include "../drivers/vector_user.h"
#include "internal.h"

/* Matches vdeplug-go link.FrameMax = 9216 + 14 + 4. */
#define UML_NT_NET_FRAME_MAX 9234

/* ---- spec parser (upstream-verbatim semantics, freestanding) --------
 * Mutates the input: '=' and ',' become NUL separators; tokens[]/
 * values[] point into it. vector_config kstrdup's the spec before
 * calling (upstream contract), so in-place is safe. */

char *uml_vector_fetch_arg(struct arglist *ifspec, char *token)
{
	int i;

	for (i = 0; i < ifspec->numargs; i++) {
		if (strcmp(ifspec->tokens[i], token) == 0)
			return ifspec->values[i];
	}
	return NULL;
}

struct arglist *uml_parse_vector_ifspec(char *arg)
{
	struct arglist *result;
	int pos, len;
	bool parsing_token = true, next_starts = true;

	if (arg == NULL)
		return NULL;
	result = uml_kmalloc(sizeof(struct arglist), UM_GFP_KERNEL);
	if (result == NULL)
		return NULL;
	result->numargs = 0;
	len = strlen(arg);
	for (pos = 0; pos < len; pos++) {
		if (next_starts) {
			if (parsing_token) {
				result->tokens[result->numargs] = arg + pos;
			} else {
				result->values[result->numargs] = arg + pos;
				result->numargs++;
			}
			next_starts = false;
		}
		if (*(arg + pos) == '=') {
			if (parsing_token)
				parsing_token = false;
			else
				goto cleanup;
			next_starts = true;
			(*(arg + pos)) = '\0';
		}
		if (*(arg + pos) == ',') {
			parsing_token = true;
			next_starts = true;
			(*(arg + pos)) = '\0';
		}
	}
	return result;
cleanup:
	printk(KERN_ERR "vector_setup - Couldn't parse '%s'\n", arg);
	kfree(result);
	return NULL;
}

/* ---- the netstack helper ------------------------------------------- */

/* `uml_nt_netstack=<path>` — where netstack.exe lives. Without it the
 * open dials only (an externally started helper works; the CI gate
 * passes the path so the boot owns the helper lifecycle). */
static char netstack_path[512];
static int have_netstack;

static int __init uml_nt_netstack_setup(char *str, int *add)
{
	*add = 0; /* consumed: never leaks into the guest cmdline */
	if (!str || !*str || strlen(str) >= sizeof(netstack_path))
		return 0;
	strcpy(netstack_path, str);
	have_netstack = 1;
	return 0;
}
__uml_setup("uml_nt_netstack=", uml_nt_netstack_setup,
"uml_nt_netstack=<path>\n"
"    M5.1c: path of the vdeplug-go netstack helper. The kernel spawns\n"
"    it (direct p2p mode, tcplisten://) when a vector device opens\n"
"    and dials the TCP channel per D8.\n");

struct uml_nt_spawn_netstack_req {
	char cmd[1200];
	int rc;
	unsigned long pid;
};

/* CreateProcessA burns >2MB of stack natively (M2 pitfall 11) — the
 * spawn runs on its own fat thread, never on a UML task stack. */
static unsigned long __attribute__((ms_abi))
netstack_spawn_thread(void *arg)
{
	struct uml_nt_spawn_netstack_req *req = arg;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si); /* 104 on x64 — pitfall 10 */
	memset(&pi, 0, sizeof(pi));
	if (!nt->CreateProcessA(NULL, req->cmd, NULL, NULL, 1, 0, NULL,
				NULL, &si, &pi)) {
		req->rc = (int)nt->RtlGetLastWin32Error();
		return 1;
	}
	/* Handles live in the child now; we never wait it (the helper
	 * serves until the kernel process dies) and the pid is
	 * diagnostic only. */
	req->pid = pi.dwProcessId;
	req->rc = 0;
	return 0;
}

/* Spawn netstack.exe in direct p2p mode: listen on vnl (the tcplisten
 * address), uplink = slirp (NAT44 + DHCP + DNS — the guest wire the
 * M5.1d acceptance curls through). Returns 0 or a win32 error. */
static int netstack_spawn(int unit, const char *vnl,
			  unsigned long *pid_out)
{
	struct uml_nt_spawn_netstack_req req;
	char descr[16];
	ULONG tid;
	HANDLE th;
	int i;

	snprintf(descr, sizeof(descr), "vec%d", unit);
	i = snprintf(req.cmd, sizeof(req.cmd),
		     "\"%s\" --descr %s tcplisten://%s slirp://",
		     netstack_path, descr, vnl);
	if (i <= 0 || i >= (int)sizeof(req.cmd))
		return -EINVAL;

	/* 1 MiB — same as the other aux threads. The old 32 MiB reserve
	 * was 32 MiB of UNPLACED VA in the crowded 0x6x.. world (the
	 * M3.3 lesson: NT's allocator will take any free range, and
	 * "free" is a lie while the flat view spans 0x60000000..). */
	th = nt->CreateThread(NULL, 1 << 20, netstack_spawn_thread,
			      &req, 0, &tid);
	if (th == NULL)
		return (int)nt->RtlGetLastWin32Error();
	nt->NtWaitForSingleObject(th, 0, UML_NT_INFINITE);
	nt->CloseHandle(th);
	if (req.rc != 0)
		return req.rc;
	*pid_out = req.pid;
	os_info("net: helper spawned pid %lu (%s)\n", req.pid, req.cmd);
	return 0;
}

/* ---- SPSC frame ring (the D19 edge-capture handoff) ----------------- */

#define UML_NT_NET_RING_SLOTS 32 /* power of two */

struct uml_nt_net_slot {
	unsigned short len;
	unsigned char data[UML_NT_NET_FRAME_MAX];
};

struct uml_nt_net_ring {
	volatile unsigned int head; /* consumer index (vCPU poll) */
	volatile unsigned int tail; /* producer index (reader thread) */
	unsigned int drops;
	struct uml_nt_net_slot slot[UML_NT_NET_RING_SLOTS];
};

/* One device = one ring (allocated at open, kernel heap). The reader
 * publishes (memcpy + tail++), the poll drains (head++); free-running
 * counters, full = tail - head == SLOTS, empty = equal. */
static struct uml_nt_net_ring *net_ring;

static int net_ring_push(const unsigned char *frame, unsigned int len)
{
	unsigned int tail = net_ring->tail;
	unsigned int used = tail - net_ring->head;
	struct uml_nt_net_slot *s;

	while (used >= UML_NT_NET_RING_SLOTS) {
		/* Full: the reader blocks (TCP backpressure via an
		 * unread socket) instead of dropping — a dropped DHCP
		 * ACK or ARP reply costs seconds of guest timeouts. */
		LARGE_INTEGER d;

		d.QuadPart = -100000LL; /* 10ms, relative */
		nt->NtDelayExecution(0, &d);
		tail = net_ring->tail;
		used = tail - net_ring->head;
	}
	s = &net_ring->slot[tail & (UML_NT_NET_RING_SLOTS - 1)];
	s->len = (unsigned short)len;
	memcpy(s->data, frame, len);
	__sync_synchronize(); /* payload before the tail publish */
	net_ring->tail = tail + 1;
	return 0;
}

static int net_ring_pop(unsigned char *dst, unsigned int cap)
{
	unsigned int head = net_ring->head;
	struct uml_nt_net_slot *s;
	unsigned int len;

	if (head == net_ring->tail)
		return 0; /* empty — the poll's "no more" */
	__sync_synchronize(); /* tail acquire before the slot read */
	s = &net_ring->slot[head & (UML_NT_NET_RING_SLOTS - 1)];
	len = s->len;
	if (len > cap)
		len = cap; /* truncate like a short seqpacket recv */
	memcpy(dst, s->data, len);
	net_ring->head = head + 1;
	return (int)len;
}

/* ---- the aux reader thread (D19: edge-capture only) ------------------ */

struct uml_nt_net_dev {
	int fd;               /* the registry/socket key */
	unsigned long long s; /* the SOCKET (full width) */
};

static struct uml_nt_net_dev net_dev;

/* M5.1c.5: the ring's identity for the crash reporter (see
 * internal.h). ring_addr = 0 before the first vector open. */
void uml_nt_net_ring_info(unsigned long long *addr,
			  unsigned long long *head,
			  unsigned long long *tail)
{
	*addr = (unsigned long long)(uintptr_t)net_ring;
	*head = net_ring != NULL ? net_ring->head : 0;
	*tail = net_ring != NULL ? net_ring->tail : 0;
}

/* Blocking framed recv of exactly `need` bytes. 0 recv = EOF → the
 * channel is dead: park the thread loudly (never exit the process —
 * the kernel keeps running, the device is just dead). */
static int recv_exact(unsigned long long s, unsigned char *buf,
		      unsigned int need)
{
	unsigned int total = 0;

	while (total < need) {
		int got = nt->recv(s, (char *)buf + total,
				   (int)(need - total), 0);

		if (got <= 0)
			return -1;
		total += (unsigned int)got;
	}
	return (int)total;
}

static unsigned long __attribute__((ms_abi)) net_reader_thread(void *arg)
{
	struct uml_nt_net_dev *dev = arg;
	static unsigned char frame[UML_NT_NET_FRAME_MAX];
	unsigned char head[2];
	int n;

	uml_nt_thread_role = "net-reader";

	for (;;) {
		if (recv_exact(dev->s, head, 2) < 0)
			break;
		n = ((int)head[0] << 8) | head[1];
		if (n <= 0 || n > UML_NT_NET_FRAME_MAX) {
			os_warn("net: reader: bad frame length %d — "
				"channel desync, device dead\n", n);
			break;
		}
		if (recv_exact(dev->s, frame, (unsigned int)n) < 0)
			break;
		net_ring_push(frame, (unsigned int)n);
		/* The handoff: registry + SIGIO flag + wake. No kernel
		 * code here (D19). */
		uml_nt_net_rx_ready(dev->fd);
	}
	os_warn("net: reader thread parked — TCP channel closed/errored "
		"(code %d)\n", nt->WSAGetLastError());
	for (;;)
		nt->NtDelayExecution(0, &(LARGE_INTEGER){
			.QuadPart = -100000000LL /* 10s */ });
	return 0;
}

/* ---- transport open: spawn + dial + reader --------------------------- */

/* The whole NT-heavy body runs on a fat thread (the house rule —
 * probe/spawn precedent): the boot/vCPU stack is a UML THREAD_SIZE
 * stack by discipline, and the first winsock call on a thread pulls
 * lazy per-thread init frames on top of whatever kernel syscall path
 * is already running — the native CI faulted c00000fd (stack
 * overflow) dialing from the ioctl path directly. */
struct uml_nt_open_ctx {
	int unit;
	const char *vnl;
	unsigned long long s;   /* the dialed socket (INVALID on fail) */
	int attempt;            /* the attempt that succeeded (or 50) */
	unsigned long pid;      /* the spawned helper's pid, diagnostic */
	int spawned;            /* netstack_spawn's rc */
};

/* One thread, the whole NT-heavy open: spawn the helper, then dial
 * with retry — the helper needs a moment to bind (and a freshly
 * spawned one starts listening asynchronously). 50 × 100ms = 5s,
 * then the device open fails loudly. */
static unsigned long __attribute__((ms_abi)) uml_nt_open_thread(void *arg)
{
	struct uml_nt_open_ctx *ctx = arg;
	LARGE_INTEGER d;
	int attempt;

	uml_nt_thread_role = "net-open";

	if (uml_nt_ws_init() == 0) {
		if (have_netstack) {
			ctx->spawned = netstack_spawn(ctx->unit, ctx->vnl,
						      &ctx->pid);
			if (ctx->spawned != 0)
				os_warn("net: helper spawn failed (win32 "
					"%d) — assuming an external helper "
					"on %s\n",
					ctx->spawned, ctx->vnl);
		}

		d.QuadPart = -1000000LL; /* 100ms, relative */
		for (attempt = 0; attempt < 50; attempt++) {
			ctx->s = uml_nt_net_dial(ctx->vnl);
			if (ctx->s != UML_NT_INVALID_SOCKET)
				break;
			nt->NtDelayExecution(0, &d);
		}
		ctx->attempt = attempt;
	}
	return 0;
}

struct vector_fds *uml_vector_user_open(int unit, struct arglist *parsed)
{
	char *transport, *vnl;
	struct uml_nt_open_ctx ctx;
	struct vector_fds *result;
	ULONG tid;
	HANDLE th;

	if (parsed == NULL)
		return NULL;
	transport = uml_vector_fetch_arg(parsed, "transport");
	if (transport == NULL ||
	    strncmp(transport, "vde", strlen("vde")) != 0) {
		os_warn("net: transport '%s' unsupported on NT (want vde — "
			"the D8 TCP channel)\n",
			transport ? transport : "(none)");
		return NULL;
	}
	vnl = uml_vector_fetch_arg(parsed, "vnl");
	if (vnl == NULL) {
		os_warn("net: vde transport needs vnl=HOST:PORT (the "
			"tcplisten address of the netstack helper)\n");
		return NULL;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.unit = unit;
	ctx.vnl = vnl;
	ctx.s = UML_NT_INVALID_SOCKET;

	/* Fat thread: spawn + dial + winsock (see the ctx comment). */
	th = nt->CreateThread(NULL, 1 << 20, uml_nt_open_thread, &ctx, 0,
			      &tid);
	if (th == NULL) {
		os_warn("net: open thread failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		return NULL;
	}
	os_info("net: open thread tid=%lu\n", tid);
	nt->NtWaitForSingleObject(th, 0, UML_NT_INFINITE);
	nt->CloseHandle(th);

	if (ctx.s == UML_NT_INVALID_SOCKET) {
		os_warn("net: dial %s exhausted (%d attempts, helper %s) "
			"— device dead\n",
			vnl, ctx.attempt,
			have_netstack ? (ctx.spawned == 0 ? "spawned"
							  : "spawn FAILED")
				      : "external");
		return NULL;
	}
	os_info("net: dialed %s (helper %s, attempt %d)\n", vnl,
		have_netstack ? "spawned" : "external", ctx.attempt + 1);

	net_ring = uml_kmalloc(sizeof(*net_ring), UM_GFP_KERNEL);
	if (net_ring == NULL) {
		nt->closesocket(ctx.s);
		return NULL;
	}
	net_ring->head = 0;
	net_ring->tail = 0;
	net_ring->drops = 0;

	net_dev.fd = (int)ctx.s;
	net_dev.s = ctx.s;

	th = nt->CreateThread(NULL, 1 << 20, net_reader_thread, &net_dev,
			      0, &tid);
	if (th == NULL) {
		os_warn("net: reader thread failed win32=%lu\n",
			nt->RtlGetLastWin32Error());
		nt->closesocket(ctx.s);
		return NULL;
	}
	os_info("net: reader thread tid=%lu\n", tid);
	/* Detached: the thread parks forever when the channel dies
	 * (never exits the process); the handle leaks with the boot. */
	nt->CloseHandle(th);

	result = uml_kmalloc(sizeof(struct vector_fds), UM_GFP_KERNEL);
	if (result == NULL) {
		nt->closesocket(ctx.s);
		return NULL;
	}
	result->rx_fd = (int)ctx.s;
	result->tx_fd = (int)ctx.s;
	result->remote_addr = NULL;
	result->remote_addr_size = 0;
	os_info("net: vec%d open — D8 TCP channel live (ring %d x %d)\n",
		unit, UML_NT_NET_RING_SLOTS, UML_NT_NET_FRAME_MAX);
	return result;
}

/* ---- frame io ---------------------------------------------------------
 * The mmsg shapes are what the default VDE options (VECTOR_RX|VECTOR_
 * TX) drive; recvmsg/writev are the legacy (vec=0) shapes. All share
 * the ring (RX) / the framed send (TX). A frame longer than the
 * destination truncates (a short seqpacket recv); the RX side never
 * blocks — the ring already holds the bytes. */

static unsigned int iov_len_total(const struct iovec *iov, int iovcnt)
{
	unsigned int total = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		total += (unsigned int)iov[i].iov_len;
	return total;
}

static int iov_fill(const struct iovec *iov, int iovcnt,
		    const unsigned char *src, unsigned int len)
{
	unsigned int off = 0;

	while (off < len && iovcnt > 0) {
		unsigned int n = len - off;

		if ((unsigned int)iov->iov_len < n)
			n = (unsigned int)iov->iov_len;
		if (n) {
			memcpy(iov->iov_base, src + off, n);
			off += n;
		}
		iov++;
		iovcnt--;
	}
	return (int)off;
}

int uml_vector_recvmsg(int fd, void *hdr, int flags)
{
	struct user_msghdr *msg = hdr;

	(void)flags;
	if (msg == NULL || msg->msg_iov == NULL || msg->msg_iovlen < 1)
		return -EINVAL;
	return net_ring_pop(msg->msg_iov[0].iov_base,
			    (unsigned int)msg->msg_iov[0].iov_len);
}

int uml_vector_writev(int fd, void *hdr, int iovcount)
{
	static unsigned char out[UML_NT_NET_FRAME_MAX]; /* vCPU-only */
	static int tx_once;
	const struct iovec *iv = hdr;
	unsigned int total, off = 0;
	int i, rc;

	if (iv == NULL || iovcount < 1)
		return -EINVAL;
	total = iov_len_total(iv, iovcount);
	if (total == 0 || total > UML_NT_NET_FRAME_MAX)
		return -EINVAL;
	if (!tx_once) {
		tx_once = 1;
		os_info("net: first TX (%u bytes, fd %d)\n", total, fd);
	}
	/* The frame = the iovs concatenated (upstream writev sends the
	 * scatter-gather as ONE datagram on the seqpacket pair; on the
	 * TCP stream the 2-byte prefix re-marks the boundary). */
	for (i = 0; i < iovcount; i++) {
		memcpy(out + off, iv[i].iov_base, iv[i].iov_len);
		off += (unsigned int)iv[i].iov_len;
	}
	rc = uml_nt_net_send_frame(net_dev.s, out, total);
	if (rc != 0)
		return rc;
	return (int)total;
}

int uml_vector_sendmsg(int fd, void *hdr, int flags)
{
	struct user_msghdr *msg = hdr;

	(void)flags;
	if (msg == NULL || msg->msg_iov == NULL || msg->msg_iovlen < 1)
		return -EINVAL;
	return uml_vector_writev(fd, msg->msg_iov, (int)msg->msg_iovlen);
}

int uml_vector_sendmmsg(int fd, void *msgvec, unsigned int vlen,
			unsigned int flags)
{
	struct mmsghdr *mv = msgvec;
	unsigned int i, sent = 0;

	(void)flags;
	if (mv == NULL)
		return -EINVAL;
	for (i = 0; i < vlen; i++) {
		struct user_msghdr *mh = &mv[i].msg_hdr;
		int rc;

		if (mh->msg_iov == NULL || mh->msg_iovlen < 1)
			break;
		rc = uml_vector_writev(net_dev.fd, mh->msg_iov,
				       (int)mh->msg_iovlen);
		if (rc < 0)
			break;
		mv[i].msg_len = (unsigned int)rc;
		sent++;
	}
	return (int)sent;
}

int uml_vector_recvmmsg(int fd, void *msgvec, unsigned int vlen,
			unsigned int flags)
{
	static unsigned char frame[UML_NT_NET_FRAME_MAX]; /* vCPU-only */
	struct mmsghdr *mv = msgvec;
	unsigned int i;

	(void)flags;
	if (mv == NULL)
		return -EINVAL;
	for (i = 0; i < vlen; i++) {
		struct user_msghdr *mh = &mv[i].msg_hdr;
		unsigned int cap;
		int n;

		if (mh->msg_iov == NULL || mh->msg_iovlen < 1)
			break;
		cap = iov_len_total(mh->msg_iov, (int)mh->msg_iovlen);
		if (cap > UML_NT_NET_FRAME_MAX)
			cap = UML_NT_NET_FRAME_MAX;
		n = net_ring_pop(frame, cap);
		if (n <= 0)
			break; /* ring empty — done */
		mv[i].msg_len = (unsigned int)iov_fill(
			mh->msg_iov, (int)mh->msg_iovlen, frame,
			(unsigned int)n);
	}
	return (int)i;
}

/* ---- filters/offloads: the TCP transport has none (upstream VDE
 * socketpair shape: no encapsulation headers, no bpf attach) ---------- */

int uml_vector_attach_bpf(int fd, void *bpf)
{
	(void)fd; (void)bpf;
	return 0;
}

int uml_vector_detach_bpf(int fd, void *bpf)
{
	(void)fd; (void)bpf;
	return 0;
}

void *uml_vector_default_bpf(const void *mac)
{
	(void)mac;
	return NULL;
}

void *uml_vector_user_bpf(char *filename)
{
	(void)filename;
	return NULL;
}

bool uml_raw_enable_qdisc_bypass(int fd)
{
	(void)fd;
	return false;
}

bool uml_raw_enable_vnet_headers(int fd)
{
	(void)fd;
	return false;
}

bool uml_tap_enable_vnet_headers(int fd)
{
	(void)fd;
	return false;
}
