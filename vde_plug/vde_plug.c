/*
 * vde_plug — monolithic static build for UML VECTOR transport
 *
 * Replaces: vde_plug + libvdeplug.so + libvdeplug_slirp.so + libvdeslirp.so + libslirp.so
 * Single static binary, zero runtime deps, no dlopen().
 *
 * Protocol: UML kernel fork/execs "vde_plug" with a seqpacket socketpair,
 * then sends/receives Ethernet frames as length-prefixed messages.
 * This binary bridges those frames to libslirp for NAT.
 *
 * Based on vdeplug4 (Renzo Davoli, GPLv2+) and libvdeplug_slirp (LGPLv2.1+).
 * Monolithic integration by slirp-rewrite project.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <getopt.h>

#ifdef STATIC_BUILD
#include <libvdeslirp.h>
#else
#include <slirp/libvdeslirp.h>
#endif

/* ── Constants ── */
#define VDE_MAXMTU     9216
#define VDE_ETHBUFSIZE (VDE_MAXMTU + 14 + 4)
#define MAXPACKET      (VDE_ETHBUFSIZE + 2)
#define ETH_HDRLEN     14

/* ── Forward declarations ── */
struct vdeparms { char *tag; char **value; };
static int vde_parseparms(char *str, struct vdeparms *parms);

/* ── vdestream: length-prefixed framing over a pipe/fd ── */
typedef struct vdestream {
	int fdout;
	void *opaque;
	ssize_t (*frecv)(void *opaque, void *buf, size_t count);
	char fragment[MAXPACKET];
	char *fragp;
	unsigned int rnx, remaining;
} VDESTREAM;

static VDESTREAM *vdestream_open(void *opaque, int fdout,
		ssize_t (*frecv)(void *opaque, void *buf, size_t count))
{
	VDESTREAM *vs = calloc(1, sizeof(*vs));
	if (!vs) return NULL;
	vs->opaque = opaque;
	vs->fdout = fdout;
	vs->frecv = frecv;
	return vs;
}

static ssize_t vdestream_send(VDESTREAM *vs, const void *buf, size_t len)
{
	if (len > MAXPACKET) return 0;
	unsigned char hdr[2] = { len >> 8, len & 0xff };
	struct iovec iov[2] = { {hdr, 2}, {(void*)buf, len} };
	return writev(vs->fdout, iov, 2);
}

static void vdestream_recv(VDESTREAM *vs, unsigned char *buf, size_t len)
{
	if (len == 0) return;
	if (vs->rnx > 0) {
		size_t amt = (vs->remaining < len) ? vs->remaining : len;
		memcpy(vs->fragp, buf, amt);
		vs->remaining -= amt;
		vs->fragp += amt;
		buf += amt; len -= amt;
		if (vs->remaining == 0) {
			vs->frecv(vs->opaque, vs->fragment, vs->rnx);
			vs->rnx = 0;
		}
	}
	while (len > 1) {
		vs->rnx = (buf[0] << 8) | buf[1];
		len -= 2; buf += 2;
		if (vs->rnx == 0) continue;
		if (vs->rnx > MAXPACKET) { vs->rnx = 0; return; }
		if (vs->rnx > len) {
			vs->fragp = vs->fragment;
			memcpy(vs->fragp, buf, len);
			vs->remaining = vs->rnx - len;
			vs->fragp += len;
			len = 0;
		} else {
			vs->frecv(vs->opaque, buf, vs->rnx);
			buf += vs->rnx; len -= vs->rnx;
			vs->rnx = 0;
		}
	}
}

/* ── Globals ── */
static struct vdeslirp *slirp;
static VDESTREAM *stream;
static volatile sig_atomic_t running = 1;

/* ── Signal handler ── */
static void sig_handler(int sig) { (void)sig; running = 0; }

/* ── Callback: frame from slirp → send to UML kernel via stream ── */
static ssize_t stream_to_kernel(void *opaque, void *buf, size_t count)
{
	(void)opaque;
	return vdestream_send(stream, buf, count);
}

/* ── parseparms (simplified from vdeplug4) ── */
static int vde_parseparms(char *str, struct vdeparms *parms)
{
	if (!str || !*str) return 0;
	char *saveptr, *token;
	for (token = strtok_r(str, "/", &saveptr); token;
			token = strtok_r(NULL, "/", &saveptr)) {
		char *eq = strchr(token, '=');
		if (!eq) continue;
		*eq = '\0';
		char *key = token, *val = eq + 1;
		for (struct vdeparms *p = parms; p->tag; p++) {
			if (strcmp(p->tag, key) == 0) {
				*(p->value) = val;
				break;
			}
		}
	}
	return 0;
}

/* ── Port forwarding helper ── */
static void do_fwd(struct vdeslirp *s, int is_udp, char *arg)
{
	if (!arg) return;
	char *save, *item;
	for (item = strtok_r(arg, ",", &save); item;
			item = strtok_r(NULL, ",", &save)) {
		char *f, *ha, *hp, *ga, *gp;
		ha = strtok_r(item, ":", &f);
		hp = strtok_r(NULL, ":", &f);
		ga = strtok_r(NULL, ":", &f);
		gp = strtok_r(NULL, "", &f);
		if (!gp) { gp = ga; ga = hp; hp = ha; ha = "0.0.0.0"; }
		if (!ha[0]) ha = "0.0.0.0";
		struct in_addr host_addr, guest_addr;
		if (inet_pton(AF_INET, ha, &host_addr) == 1 &&
				inet_pton(AF_INET, ga, &guest_addr) == 1) {
			int r = vdeslirp_add_fwd(s, is_udp, host_addr, atoi(hp),
					guest_addr, atoi(gp));
			fprintf(stderr, "[vde_plug] %sfwd %s:%s -> %s:%s: %s\n",
					is_udp ? "udp" : "tcp", ha, hp, ga, gp,
					r == 0 ? "ok" : strerror(errno));
		}
	}
}

/* ── Main ── */
int main(int argc, char *argv[])
{
	/* UML kernel passes: vde_plug --descr UML seqpacket://FD vnl
	 * We need to parse VNL (e.g. "slirp://") to get slirp options,
	 * and use the seqpacket FD for Ethernet frame exchange. */

	char *vnl = NULL;
	char *descr = NULL;
	int seqpacket_fd = -1;

	/* Parse args the same way UML sends them */
	static struct option long_options[] = {
		{"descr",  required_argument, 0, 'D'},
		{"port2",  required_argument, 0, 'P'},
		{"mod2",   required_argument, 0, 'M'},
		{"group2", required_argument, 0, 'G'},
		{0, 0, 0, 0}
	};

	int c;
	while ((c = getopt_long(argc, argv, "D:P:M:G:", long_options, NULL)) != -1) {
		switch (c) {
			case 'D': descr = optarg; break;
			default: break;
		}
	}

	/* Remaining args: seqpacket://FD vnl */
	for (int i = optind; i < argc; i++) {
		if (strncmp(argv[i], "seqpacket://", 12) == 0) {
			seqpacket_fd = atoi(argv[i] + 12);
		} else if (!vnl) {
			vnl = argv[i];
		}
	}

	if (seqpacket_fd < 0) {
		/* Fallback: stream mode on stdin/stdout (for testing) */
		seqpacket_fd = -1;
	}

	/* Parse VNL: strip "slirp://" prefix, rest is params */
	char *params = NULL;
	if (vnl) {
		if (strncmp(vnl, "slirp://", 8) == 0)
			params = vnl + 8;
		else
			params = vnl;
	}

	/* Parse slirp parameters from VNL */
	char *host4 = NULL, *tcpfwd = NULL, *udpfwd = NULL;
	char *mtu = NULL, *mru = NULL, *dhcp = NULL;
	char *vnameserver = NULL, *vhostname = NULL;
	char *verbose = NULL;
	struct vdeparms vparms[] = {
		{"host", &host4}, {"addr", &host4},
		{"dhcp", &dhcp},
		{"vnameserver", &vnameserver},
		{"hostname", &vhostname},
		{"mtu", &mtu}, {"mru", &mru},
		{"tcpfwd", &tcpfwd}, {"udpfwd", &udpfwd},
		{"verbose", &verbose},
		{NULL, NULL}
	};
	if (params && *params)
		vde_parseparms(params, vparms);

	/* Init slirp */
	SlirpConfig cfg;
	vdeslirp_init(&cfg, VDE_INIT_DEFAULT);
	if (host4) {
		int prefix = 24;
		char *slash = strchr(host4, '/');
		if (slash) { prefix = atoi(slash+1); *slash = 0; }
		inet_pton(AF_INET, host4, &cfg.vhost);
		vdeslirp_setvprefix(&cfg, prefix);
	}
	if (dhcp) inet_pton(AF_INET, dhcp, &cfg.vdhcp_start);
	if (vnameserver) inet_pton(AF_INET, vnameserver, &cfg.vnameserver);
	if (vhostname) cfg.vhostname = vhostname;
	if (mtu) cfg.if_mtu = atoi(mtu);
	if (mru) cfg.if_mru = atoi(mru);

	slirp = vdeslirp_open(&cfg);
	if (!slirp) {
		fprintf(stderr, "[vde_plug] vdeslirp_open failed: %s\n", strerror(errno));
		return 1;
	}

	do_fwd(slirp, 0, tcpfwd);
	do_fwd(slirp, 1, udpfwd);

	int slirp_fd = vdeslirp_fd(slirp);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	fprintf(stderr, "[vde_plug] started (descr=%s, vnl=%s, fd=%d, slirp_fd=%d)\n",
			descr ? descr : "none", vnl ? vnl : "none",
			seqpacket_fd, slirp_fd);

	if (seqpacket_fd >= 0) {
		/* === SEQPACKET MODE (normal UML operation) === */
		/* Each recv/send on the seqpacket socket is one Ethernet frame */
		unsigned char buf[VDE_ETHBUFSIZE];
		struct pollfd pfd[2] = {
			{ .fd = seqpacket_fd, .events = POLLIN },
			{ .fd = slirp_fd,     .events = POLLIN },
		};

		while (running) {
			int n = poll(pfd, 2, 1000);
			if (n < 0) { if (errno == EINTR) continue; break; }

			if (pfd[0].revents & (POLLHUP | POLLERR)) break;
			if (pfd[1].revents & (POLLHUP | POLLERR)) break;

			/* Frames from UML kernel → slirp */
			if (pfd[0].revents & POLLIN) {
				ssize_t rx = recv(seqpacket_fd, buf, sizeof(buf), 0);
				if (rx <= 0) break;
				vdeslirp_send(slirp, buf, rx);
			}

			/* Frames from slirp → UML kernel */
			if (pfd[1].revents & POLLIN) {
				ssize_t rx = vdeslirp_recv(slirp, buf, sizeof(buf));
				if (rx > 0)
					send(seqpacket_fd, buf, rx, 0);
			}
		}
	} else {
		/* === STREAM MODE (stdin/stdout, for testing or pipe) === */
		stream = vdestream_open(NULL, STDOUT_FILENO, stream_to_kernel);
		if (!stream) { fprintf(stderr, "[vde_plug] vdestream_open failed\n"); return 1; }

		unsigned char buf[VDE_ETHBUFSIZE];
		struct pollfd pfd[2] = {
			{ .fd = STDIN_FILENO, .events = POLLIN },
			{ .fd = slirp_fd,     .events = POLLIN },
		};

		while (running) {
			int n = poll(pfd, 2, 1000);
			if (n < 0) { if (errno == EINTR) continue; break; }

			if (pfd[0].revents & POLLHUP) break;

			if (pfd[0].revents & POLLIN) {
				ssize_t rx = read(STDIN_FILENO, buf, sizeof(buf));
				if (rx <= 0) break;
				vdestream_recv(stream, buf, rx);
			}

			if (pfd[1].revents & POLLIN) {
				ssize_t rx = vdeslirp_recv(slirp, buf, sizeof(buf));
				if (rx >= ETH_HDRLEN)
					vdestream_send(stream, buf, rx);
			}
		}
		free(stream);
	}

	vdeslirp_close(slirp);
	fprintf(stderr, "[vde_plug] shutdown\n");
	return 0;
}
