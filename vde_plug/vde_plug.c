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
 * Config: reads config.yaml from same directory as binary for port forwards,
 * IPv6 settings, etc. VNL params override config file.
 *
 * Based on vdeplug4 (Renzo Davoli, GPLv2+) and libvdeplug_slirp (LGPLv2.1+).
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
#include <arpa/inet.h>
#include <getopt.h>
#include <libgen.h>

#ifdef STATIC_BUILD
#include <libvdeslirp.h>
#else
#include <slirp/libvdeslirp.h>
#endif

#define VDE_ETHBUFSIZE (9216 + 14 + 4)
#define ETH_HDRLEN     14
#define MAX_LINE       512
#define MAX_PORTS      64

/* ── Port forward entry ── */
struct portfwd {
	int is_udp;
	struct in_addr host_addr;
	int host_port;
	struct in_addr guest_addr;
	int guest_port;
};

/* ── Globals ── */
static struct vdeslirp *slirp;
static volatile sig_atomic_t running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

/* ── Config ── */
struct config {
	int ipv6;
	int portfwd;
	struct portfwd ports[MAX_PORTS];
	int nports;
};

/* Trim leading/trailing whitespace */
static char *trim(char *s) {
	while (*s == ' ' || *s == '\t') s++;
	char *e = s + strlen(s) - 1;
	while (e > s && (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r')) *e-- = '\0';
	return s;
}

/* Strip quotes */
static char *unquote(char *s) {
	size_t len = strlen(s);
	if (len >= 2 && ((s[0] == '"' && s[len-1] == '"') || (s[0] == '\'' && s[len-1] == '\''))) {
		s[len-1] = '\0';
		return s + 1;
	}
	return s;
}

/* Parse config.yaml - lightweight, no libyaml needed */
static void parse_config(const char *path, struct config *cfg) {
	memset(cfg, 0, sizeof(*cfg));

	FILE *f = fopen(path, "r");
	if (!f) return;

	char line[MAX_LINE];
	int in_ports = 0;

	while (fgets(line, sizeof(line), f)) {
		/* Check indentation before trimming */
		int indented = (line[0] == ' ' || line[0] == '\t');
		char *p = trim(line);
		if (*p == '#' || *p == '\0') continue;

		/* port list items (indented lines starting with -) */
		if (in_ports && indented && p[0] == '-') {
			if (cfg->nports >= MAX_PORTS) continue;
			p = trim(p + 1);
			/* strip inline comment first */
			char *hash = strchr(p, '#');
			if (hash) *hash = '\0';
			p = trim(p);
			p = unquote(p);

			struct portfwd *pf = &cfg->ports[cfg->nports];
			pf->is_udp = 0;
			if (strncmp(p, "udp ", 4) == 0) { pf->is_udp = 1; p += 4; }
			else if (strncmp(p, "tcp ", 4) == 0) { p += 4; }

			char *colon = strchr(p, ':');
			if (!colon) continue;
			*colon = '\0';
			pf->host_port = atoi(trim(p));
			pf->guest_port = atoi(trim(colon + 1));
			if (pf->host_port <= 0 || pf->guest_port <= 0) continue;
			inet_pton(AF_INET, "0.0.0.0", &pf->host_addr);
			inet_pton(AF_INET, "10.0.2.15", &pf->guest_addr);
			cfg->nports++;
			continue;
		}

		/* End of port list on non-indented line */
		if (!indented) in_ports = 0;

		char *colon = strchr(p, ':');
		if (!colon) continue;
		*colon = '\0';
		char *key = trim(p);
		char *val = trim(colon + 1);

		if (strcmp(key, "ipv6") == 0)
			cfg->ipv6 = (strcmp(val, "true") == 0);
		else if (strcmp(key, "portfwd") == 0)
			cfg->portfwd = (strcmp(val, "true") == 0);
		else if (strcmp(key, "ports") == 0)
			in_ports = 1;
	}
	fclose(f);
}

/* ── VNL parameter parsing (simple key=val/key=val) ── */
static void parse_vnl_params(char *params, SlirpConfig *cfg, int *has_v6) {
	if (!params || !*params) return;
	char *save, *tok;
	for (tok = strtok_r(params, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
		char *eq = strchr(tok, '=');
		if (!eq) continue;
		*eq = '\0';
		char *k = tok, *v = eq + 1;
		if (strcmp(k, "v6") == 0 && strcmp(v, "1") == 0) *has_v6 = 1;
		else if (strcmp(k, "host") == 0 || strcmp(k, "addr") == 0) {
			char *slash = strchr(v, '/'); int prefix = 24;
			if (slash) { prefix = atoi(slash+1); *slash = 0; }
			inet_pton(AF_INET, v, &cfg->vhost);
			vdeslirp_setvprefix(cfg, prefix);
		}
		else if (strcmp(k, "mtu") == 0) cfg->if_mtu = atoi(v);
		else if (strcmp(k, "mru") == 0) cfg->if_mru = atoi(v);
	}
}

/* ── Main ── */
int main(int argc, char *argv[])
{
	char *vnl = NULL;
	char *descr = NULL;
	int seqpacket_fd = -1;

	/* Parse args (UML passes: vde_plug --descr UML seqpacket://FD vnl) */
	static struct option long_options[] = {
		{"descr",  required_argument, 0, 'D'},
		{"port2",  required_argument, 0, 'P'},
		{"mod2",   required_argument, 0, 'M'},
		{"group2", required_argument, 0, 'G'},
		{0, 0, 0, 0}
	};
	int c;
	while ((c = getopt_long(argc, argv, "D:P:M:G:", long_options, NULL)) != -1) {
		if (c == 'D') descr = optarg;
	}
	for (int i = optind; i < argc; i++) {
		if (strncmp(argv[i], "seqpacket://", 12) == 0)
			seqpacket_fd = atoi(argv[i] + 12);
		else if (!vnl)
			vnl = argv[i];
	}

	/* Find config.yaml next to binary */
	char config_path[4096];
	{
		char self[4096];
		ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
		if (n > 0) {
			self[n] = '\0';
			char *dir = dirname(self);
			snprintf(config_path, sizeof(config_path), "%s/config.yaml", dir);
		} else {
			strcpy(config_path, "config.yaml");
		}
	}

	/* Parse config file */
	struct config cfg_file;
	parse_config(config_path, &cfg_file);

	/* Parse VNL: strip "slirp://" prefix */
	char *params = NULL;
	if (vnl && strncmp(vnl, "slirp://", 8) == 0)
		params = vnl + 8;

	/* Init slirp config */
	SlirpConfig scfg;
	vdeslirp_init(&scfg, VDE_INIT_DEFAULT);

	/* Apply IPv6 from config file */
	int has_v6 = cfg_file.ipv6;

	/* Apply VNL params (override config) */
	if (params && *params) {
		char *pcopy = strdup(params);
		parse_vnl_params(pcopy, &scfg, &has_v6);
		free(pcopy);
	}

	if (has_v6) {
		scfg.in6_enabled = 1;
	} else {
		scfg.in6_enabled = 0;
	}

	slirp = vdeslirp_open(&scfg);
	if (!slirp) {
		fprintf(stderr, "[vde_plug] vdeslirp_open: %s\n", strerror(errno));
		return 1;
	}

	/* Apply port forwards from config */
	if (cfg_file.portfwd) {
		for (int i = 0; i < cfg_file.nports; i++) {
			struct portfwd *pf = &cfg_file.ports[i];
			int r = vdeslirp_add_fwd(slirp, pf->is_udp,
					pf->host_addr, pf->host_port,
					pf->guest_addr, pf->guest_port);
			fprintf(stderr, "[vde_plug] %sfwd :%d -> 10.0.2.15:%d %s\n",
					pf->is_udp ? "udp" : "tcp",
					pf->host_port, pf->guest_port,
					r == 0 ? "ok" : strerror(errno));
		}
	}

	int slirp_fd = vdeslirp_fd(slirp);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	fprintf(stderr, "[vde_plug] started (descr=%s vnl=%s fd=%d slirp_fd=%d ipv6=%d ports=%d)\n",
			descr ? descr : "-", vnl ? vnl : "-",
			seqpacket_fd, slirp_fd, has_v6, cfg_file.nports);

	/* === SEQPACKET MODE (normal UML operation) === */
	if (seqpacket_fd >= 0) {
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
			if (pfd[0].revents & POLLIN) {
				ssize_t rx = recv(seqpacket_fd, buf, sizeof(buf), 0);
				if (rx <= 0) break;
				vdeslirp_send(slirp, buf, rx);
			}
			if (pfd[1].revents & POLLIN) {
				ssize_t rx = vdeslirp_recv(slirp, buf, sizeof(buf));
				if (rx > 0)
					send(seqpacket_fd, buf, rx, 0);
			}
		}
	} else {
		fprintf(stderr, "[vde_plug] no seqpacket fd, nothing to do\n");
		vdeslirp_close(slirp);
		return 1;
	}

	vdeslirp_close(slirp);
	fprintf(stderr, "[vde_plug] shutdown\n");
	return 0;
}
