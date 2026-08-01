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
 * Two operating modes:
 *
 *   1. STANDALONE (switch: false) — classic behaviour. One slirp NAT stack per
 *      instance, guest always ends up on 10.0.2.15.
 *
 *   2. SWITCH (switch: true, default) — instances on the same host share an
 *      L2 broadcast domain through a unix SEQPACKET socket (vde.socket).
 *      The first instance to bind the socket becomes the HUB: it runs the
 *      learning switch plus the uplink (slirp NAT or a host tap device).
 *      Later instances become PEERs: pure wires into the hub.
 *
 *      Because every guest shares one segment, addresses come from a single
 *      DHCP server (slirp's, or the real LAN's when uplink=tap). Guests get
 *      distinct leases (10.0.2.15, .16, .17 ...) instead of all claiming .15.
 *
 * Config: reads config.yaml from same directory as binary for port forwards,
 * IPv6 settings, network/DHCP range, switch socket, uplink. VNL params override.
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
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <libgen.h>
#include <net/if.h>
#include <linux/if_tun.h>

#ifdef STATIC_BUILD
#include <libvdeslirp.h>
#else
#include <slirp/libvdeslirp.h>
#endif

#define VDE_ETHBUFSIZE (9216 + 14 + 4)
#define ETH_HDRLEN     14
#define MAX_LINE       512
#define MAX_PORTS      64

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ── Port forward entry ── */
struct portfwd {
	int is_udp;
	struct in_addr host_addr;
	int host_port;
	int guest_port;

	/*
	 * Guest target, resolved in this order:
	 *   guest_addr != 0   explicit address from the config
	 *   last_octet >= 1   ".N" shorthand, completed with the virtual network
	 *   otherwise         fallback rule — follows the first client on the
	 *                     segment, re-pointed once its lease is observed
	 */
	struct in_addr guest_addr;
	int last_octet;

	int applied;                   /* currently installed in slirp */
	struct in_addr applied_to;     /* address it is installed for */
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

	/* switch / private network */
	int sw_enabled;               /* switch: true|false            */
	char sw_socket[PATH_MAX];     /* socket: /tmp/vde.socket       */
	int sw_mode;                  /* socket_mode: 0600             */

	/* uplink */
	char uplink[64];              /* uplink: slirp | tap:NAME      */

	/* virtual network (slirp uplink only) */
	char network[64];             /* network: 10.0.2.0/24          */
	char host_addr[64];           /* host: 10.0.2.2                */
	char dhcp_start[64];          /* dhcp_start: 10.0.2.15         */
	char nameserver[64];          /* nameserver: 10.0.2.3          */
	char hostname[64];            /* hostname: uml                 */
	int mtu;
};

static struct config cfg_file;

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

static int parse_bool(const char *v) {
	return (strcmp(v, "true") == 0 || strcmp(v, "yes") == 0 ||
	        strcmp(v, "on") == 0   || strcmp(v, "1") == 0);
}

static void copy_str(char *dst, size_t n, const char *src) {
	snprintf(dst, n, "%s", src);
}

/*
 * Parse the address/port part of a forward rule.
 *
 *   "2222:22"           → fallback, follows the first client to lease
 *   "10.0.2.16:2222:22" → pinned to that guest
 *   ".16:2222:22"       → same, host part completed from the virtual network
 *
 * Returns 0 on a malformed rule (caller skips it).
 */
static int parse_portfwd_spec(char *spec, struct portfwd *pf)
{
	char *c1 = strchr(spec, ':');
	if (!c1) return 0;
	char *c2 = strchr(c1 + 1, ':');

	if (!c2) {
		/* HOST:GUEST — no address, this is the fallback form */
		*c1 = '\0';
		pf->host_port  = atoi(trim(spec));
		pf->guest_port = atoi(trim(c1 + 1));
		pf->guest_addr.s_addr = 0;
		pf->last_octet = 0;
	} else {
		/* ADDR:HOST:GUEST */
		*c1 = '\0';
		*c2 = '\0';
		char *addr = trim(spec);
		pf->host_port  = atoi(trim(c1 + 1));
		pf->guest_port = atoi(trim(c2 + 1));

		if (addr[0] == '.') {
			/* ".N" shorthand — completed once the network is known */
			pf->last_octet = atoi(addr + 1);
			pf->guest_addr.s_addr = 0;
			if (pf->last_octet < 1 || pf->last_octet > 254) return 0;
		} else if (inet_pton(AF_INET, addr, &pf->guest_addr) != 1) {
			fprintf(stderr, "[vde_plug] portfwd: bad address '%s', ignored\n", addr);
			return 0;
		}
	}

	return (pf->host_port > 0 && pf->host_port < 65536 &&
	        pf->guest_port > 0 && pf->guest_port < 65536);
}

/* Parse config.yaml - lightweight, no libyaml needed */
static void parse_config(const char *path, struct config *cfg) {
	memset(cfg, 0, sizeof(*cfg));

	/* defaults */
	cfg->sw_enabled = 1;
	cfg->sw_mode = 0600;
	copy_str(cfg->uplink, sizeof(cfg->uplink), "slirp");

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
			memset(pf, 0, sizeof(*pf));
			if (strncmp(p, "udp ", 4) == 0) { pf->is_udp = 1; p += 4; }
			else if (strncmp(p, "tcp ", 4) == 0) { p += 4; }
			p = trim(p);

			/*
			 * Two accepted shapes:
			 *   HOST:GUEST              fallback — first client to lease
			 *   ADDR:HOST:GUEST         pinned to one guest address
			 * ADDR may be a full address (10.0.2.16) or the ".N"
			 * shorthand (.16), completed from the virtual network.
			 */
			if (!parse_portfwd_spec(p, pf)) continue;

			inet_pton(AF_INET, "0.0.0.0", &pf->host_addr);
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
		char *hash = strchr(val, '#');
		if (hash) { *hash = '\0'; val = trim(val); }
		val = unquote(val);

		if (strcmp(key, "ipv6") == 0)
			cfg->ipv6 = parse_bool(val);
		else if (strcmp(key, "portfwd") == 0)
			cfg->portfwd = parse_bool(val);
		else if (strcmp(key, "ports") == 0)
			in_ports = 1;
		else if (strcmp(key, "switch") == 0)
			cfg->sw_enabled = parse_bool(val);
		else if (strcmp(key, "socket") == 0)
			copy_str(cfg->sw_socket, sizeof(cfg->sw_socket), val);
		else if (strcmp(key, "socket_mode") == 0)
			cfg->sw_mode = (int)strtol(val, NULL, 8);
		else if (strcmp(key, "uplink") == 0)
			copy_str(cfg->uplink, sizeof(cfg->uplink), val);
		else if (strcmp(key, "network") == 0)
			copy_str(cfg->network, sizeof(cfg->network), val);
		else if (strcmp(key, "host") == 0 || strcmp(key, "gateway") == 0)
			copy_str(cfg->host_addr, sizeof(cfg->host_addr), val);
		else if (strcmp(key, "dhcp_start") == 0)
			copy_str(cfg->dhcp_start, sizeof(cfg->dhcp_start), val);
		else if (strcmp(key, "nameserver") == 0 || strcmp(key, "dns") == 0)
			copy_str(cfg->nameserver, sizeof(cfg->nameserver), val);
		else if (strcmp(key, "hostname") == 0)
			copy_str(cfg->hostname, sizeof(cfg->hostname), val);
		else if (strcmp(key, "mtu") == 0)
			cfg->mtu = atoi(val);
	}
	fclose(f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Switch socket path resolution
 *
 * Priority: config `socket:` → $VDE_SWITCH_SOCKET → /tmp/vde.socket →
 *           $TMPDIR/vde.socket → ./vde.socket (binary's own directory)
 *
 * Pterodactyl and similar sandboxes often have no writable /tmp, hence the
 * cascade. The chosen path is printed so peers can be pointed at it.
 * ══════════════════════════════════════════════════════════════════════════ */

/* Can we create a unix socket under this directory? */
static int dir_usable(const char *dir) {
	struct stat st;
	if (stat(dir, &st) != 0) return 0;
	if (!S_ISDIR(st.st_mode)) return 0;
	return access(dir, W_OK | X_OK) == 0;
}

static void resolve_switch_socket(char *out, size_t n, const char *self_dir)
{
	const char *env;

	/* 1. explicit config */
	if (cfg_file.sw_socket[0]) {
		copy_str(out, n, cfg_file.sw_socket);
		return;
	}

	/* 2. environment override */
	env = getenv("VDE_SWITCH_SOCKET");
	if (env && *env) {
		copy_str(out, n, env);
		return;
	}

	/* 3. /tmp — the shared location that lets sibling instances find us */
	if (dir_usable("/tmp")) {
		snprintf(out, n, "/tmp/vde.socket");
		return;
	}

	/* 4. $TMPDIR */
	env = getenv("TMPDIR");
	if (env && *env && dir_usable(env)) {
		snprintf(out, n, "%s/vde.socket", env);
		return;
	}

	/* 5. fall back to the binary's own directory */
	if (self_dir && dir_usable(self_dir)) {
		snprintf(out, n, "%s/vde.socket", self_dir);
		return;
	}

	/* 6. last resort: cwd */
	snprintf(out, n, "vde.socket");
}

/* ══════════════════════════════════════════════════════════════════════════
 * Learning switch
 *
 * The hub keeps one SEQPACKET listener. Each connected peer is a port.
 * Port -1 is the uplink (slirp or tap). MAC→port learning keeps unicast off
 * the other guests; unknown/multicast/broadcast floods everywhere else.
 * ══════════════════════════════════════════════════════════════════════════ */

#define MAX_PEERS      32
#define MAC_TABLE_SIZE 256
#define MAC_TTL        300     /* seconds */
#define PORT_UPLINK    (-1)

struct mac_entry {
	unsigned char mac[6];
	int port;              /* index into peers[], or PORT_UPLINK */
	time_t seen;
	int valid;
};

struct sw_state {
	int listen_fd;
	char sock_path[PATH_MAX];
	int peers[MAX_PEERS];  /* -1 = free slot */
	int npeers;
	struct mac_entry macs[MAC_TABLE_SIZE];
};

static struct sw_state sw;
static int sw_is_hub = 0;

static unsigned mac_hash(const unsigned char *m) {
	return ((m[3] << 16) ^ (m[4] << 8) ^ m[5] ^ (m[0] << 4)) % MAC_TABLE_SIZE;
}

static void mac_learn(const unsigned char *mac, int port) {
	/* never learn from a multicast/broadcast source address */
	if (mac[0] & 0x01) return;

	unsigned h = mac_hash(mac);
	for (unsigned i = 0; i < MAC_TABLE_SIZE; i++) {
		struct mac_entry *e = &sw.macs[(h + i) % MAC_TABLE_SIZE];
		if (e->valid && memcmp(e->mac, mac, 6) == 0) {
			e->port = port;
			e->seen = time(NULL);
			return;
		}
		if (!e->valid) {
			memcpy(e->mac, mac, 6);
			e->port = port;
			e->seen = time(NULL);
			e->valid = 1;
			return;
		}
	}
	/* table full: overwrite the bucket head */
	struct mac_entry *e = &sw.macs[h];
	memcpy(e->mac, mac, 6);
	e->port = port;
	e->seen = time(NULL);
	e->valid = 1;
}

/* Returns port, or INT_MIN when unknown (caller floods) */
static int mac_lookup(const unsigned char *mac) {
	unsigned h = mac_hash(mac);
	time_t now = time(NULL);
	for (unsigned i = 0; i < MAC_TABLE_SIZE; i++) {
		struct mac_entry *e = &sw.macs[(h + i) % MAC_TABLE_SIZE];
		if (!e->valid) break;
		if (memcmp(e->mac, mac, 6) == 0) {
			if (now - e->seen > MAC_TTL) { e->valid = 0; break; }
			return e->port;
		}
	}
	return INT_MIN;
}

static void mac_forget_port(int port) {
	for (unsigned i = 0; i < MAC_TABLE_SIZE; i++)
		if (sw.macs[i].valid && sw.macs[i].port == port)
			sw.macs[i].valid = 0;
}

/*
 * Try to become the hub by binding the socket. Returns:
 *   1  = we are the hub (listen_fd set)
 *   0  = somebody else owns it; *peer_fd is a connection to them
 *  -1  = error
 */
static int sw_bind_or_connect(const char *path, int mode, int *peer_fd)
{
	struct sockaddr_un addr;
	int fd;

	if (strlen(path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "[vde_plug] switch: socket path too long: %s\n", path);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	copy_str(addr.sun_path, sizeof(addr.sun_path), path);

	/* First try to join an existing switch. */
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0) return -1;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		*peer_fd = fd;
		return 0;
	}
	close(fd);

	/*
	 * Nobody answered. A stale socket file blocks bind(), so remove it —
	 * safe now that we know connect() failed (ECONNREFUSED/ENOENT).
	 */
	unlink(path);

	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0) return -1;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int saved = errno;
		close(fd);
		/* Lost the race: another instance bound between our calls. */
		if (saved == EADDRINUSE) {
			fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
			if (fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
				*peer_fd = fd;
				return 0;
			}
			if (fd >= 0) close(fd);
		}
		errno = saved;
		return -1;
	}
	if (listen(fd, MAX_PEERS) < 0) {
		close(fd);
		unlink(path);
		return -1;
	}
	chmod(path, mode ? mode : 0600);

	sw.listen_fd = fd;
	copy_str(sw.sock_path, sizeof(sw.sock_path), path);
	return 1;
}

static void sw_cleanup(void) {
	if (sw_is_hub && sw.sock_path[0]) {
		unlink(sw.sock_path);
		sw.sock_path[0] = '\0';
	}
}

/* ══════════════════════════════════════════════════════════════════════════
 * Uplink: tap device (for Proxmox-style bridged networking)
 *
 * With `uplink: tap:NAME` the hub attaches to an existing host tap instead of
 * running slirp. DHCP then comes from the real LAN, so guests get real leases.
 * The tap must already exist and be up (created by the host admin, e.g.
 * added to vmbr0 on Proxmox); we only open it.
 * ══════════════════════════════════════════════════════════════════════════ */

static int tap_open(const char *name)
{
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "[vde_plug] tap: open /dev/net/tun: %s\n", strerror(errno));
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	copy_str(ifr.ifr_name, IFNAMSIZ, name);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		fprintf(stderr, "[vde_plug] tap: TUNSETIFF %s: %s\n", name, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Uplink abstraction — slirp or tap behind one read/write pair
 * ══════════════════════════════════════════════════════════════════════════ */

enum uplink_kind { UP_NONE, UP_SLIRP, UP_TAP };

struct uplink {
	enum uplink_kind kind;
	int fd;                /* slirp poll fd, or tap fd */
};

static struct uplink up;

static ssize_t uplink_recv(void *buf, size_t n) {
	switch (up.kind) {
	case UP_SLIRP: return vdeslirp_recv(slirp, buf, n);
	case UP_TAP:   return read(up.fd, buf, n);
	default:       return -1;
	}
}

static ssize_t uplink_send(const void *buf, size_t n) {
	switch (up.kind) {
	case UP_SLIRP: return vdeslirp_send(slirp, buf, n);
	case UP_TAP:   return write(up.fd, buf, n);
	default:       return -1;
	}
}

/* ── VNL parameter parsing (simple key=val/key=val) ── */
static void parse_vnl_params(char *params, SlirpConfig *cfg, int *has_v6) {
	if (!params || !*params) return;
	char *save, *tok;
	for (tok = strtok_r(params, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
		char *eq = strchr(tok, '=');
		if (!eq) {
			/* bare flags */
			if (strcmp(tok, "switch") == 0)   cfg_file.sw_enabled = 1;
			else if (strcmp(tok, "noswitch") == 0) cfg_file.sw_enabled = 0;
			continue;
		}
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
		/* switch / uplink overrides */
		else if (strcmp(k, "switch") == 0) cfg_file.sw_enabled = parse_bool(v);
		else if (strcmp(k, "socket") == 0)
			copy_str(cfg_file.sw_socket, sizeof(cfg_file.sw_socket), v);
		else if (strcmp(k, "uplink") == 0)
			copy_str(cfg_file.uplink, sizeof(cfg_file.uplink), v);
		else if (strcmp(k, "dhcp_start") == 0)
			copy_str(cfg_file.dhcp_start, sizeof(cfg_file.dhcp_start), v);
		else if (strcmp(k, "network") == 0)
			copy_str(cfg_file.network, sizeof(cfg_file.network), v);
	}
}

/* ══════════════════════════════════════════════════════════════════════════
 * slirp setup — network/DHCP range from config
 *
 * Defaults match upstream slirp (10.0.2.0/24, host .2, DNS .3, DHCP from .15)
 * so existing setups keep working. When several guests share the switch they
 * each get a distinct lease walking upward from dhcp_start.
 * ══════════════════════════════════════════════════════════════════════════ */

static void apply_network_config(SlirpConfig *scfg)
{
	if (cfg_file.network[0]) {
		char tmp[64];
		copy_str(tmp, sizeof(tmp), cfg_file.network);
		char *slash = strchr(tmp, '/');
		int prefix = 24;
		if (slash) { prefix = atoi(slash + 1); *slash = '\0'; }
		if (inet_pton(AF_INET, tmp, &scfg->vnetwork) == 1)
			vdeslirp_setvprefix(scfg, prefix);
	}
	if (cfg_file.host_addr[0])
		inet_pton(AF_INET, cfg_file.host_addr, &scfg->vhost);
	if (cfg_file.dhcp_start[0])
		inet_pton(AF_INET, cfg_file.dhcp_start, &scfg->vdhcp_start);
	if (cfg_file.nameserver[0])
		inet_pton(AF_INET, cfg_file.nameserver, &scfg->vnameserver);
	if (cfg_file.hostname[0])
		scfg->vhostname = cfg_file.hostname;
	if (cfg_file.mtu > 0) {
		scfg->if_mtu = cfg_file.mtu;
		scfg->if_mru = cfg_file.mtu;
	}
}

/* ══════════════════════════════════════════════════════════════════════════
 * Port forwarding
 *
 * A rule is either *pinned* to a guest address or a *fallback*.
 *
 * Pinned rules (`10.0.2.16:2222:22` or `.16:2222:22`) are installed once and
 * never move. They are how you reach a specific machine when several share
 * the segment — the address is known up front because leases are handed out
 * in order from dhcp_start.
 *
 * Fallback rules (`2222:22`, the historical form) follow the first client to
 * appear. In standalone mode that is simply the guest, so the old behaviour is
 * unchanged. On a shared switch the first lease wins, and if the rule was
 * installed before that lease was seen it is moved onto the real address.
 * ══════════════════════════════════════════════════════════════════════════ */

/* Virtual network, kept so ".N" shorthand can be completed. */
static struct in_addr fwd_network;
static struct in_addr fwd_dhcp_start;

/* First guest address observed on the segment; 0 until a lease is seen. */
static struct in_addr first_client;

/* Complete a ".N" rule against the virtual network. */
static struct in_addr octet_to_addr(int last_octet)
{
	struct in_addr a;
	a.s_addr = (fwd_network.s_addr & htonl(0xffffff00)) |
	           htonl((uint32_t)last_octet & 0xff);
	return a;
}

/* Where should this rule point right now? 0 = not resolvable yet. */
static struct in_addr fwd_target(const struct portfwd *pf)
{
	struct in_addr none = { 0 };

	if (pf->guest_addr.s_addr) return pf->guest_addr;
	if (pf->last_octet)        return octet_to_addr(pf->last_octet);
	if (first_client.s_addr)   return first_client;

	/*
	 * Standalone: only ever one guest, so dhcp_start is correct immediately
	 * and there is no reason to wait for the lease.
	 */
	if (!cfg_file.sw_enabled) return fwd_dhcp_start;

	return none;
}

static void fwd_install(struct portfwd *pf, struct in_addr target, const char *why)
{
	char gbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &target, gbuf, sizeof(gbuf));

	if (pf->applied) {
		if (pf->applied_to.s_addr == target.s_addr) return;
		vdeslirp_remove_fwd(slirp, pf->is_udp, pf->host_addr, pf->host_port);
		pf->applied = 0;
	}

	int r = vdeslirp_add_fwd(slirp, pf->is_udp,
			pf->host_addr, pf->host_port,
			target, pf->guest_port);
	if (r == 0) {
		pf->applied = 1;
		pf->applied_to = target;
	}
	fprintf(stderr, "[vde_plug] %sfwd :%d -> %s:%d %s%s\n",
			pf->is_udp ? "udp" : "tcp",
			pf->host_port, gbuf, pf->guest_port,
			r == 0 ? "ok" : strerror(errno),
			why ? why : "");
}

static void apply_port_forwards(const SlirpConfig *scfg)
{
	fwd_network = scfg->vnetwork;
	fwd_dhcp_start = scfg->vdhcp_start;

	if (!cfg_file.portfwd) return;

	for (int i = 0; i < cfg_file.nports; i++) {
		struct portfwd *pf = &cfg_file.ports[i];
		struct in_addr t = fwd_target(pf);

		if (!t.s_addr) {
			/*
			 * Fallback rule on a shared switch and nobody has leased
			 * yet. Point it at dhcp_start for now (the usual outcome
			 * anyway) and correct it when the first lease appears.
			 */
			fwd_install(pf, fwd_dhcp_start, " (pending first client)");
			continue;
		}
		fwd_install(pf, t, NULL);
	}
}

/*
 * Re-point fallback rules once we know who the first client actually is.
 * Pinned rules are left alone.
 */
static void portfwd_note_first_client(struct in_addr addr)
{
	if (first_client.s_addr || !addr.s_addr) return;
	first_client = addr;

	if (!cfg_file.portfwd || up.kind != UP_SLIRP) return;

	char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));

	for (int i = 0; i < cfg_file.nports; i++) {
		struct portfwd *pf = &cfg_file.ports[i];
		if (pf->guest_addr.s_addr || pf->last_octet) continue;  /* pinned */
		if (pf->applied && pf->applied_to.s_addr == addr.s_addr) continue;
		fwd_install(pf, addr, " (first client)");
	}
}

/*
 * Watch DHCP ACKs going to the guests so fallback rules can latch onto the
 * first address actually handed out. Only the yiaddr field is needed, so this
 * stays a cheap header peek on the uplink-to-guest path.
 *
 * Ethernet(14) + IPv4 + UDP(8) + BOOTP; yiaddr is at BOOTP offset 16.
 */
static void sniff_dhcp_ack(const unsigned char *f, size_t len)
{
	if (first_client.s_addr) return;
	if (len < 14 + 20 + 8 + 32) return;
	if (!(f[12] == 0x08 && f[13] == 0x00)) return;      /* IPv4 */

	const unsigned char *ip = f + 14;
	if ((ip[0] >> 4) != 4) return;
	if (ip[9] != 17) return;                            /* UDP */

	size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (ihl < 20 || len < 14 + ihl + 8 + 32) return;

	const unsigned char *udp = ip + ihl;
	unsigned sport = (unsigned)(udp[0] << 8 | udp[1]);
	unsigned dport = (unsigned)(udp[2] << 8 | udp[3]);
	if (sport != 67 || dport != 68) return;             /* server -> client */

	const unsigned char *bp = udp + 8;
	if (bp[0] != 2) return;                             /* BOOTREPLY */

	struct in_addr yi;
	memcpy(&yi, bp + 16, 4);
	if (!yi.s_addr) return;

	portfwd_note_first_client(yi);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Hub loop — own the switch socket, bridge guest ↔ peers ↔ uplink
 * ══════════════════════════════════════════════════════════════════════════ */

/* Our own guest sits on a reserved port number so learning can address it. */
#define PORT_LOCAL (MAX_PEERS)

static void hub_send(int port, int local_fd, const void *buf, size_t len)
{
	if (port == PORT_UPLINK) { uplink_send(buf, len); return; }
	if (port == PORT_LOCAL)  { if (local_fd >= 0) send(local_fd, buf, len, 0); return; }
	if (port >= 0 && port < MAX_PEERS && sw.peers[port] >= 0)
		send(sw.peers[port], buf, len, 0);
}

static void hub_flood(int from_port, int local_fd, const void *buf, size_t len)
{
	if (from_port != PORT_UPLINK) uplink_send(buf, len);
	if (from_port != PORT_LOCAL && local_fd >= 0) send(local_fd, buf, len, 0);
	for (int i = 0; i < MAX_PEERS; i++)
		if (sw.peers[i] >= 0 && i != from_port)
			send(sw.peers[i], buf, len, 0);
}

/* One frame arrived on from_port: learn the source, then forward. */
static void hub_forward(int from_port, int local_fd, unsigned char *buf, size_t len)
{
	if (len < ETH_HDRLEN) return;

	const unsigned char *dst = buf;
	const unsigned char *src = buf + 6;

	mac_learn(src, from_port);

	if (dst[0] & 0x01) {           /* broadcast / multicast */
		hub_flood(from_port, local_fd, buf, len);
		return;
	}

	int port = mac_lookup(dst);
	if (port == INT_MIN) {         /* unknown unicast */
		hub_flood(from_port, local_fd, buf, len);
		return;
	}
	if (port == from_port) return; /* would hairpin */
	hub_send(port, local_fd, buf, len);
}

static int hub_loop(int local_fd)
{
	unsigned char buf[VDE_ETHBUFSIZE];

	while (running) {
		struct pollfd pfd[MAX_PEERS + 3];
		int map[MAX_PEERS + 3];   /* pfd index -> port (or sentinel) */
		int n = 0;

		/* local guest */
		pfd[n].fd = local_fd; pfd[n].events = POLLIN; pfd[n].revents = 0;
		map[n++] = PORT_LOCAL;

		/* uplink */
		if (up.kind != UP_NONE) {
			pfd[n].fd = up.fd; pfd[n].events = POLLIN; pfd[n].revents = 0;
			map[n++] = PORT_UPLINK;
		}

		/* listener for new peers */
		int listen_idx = n;
		pfd[n].fd = sw.listen_fd; pfd[n].events = POLLIN; pfd[n].revents = 0;
		map[n++] = INT_MIN;

		/* connected peers */
		for (int i = 0; i < MAX_PEERS; i++) {
			if (sw.peers[i] < 0) continue;
			pfd[n].fd = sw.peers[i]; pfd[n].events = POLLIN; pfd[n].revents = 0;
			map[n++] = i;
		}

		int r = poll(pfd, n, 1000);
		if (r < 0) { if (errno == EINTR) continue; break; }
		if (r == 0) continue;

		for (int k = 0; k < n; k++) {
			short ev = pfd[k].revents;
			if (!ev) continue;

			/* new peer */
			if (k == listen_idx) {
				if (!(ev & POLLIN)) continue;
				int cfd = accept(sw.listen_fd, NULL, NULL);
				if (cfd < 0) continue;
				int slot = -1;
				for (int i = 0; i < MAX_PEERS; i++)
					if (sw.peers[i] < 0) { slot = i; break; }
				if (slot < 0) {
					fprintf(stderr, "[vde_plug] switch: peer limit reached\n");
					close(cfd);
					continue;
				}
				sw.peers[slot] = cfd;
				sw.npeers++;
				fprintf(stderr, "[vde_plug] switch: peer %d joined (%d total)\n",
						slot, sw.npeers);
				continue;
			}

			int port = map[k];

			/* local guest died -> the VM is gone, so are we */
			if (port == PORT_LOCAL && (ev & (POLLHUP | POLLERR)))
				return 0;

			if (port == PORT_UPLINK && (ev & (POLLHUP | POLLERR)))
				return 0;

			/* peer disconnect */
			if (port >= 0 && port < MAX_PEERS && (ev & (POLLHUP | POLLERR))) {
				close(sw.peers[port]);
				sw.peers[port] = -1;
				sw.npeers--;
				mac_forget_port(port);
				fprintf(stderr, "[vde_plug] switch: peer %d left (%d total)\n",
						port, sw.npeers);
				continue;
			}

			if (!(ev & POLLIN)) continue;

			ssize_t rx;
			if (port == PORT_UPLINK) {
				rx = uplink_recv(buf, sizeof(buf));
				/* latch fallback forwards onto the first lease */
				if (rx > 0) sniff_dhcp_ack(buf, (size_t)rx);
			} else if (port == PORT_LOCAL)
				rx = recv(local_fd, buf, sizeof(buf), 0);
			else
				rx = recv(sw.peers[port], buf, sizeof(buf), 0);

			if (rx <= 0) {
				if (port == PORT_LOCAL || port == PORT_UPLINK) return 0;
				close(sw.peers[port]);
				sw.peers[port] = -1;
				sw.npeers--;
				mac_forget_port(port);
				continue;
			}

			hub_forward(port, local_fd, buf, (size_t)rx);
		}
	}
	return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Peer loop — straight wire between our guest and the hub
 * ══════════════════════════════════════════════════════════════════════════ */

static int peer_loop(int local_fd, int hub_fd)
{
	unsigned char buf[VDE_ETHBUFSIZE];
	struct pollfd pfd[2] = {
		{ .fd = local_fd, .events = POLLIN },
		{ .fd = hub_fd,   .events = POLLIN },
	};

	while (running) {
		int n = poll(pfd, 2, 1000);
		if (n < 0) { if (errno == EINTR) continue; break; }
		if (pfd[0].revents & (POLLHUP | POLLERR)) break;
		if (pfd[1].revents & (POLLHUP | POLLERR)) {
			fprintf(stderr, "[vde_plug] switch: hub went away\n");
			break;
		}
		if (pfd[0].revents & POLLIN) {
			ssize_t rx = recv(local_fd, buf, sizeof(buf), 0);
			if (rx <= 0) break;
			send(hub_fd, buf, rx, 0);
		}
		if (pfd[1].revents & POLLIN) {
			ssize_t rx = recv(hub_fd, buf, sizeof(buf), 0);
			if (rx <= 0) break;
			send(local_fd, buf, rx, 0);
		}
	}
	return 0;
}

/* ══════════════════════════════════════════════════════════════════════════ Main ════ */

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

	/* Find config.yaml next to binary; remember the dir for socket fallback */
	char config_path[PATH_MAX];
	char self_dir[PATH_MAX];
	self_dir[0] = '\0';
	{
		char self[PATH_MAX];
		ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
		if (n > 0) {
			self[n] = '\0';
			char *dir = dirname(self);
			copy_str(self_dir, sizeof(self_dir), dir);
			snprintf(config_path, sizeof(config_path), "%s/config.yaml", dir);
		} else {
			copy_str(config_path, sizeof(config_path), "config.yaml");
		}
	}

	/* Parse config file (also seeds switch/uplink defaults) */
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

	scfg.in6_enabled = has_v6 ? 1 : 0;

	/* Network / DHCP range from config (defaults keep 10.0.2.0/24) */
	apply_network_config(&scfg);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	if (seqpacket_fd < 0) {
		fprintf(stderr, "[vde_plug] no seqpacket fd, nothing to do\n");
		return 1;
	}

	/*
	 * Decide our role. In switch mode the first instance to bind the socket
	 * runs slirp/tap for everybody; the rest are plain wires. Only the hub
	 * touches the uplink, so exactly one DHCP server serves the segment and
	 * guests receive distinct leases.
	 */
	for (int i = 0; i < MAX_PEERS; i++) sw.peers[i] = -1;
	sw.listen_fd = -1;

	int hub_fd = -1;
	char sock_path[PATH_MAX] = "";

	if (cfg_file.sw_enabled) {
		resolve_switch_socket(sock_path, sizeof(sock_path), self_dir);
		int r = sw_bind_or_connect(sock_path, cfg_file.sw_mode, &hub_fd);
		if (r == 1) {
			sw_is_hub = 1;
			atexit(sw_cleanup);
		} else if (r == 0) {
			sw_is_hub = 0;
		} else {
			fprintf(stderr, "[vde_plug] switch: %s unusable (%s), standalone\n",
					sock_path, strerror(errno));
			cfg_file.sw_enabled = 0;
		}
	}

	/* Uplink is the hub's job (or standalone mode's). */
	int need_uplink = (!cfg_file.sw_enabled || sw_is_hub);

	up.kind = UP_NONE;
	up.fd = -1;

	if (need_uplink) {
		if (strncmp(cfg_file.uplink, "tap:", 4) == 0) {
			int tfd = tap_open(cfg_file.uplink + 4);
			if (tfd < 0) {
				fprintf(stderr, "[vde_plug] uplink tap failed, falling back to slirp\n");
			} else {
				up.kind = UP_TAP;
				up.fd = tfd;
			}
		} else if (strcmp(cfg_file.uplink, "none") == 0) {
			/* isolated private segment, no internet */
		}

		if (up.kind == UP_NONE && strcmp(cfg_file.uplink, "none") != 0) {
			slirp = vdeslirp_open(&scfg);
			if (!slirp) {
				fprintf(stderr, "[vde_plug] vdeslirp_open: %s\n", strerror(errno));
				return 1;
			}
			up.kind = UP_SLIRP;
			up.fd = vdeslirp_fd(slirp);
			apply_port_forwards(&scfg);
		}
	}

	/* Status line */
	{
		const char *role = !cfg_file.sw_enabled ? "standalone"
		                 : (sw_is_hub ? "hub" : "peer");
		const char *upname = up.kind == UP_SLIRP ? "slirp"
		                   : up.kind == UP_TAP   ? cfg_file.uplink
		                   : "none";
		char dhcpbuf[INET_ADDRSTRLEN] = "-";
		if (up.kind == UP_SLIRP)
			inet_ntop(AF_INET, &scfg.vdhcp_start, dhcpbuf, sizeof(dhcpbuf));

		fprintf(stderr,
			"[vde_plug] started (descr=%s vnl=%s fd=%d role=%s uplink=%s "
			"dhcp_from=%s ipv6=%d ports=%d",
			descr ? descr : "-", vnl ? vnl : "-",
			seqpacket_fd, role, upname, dhcpbuf, has_v6, cfg_file.nports);
		if (cfg_file.sw_enabled)
			fprintf(stderr, " socket=%s", sock_path);
		fprintf(stderr, ")\n");
	}

	int rc;
	if (cfg_file.sw_enabled && sw_is_hub)
		rc = hub_loop(seqpacket_fd);
	else if (cfg_file.sw_enabled)
		rc = peer_loop(seqpacket_fd, hub_fd);
	else {
		/* standalone: guest ↔ uplink, no switch */
		unsigned char buf[VDE_ETHBUFSIZE];
		struct pollfd pfd[2] = {
			{ .fd = seqpacket_fd, .events = POLLIN },
			{ .fd = up.fd,        .events = POLLIN },
		};
		int nfd = (up.kind == UP_NONE) ? 1 : 2;
		while (running) {
			int n = poll(pfd, nfd, 1000);
			if (n < 0) { if (errno == EINTR) continue; break; }
			if (pfd[0].revents & (POLLHUP | POLLERR)) break;
			if (nfd > 1 && (pfd[1].revents & (POLLHUP | POLLERR))) break;
			if (pfd[0].revents & POLLIN) {
				ssize_t rx = recv(seqpacket_fd, buf, sizeof(buf), 0);
				if (rx <= 0) break;
				uplink_send(buf, rx);
			}
			if (nfd > 1 && (pfd[1].revents & POLLIN)) {
				ssize_t rx = uplink_recv(buf, sizeof(buf));
				if (rx > 0) {
					/*
					 * Normally the single guest leases dhcp_start,
					 * which fwd_target() already assumed. Watch
					 * anyway in case it asked for something else.
					 */
					sniff_dhcp_ack(buf, (size_t)rx);
					send(seqpacket_fd, buf, rx, 0);
				}
			}
		}
		rc = 0;
	}

	if (hub_fd >= 0) close(hub_fd);
	if (up.kind == UP_TAP && up.fd >= 0) close(up.fd);
	if (up.kind == UP_SLIRP && slirp) vdeslirp_close(slirp);
	if (sw_is_hub) {
		for (int i = 0; i < MAX_PEERS; i++)
			if (sw.peers[i] >= 0) close(sw.peers[i]);
		if (sw.listen_fd >= 0) close(sw.listen_fd);
		sw_cleanup();
	}

	fprintf(stderr, "[vde_plug] shutdown\n");
	return rc;
}
