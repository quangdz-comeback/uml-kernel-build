// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/vector_user.c — the vector driver's user half, NT edition.
 * Upstream: linux v6.18.37 arch/um/drivers/vector_user.c (942 lines of
 * unix-land: /dev/net/tun, AF_PACKET, AF_UNIX socketpairs, exec'd
 * helpers with inherited fds — none of that exists on NT).
 *
 * The transport uml-nt speaks is the D8 channel: the netstack helper
 * (vdeplug-go, M5.1b direct mode) LISTENS on TCP localhost; the kernel
 * dials in and the two exchange ETHERNET FRAMES as 2-byte big-endian
 * length-prefixed buffers — the exact wire contract of vdeplug-go's
 * tcpConn and of upstream's SOCK_SEQPACKET VDE socketpair (one message
 * == one frame), flattened onto a byte stream.
 *
 * Upstream interface (vector_user.h) kept verbatim so vector_kern.c is
 * untouched at this seam:
 *   uml_parse_vector_ifspec / uml_vector_fetch_arg  — spec parser
 *   uml_vector_user_open                            — transport open
 *   uml_vector_recvmsg/writev/sendmsg/sendmmsg/recvmmsg — frame io
 *   uml_vector_{attach,detach}_bpf, default_bpf, user_bpf — filters
 *   uml_raw_enable_qdisc_bypass, uml_{raw,tap}_enable_vnet_headers
 *
 * M5.1c slice 1 lands the parse surface + fail-loud transport stubs
 * (nothing dials without a vec device in the cmdline, so the old gates
 * never reach these); the real open/framing/reader-thread lands with
 * the IRQ registry (D19 edge-capture) in the next slice.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <um_malloc.h>
#include <os.h>
/* The contract header is a sibling dir (ubd_user.c redeclares its two
 * symbols instead, but this surface is 14 functions + 2 structs — one
 * source of truth beats a drift-catching assert pile). */
#include "../drivers/vector_user.h"
#include "internal.h"

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

/* ---- transport open (M5.1c slice 2: spawn helper + dial + reader) --- */

struct vector_fds *uml_vector_user_open(int unit, struct arglist *parsed)
{
	(void)unit;
	(void)parsed;
	os_warn("vector_user: open not implemented yet (M5.1c slice 2)\n");
	return NULL;
}

/* ---- frame io stubs (reachability requires an open transport) ------- */

int uml_vector_recvmsg(int fd, void *hdr, int flags)
{
	(void)fd; (void)hdr; (void)flags;
	os_warn("vector_user: recvmsg without an open transport\n");
	return -EIO;
}

int uml_vector_sendmsg(int fd, void *hdr, int flags)
{
	(void)fd; (void)hdr; (void)flags;
	os_warn("vector_user: sendmsg without an open transport\n");
	return -EIO;
}

int uml_vector_writev(int fd, void *hdr, int iovcount)
{
	(void)fd; (void)hdr; (void)iovcount;
	os_warn("vector_user: writev without an open transport\n");
	return -EIO;
}

int uml_vector_sendmmsg(int fd, void *msgvec, unsigned int vlen,
			unsigned int flags)
{
	(void)fd; (void)msgvec; (void)vlen; (void)flags;
	os_warn("vector_user: sendmmsg without an open transport\n");
	return -EIO;
}

int uml_vector_recvmmsg(int fd, void *msgvec, unsigned int vlen,
			unsigned int flags)
{
	(void)fd; (void)msgvec; (void)vlen; (void)flags;
	os_warn("vector_user: recvmmsg without an open transport\n");
	return -EIO;
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
