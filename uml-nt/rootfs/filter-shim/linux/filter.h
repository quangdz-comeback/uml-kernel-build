/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rootfs/filter-shim/linux/filter.h — busybox udhcpc build shim.
 *
 * busybox's networking/udhcp/dhcpc.c includes <linux/filter.h> for the
 * SO_ATTACH_FILTER types; glibc hosts get it from the installed kernel
 * headers, musl-gcc ships no linux/ dir at all. This stub carries the
 * two struct definitions the guest kernel's own <linux/filter.h> uses
 * (x86_64 layout — the guest setsockopt(SO_ATTACH_FILTER) copies THIS
 * through the D15 walker into the real filter code), nothing else.
 */
#ifndef _UAPI_LINUX_FILTER_H_SHIM
#define _UAPI_LINUX_FILTER_H_SHIM

struct sock_filter {
	unsigned short code; /* u16 */
	unsigned char  jt;
	unsigned char  jf;
	unsigned int   k;    /* u32 */
};

struct sock_fprog {
	unsigned short len;
	struct sock_filter *filter;
};

#endif /* _UAPI_LINUX_FILTER_H_SHIM */
