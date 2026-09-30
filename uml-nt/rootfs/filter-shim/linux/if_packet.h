/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rootfs/filter-shim/linux/if_packet.h — busybox udhcpc build shim
 * (see filter-shim/linux/filter.h). musl exposes the same sockaddr_ll
 * and PACKET_* names via <netpacket/packet.h>.
 */
#ifndef _UAPI_LINUX_IF_PACKET_H_SHIM
#define _UAPI_LINUX_IF_PACKET_H_SHIM

#include <netpacket/packet.h>

/*
 * musl's <netpacket/packet.h> stops at sockaddr_ll/PACKET_*; dhcpc.c
 * also reads the PACKET_AUXDATA cmsg payload (tpacket_auxdata) to
 * honor the kernel's checksum status. Same memory layout as the uapi
 * struct on x86_64.
 */
struct tpacket_auxdata {
	unsigned int   tp_status;
	unsigned int   tp_len;
	unsigned int   tp_snaplen;
	unsigned short tp_mac;
	unsigned short tp_net;
};

#define TP_STATUS_CSUMNOTREADY (1 << 2)
#define TP_STATUS_CSUM_VALID   0x80

#endif /* _UAPI_LINUX_IF_PACKET_H_SHIM */
