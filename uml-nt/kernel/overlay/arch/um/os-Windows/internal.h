/* SPDX-License-Identifier: GPL-2.0 */
/*
 * os-Windows/internal.h — state + helpers shared between os-Windows
 * modules. Upstream: arch/um/os-Linux/internal.h.
 */
#ifndef __UM_OS_WINDOWS_INTERNAL_H
#define __UM_OS_WINDOWS_INTERNAL_H

#include <ntabi.h>
#include <boot-info.h>

/* Validated copy of the launcher handoff (main.c, before any os_* call). */
extern struct uml_boot_info uml_boot;

/* Shorthand: the D9 table. main.c has validated version/size first. */
extern struct uml_nt_api_table *nt;

/* Pseudo-fd create_mem_file hands back (M1: single guest RAM bank). */
#define UML_NT_MEMFD_PHYS 0

/* Early console: NtWriteFile to boot.stdio_out (util.c). */
void nt_console_write(const char *s, unsigned int n);

/* M3.8: last-chance VEH — any native exception in the kernel process
 * prints rip/fault-address (direct NtWriteFile, no console lock —
 * the crashing thread may hold it) and terminates exit 1. Install
 * from nt_main right after the D9 table check (start_up.c). */
void uml_nt_install_crash_reporter(void);

/* D19 canary: verify uml_physmem/high_physmem still hold their boot
 * values. A trashed page_offset makes every virt_to_page/kmem_cache_
 * free fault far from the offending write (the S4c2 busybox crash:
 * physmem read 0x400000001, high 0x62000200 — deterministic,
 * address-shaped values), so the os-I/O layer checks on every call,
 * prints the offending call's context + return addresses, and dies
 * loud AT the corrupting window. */
void uml_nt_physmem_check(const char *what, int fd, long len,
			  unsigned long long off);

/* net_win.c (M5.1a): winsock seam for the netstack channel (D8).
 * uml_nt_ws_init is idempotent; dial returns UML_NT_INVALID_SOCKET on
 * failure (reason already logged). Frame io speaks the 2-byte
 * big-endian length-prefix protocol of vdeplug-go's TCP transport. */
int uml_nt_ws_init(void);
unsigned long long uml_nt_net_dial(const char *host_port);
int uml_nt_net_send_frame(unsigned long long s, const void *buf,
			  unsigned int len);
int uml_nt_net_recv_frame(unsigned long long s, void *buf,
			  unsigned int maxlen);

/* irq.c (M5.1c): the net RX wake multiplex. uml_nt_net_wake_event is
 * the auto-reset event the userspace() wait listens on alongside the
 * stub's evt_in (lazily created, CAS-guarded — vCPU side). The aux
 * reader thread calls uml_nt_net_rx_ready(fd) when a frame is staged:
 * registry flag + mark_sigio_pending + SetEvent (D19 handoff). */
HANDLE uml_nt_net_wake_event(void);
void uml_nt_net_rx_ready(int fd);

/* signal.c (M5.1c): vCPU-side SIGIO flush for waiters with signals
 * enabled (the userspace() wake path). */
void uml_nt_sigio_flush(void);

#endif
