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

/* start_up.c (M5.1c.3 diagnosis): which aux thread is running — set
 * at thread entry, printed by the crash reporter. */
extern const char *uml_nt_thread_role;

/* skas/process.c (M5.1c.4): scheduler switch-trace ring. The hooks are
 * called from arch/um/kernel/process.c (__switch_to / fork_handler)
 * via patch 0017 under CONFIG_OS_WINDOWS; the crash reporter prints
 * the ring so a crash names the task chain that led to it (the M5.1c
 * fault dies on a task stack that is NOT the one the switch history
 * explains — the ring discriminates stale-task vs switch mid-flush). */
struct uml_nt_switch_rec {
	unsigned long long from_pid, to_pid, to_state, to_stack;
};

#define UML_NT_SWITCH_RING 32

/* Snapshot of the last UML_NT_SWITCH_RECORD switches; *out points at
 * the ring, the return value = number of valid records (oldest first). */
unsigned long long uml_nt_switch_ring(const struct uml_nt_switch_rec **out);

/* void task_struct* args: internal.h stays sched.h-free (os modules
 * include it without kernel/sched types); skas/process.c casts. */
void uml_nt_switch_trace(void *from, void *to);
void uml_nt_fork_trace(void);

/* vector_user.c (M5.1c.5): the net SPSC ring identity for the crash
 * report — the ring is the biggest kmalloc'd object of the net window;
 * if its backing got aliased with vmalloc'd task stacks (allocator
 * bug), find_vm_area on both names it. */
void uml_nt_net_ring_info(unsigned long long *addr,
			  unsigned long long *head,
			  unsigned long long *tail);

/* stub_ctl.c (M5.1c.5): the smash-writer hunt. The flat-view design
 * gives every guest-physical offset a PERMANENT kernel-side identity
 * (physmem_base+off), while kernel vmalloc objects (task stacks!)
 * get mapped to the same section at a second VA — so a guest VMA
 * backed by a run that the buddy also owns as a kernel object = the
 * same bytes under two owners. Scan both live mms' VMA trees for
 * VMA backing ([run_off, run_off+len)) intersecting the section
 * offsets [lo, hi) and print the guilty VMAs (guest VA range + mm
 * name) — the reporter calls this per page of a smashed task stack
 * (stack VA -> vmalloc_to_page -> pfn -> section offset). */
void uml_nt_alias_scan(unsigned long long lo, unsigned long long hi);

/* stub_ctl.c (map 049 + M5.6a): the phys refcount event log — pinned
 * as uml_nt_phys_event in nt_main. One os_info line per block free,
 * unref-refused (the claim-theft signal) and alloc-reject (the
 * double-free signature); park/free/park-spill events additionally
 * run the release-under-vma tripwire (the 0x3960000 tcache-run
 * recycle class — names the surviving conn's VMA, exempts the
 * dropping owner's own dying views). */
void uml_nt_phys_event_log(const char *kind, long long off, int nruns,
			   int refs, const void *owner);

#endif
