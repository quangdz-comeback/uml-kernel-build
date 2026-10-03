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

/* process.c (R17 DIAG): dump the vmalloc-band ledger ring — the
 * last n os_map_memory/os_unmap_memory window ops. Callers: the
 * flat-view tripwires in os_unmap_memory and the sweep mark-buffer
 * alloc failure (the stale-PTE WARN precedent, run 36984931372). */
void uml_nt_vmr_dump(const char *why, unsigned int n);

/* start_up.c (M5.6a [ktrip], map 117): arm the KERNEL-flat witness —
 * PAGE_READONLY on [lo,hi) inside THIS process's physmem view, the
 * one mapping no witness has ever protected. The crash reporter's
 * VEH repairs (back to RW) + replays on the first write, logging rip
 * + stack: a legit funnel writeback costs one line, an unknown rip
 * is the flat-write stomper. One window at a time; re-arms unprotect
 * the old page. */
void uml_nt_ktrip_arm(unsigned long long lo, unsigned long long hi);

/* start_up.c (M5.6a [ktrip-w], referee 37124011556 decode): SECOND
 * kernel-flat witness window, independent of the struct-page arm —
 * the struct page re-arms EVERY round (its static page tracker
 * unprotects whatever single window ktrip holds), so a fire-armed
 * chunk page would be displaced after one round. The
 * [tcchunk-POISON] fire path arms the fired chunk's own 4K page
 * here: the corruption lives at chunk+0/+8 (env text over
 * e->next+e->key — the clobbered key also blinds glibc's tcache
 * double-free check, leaving the chunk linked in tcache AND
 * unsorted), and the next kernel-flat write to that page names its
 * rip. Stub-side writes stay covered by the run-level cowtrap. */
void uml_nt_ktrip_w_arm(unsigned long long lo, unsigned long long hi);

/* start_up.c (M5.6a [kheap], referees 37124011556 + 37126690946): the
 * PRE-EMPTIVE whole-heap kernel-flat witness — [heap_start, heap_end)
 * PAGE_READONLY page-by-page in THIS process's physmem view, armed
 * BEFORE the corruption lands. Every kernel-flat write to a heap page
 * trips the VEH with its rip (funnel writeback = legit, one line;
 * unknown rip = the flat-write stomper). The catch unprotects only the
 * faulting page (replay) and the next uml_nt_kheap_sync call re-arms
 * dirty pages + drops/extends ranges whose piece re-homed (era
 * change). The heap is PIECEWISE (one VMA piece per re-homed run) so
 * the witness is a SET of flat ranges, one per piece. */
#define UML_NT_KHEAP_RANGES 12
struct uml_nt_kheap_piece {
	unsigned long long lo; /* flat, page-aligned */
	unsigned long long hi; /* flat, exclusive */
};
void uml_nt_kheap_sync(const struct uml_nt_kheap_piece *pcs, int n);

/* stub_ctl.c (M5.6a [alloc-alias], map 121): the physalloc handout
 * probe — scan every live conn's VMAs into the freshly claimed
 * [off, off+nruns*RUN) range; a hit names the stale translation
 * ("alloc over a live run", the heap-trasher family). Log-only. */
void uml_nt_alloc_alias_scan(long long off, int nruns);

/* skas/uaccess.c (M5.6a [deadwrite], lead 115): arm the destroy-path
 * writeback witness. While armed, EVERY translate-then-write (raw_
 * copy_to_user / clear_user / futex atomics) landing in the dying
 * mm's heap window [heap_start, +0x20000) logs "[deadwrite] tag=...
 * dying=..." with the call-site tag. Arm sites: the dispatch's
 * task-backed exit_group route (tag "exit") and uml_nt_mmctx_destroy
 * (tag "destroy") — the robust-list exit-fixup suspect set. The
 * dispatch entry disarms: a fresh syscall round on any conn is a
 * live context, and do_exit never returns, so the exit arm would
 * otherwise leak into every later round on this thread. */
void uml_nt_deadwrite_arm(int pid, const char *tag);
void uml_nt_deadwrite_disarm(void);

#endif
