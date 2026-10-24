/* SPDX-License-Identifier: GPL-2.0 */
/*
 * con_ring.h — the console input edge-capture ring (pure —
 * unit-tested on the host CI, test_console.c).
 *
 * M5.6a slice A (to-shelley 141-A, the D19 violation): the stdin
 * reader NT thread used to call tty_insert_flip_string() straight
 * from its own thread — kernel context running CONCURRENTLY with
 * the vCPU, zero exclusion on the port/flip/n_tty state on the UP
 * build (the 5cb22f8 S4c2 class, console edition). The reader is
 * now a pure producer: NtReadFile -> push into this ring -> SetEvent
 * (the wake multiplex). The vCPU drains the ring into the tty core
 * at the safe points (the userspace() wait wake and the
 * unblock_signals flush — exactly where the pending-only timer
 * alarm flushes).
 *
 * SPSC, wait-free: ONE producer thread (the reader), ONE consumer
 * (the vCPU). Monotonic 32-bit cursors wrap naturally; capacity is
 * the full CAP (full = head - tail == CAP). A full ring DROPS the
 * incoming tail and counts the loss in `drops` — input loss is
 * loud at the call site, never a silent overwrite of unread bytes.
 */
#ifndef __UML_NT_CON_RING_H
#define __UML_NT_CON_RING_H

#define UML_NT_CON_RING_CAP 4096 /* power of two */

struct uml_nt_con_ring {
	unsigned char buf[UML_NT_CON_RING_CAP];
	volatile unsigned int head; /* producer: next write cursor */
	volatile unsigned int tail; /* consumer: next read cursor */
	unsigned int drops;         /* producer: bytes dropped (full) */
};

void uml_nt_con_ring_init(struct uml_nt_con_ring *r);

/* Producer: append up to len bytes; returns the count STORED
 * (short = the ring filled, the rest is tallied in drops). */
unsigned int uml_nt_con_ring_push(struct uml_nt_con_ring *r,
				  const unsigned char *src,
				  unsigned int len);

/* Consumer: pop up to maxlen bytes; returns the count (0 = empty). */
unsigned int uml_nt_con_ring_pop(struct uml_nt_con_ring *r,
				 unsigned char *dst, unsigned int maxlen);

/* Consumer: DISCARD every unread byte (the §4a tty-flush boundary —
 * TCSETSF/TCFLSH). Returns the count dropped. A producer push racing
 * the drop keeps the new bytes (they land at/after the observed
 * head). */
unsigned int uml_nt_con_ring_drop(struct uml_nt_con_ring *r);

/* 1 when bytes wait (the cheap vCPU-side poll for the flush). */
int uml_nt_con_ring_pending(const struct uml_nt_con_ring *r);

#endif /* __UML_NT_CON_RING_H */
