// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/con_ring.c — the console input edge-capture ring.
 * Pure logic, no kernel includes: the unit test compiles it
 * standalone on Linux CI (same pattern as console_status.c).
 * The __sync fences publish/consume cursors across the two host
 * threads (the same builtins signal.c's pending machine uses).
 */
#include <con_ring.h>

#define CON_RING_MASK (UML_NT_CON_RING_CAP - 1u)

void uml_nt_con_ring_init(struct uml_nt_con_ring *r)
{
	unsigned int i;

	if (r == (struct uml_nt_con_ring *)0)
		return;
	for (i = 0; i < UML_NT_CON_RING_CAP; i++)
		r->buf[i] = 0;
	r->head = 0;
	r->tail = 0;
	r->drops = 0;
}

unsigned int uml_nt_con_ring_push(struct uml_nt_con_ring *r,
				  const unsigned char *src,
				  unsigned int len)
{
	unsigned int head, tail, free_, n, i;

	if (r == (struct uml_nt_con_ring *)0 ||
	    src == (const unsigned char *)0)
		return 0;
	head = r->head;
	tail = r->tail; /* consumer-owned; a stale read only
			 * UNDERESTIMATES the free space (safe) */
	free_ = UML_NT_CON_RING_CAP - (head - tail);
	n = len < free_ ? len : free_;
	for (i = 0; i < n; i++)
		r->buf[(head + i) & CON_RING_MASK] = src[i];
	if (n != 0) {
		__sync_synchronize(); /* bytes before the cursor */
		r->head = head + n;
	}
	if (n < len)
		r->drops += len - n;
	return n;
}

unsigned int uml_nt_con_ring_pop(struct uml_nt_con_ring *r,
				 unsigned char *dst, unsigned int maxlen)
{
	unsigned int head, tail, n, i;

	if (r == (struct uml_nt_con_ring *)0 ||
	    dst == (unsigned char *)0)
		return 0;
	head = r->head; /* producer-owned; a stale read only
			 * UNDERESTIMATES availability (safe) */
	__sync_synchronize(); /* the cursor before the bytes */
	tail = r->tail;
	n = head - tail;
	if (n > maxlen)
		n = maxlen;
	for (i = 0; i < n; i++)
		dst[i] = r->buf[(tail + i) & CON_RING_MASK];
	if (n != 0) {
		__sync_synchronize(); /* reads before the cursor move */
		r->tail = tail + n;
	}
	return n;
}

int uml_nt_con_ring_pending(const struct uml_nt_con_ring *r)
{
	if (r == (const struct uml_nt_con_ring *)0)
		return 0;
	return r->head != r->tail;
}

unsigned int uml_nt_con_ring_drop(struct uml_nt_con_ring *r)
{
	unsigned int head, tail;

	if (r == (struct uml_nt_con_ring *)0)
		return 0;
	head = r->head; /* producer-owned; bytes pushed after this read
			 * stay queued (their indices are >= head) */
	__sync_synchronize();
	tail = r->tail;
	r->tail = head;
	return head - tail;
}
