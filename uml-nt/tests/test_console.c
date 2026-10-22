/* SPDX-License-Identifier: GPL-2.0 */
/*
 * console-status classifier unit test (Shelley's 100-real-alpine
 * freeze): the stdin reader must re-arm on the spurious
 * zero-information statuses (the observed killer = 0x101/WAIT_1)
 * and park only on the real EOF/handle-death statuses.
 *
 * M5.6a slice A (to-shelley 141-A): the console input ring — the
 * D19 pending-only refactor's handoff. The reader thread is a pure
 * edge-capture producer (NtReadFile -> ring push -> SetEvent); the
 * vCPU drains the ring into the tty flip buffer at the safe points
 * (the userspace() wait wake + the unblock_signals flush, the
 * 5cb22f8 timer pattern). These tests pin the ring contract:
 * FIFO order, wrap, full-drop accounting (input loss is LOUD,
 * never silent), and the empty-pop edge.
 */
#include <stdio.h>
#include <string.h>
#include <console_status.h>
#include <con_ring.h>

#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s\n", \
	__LINE__, #x); return 1; } } while (0)

static int test_ring(void)
{
	struct uml_nt_con_ring r;
	unsigned char out[600];
	unsigned char src[UML_NT_CON_RING_CAP + 64];
	unsigned int i;

	for (i = 0; i < sizeof(src); i++)
		src[i] = (unsigned char)(i * 7 + 3);

	uml_nt_con_ring_init(&r);
	CHECK(uml_nt_con_ring_pending(&r) == 0);
	CHECK(uml_nt_con_ring_pop(&r, out, sizeof(out)) == 0);

	/* basic FIFO */
	CHECK(uml_nt_con_ring_push(&r, src, 100) == 100);
	CHECK(uml_nt_con_ring_pending(&r) == 1);
	CHECK(uml_nt_con_ring_pop(&r, out, 40) == 40);
	CHECK(memcmp(out, src, 40) == 0);
	CHECK(uml_nt_con_ring_pop(&r, out, 100) == 60);
	CHECK(memcmp(out, src + 40, 60) == 0);
	CHECK(uml_nt_con_ring_pending(&r) == 0);

	/* wrap: fill to within 64 of the physical end, drain 256,
	 * push 200 (crosses the physical end), then read the whole
	 * FIFO back in order */
	uml_nt_con_ring_init(&r);
	CHECK(uml_nt_con_ring_push(&r, src, UML_NT_CON_RING_CAP - 64) ==
	      UML_NT_CON_RING_CAP - 64);
	CHECK(uml_nt_con_ring_pop(&r, out, 256) == 256);
	CHECK(memcmp(out, src, 256) == 0);
	CHECK(uml_nt_con_ring_push(&r, src, 200) == 200);
	CHECK(uml_nt_con_ring_pending(&r) == 1);
	{
		unsigned int got = 0, n, k;

		while ((n = uml_nt_con_ring_pop(&r, out, 100)) != 0) {
			for (k = 0; k < n; k++) {
				unsigned char want =
					got + k < UML_NT_CON_RING_CAP - 320 ?
					src[256 + got + k] :
					src[got + k -
					    (UML_NT_CON_RING_CAP - 320)];
				CHECK(out[k] == want);
			}
			got += n;
		}
		CHECK(got == UML_NT_CON_RING_CAP - 64 - 256 + 200);
	}

	/* full: the push reports a SHORT count and the drop tally
	 * records the rest (the reader logs it loud); nothing
	 * already queued is ever overwritten */
	uml_nt_con_ring_init(&r);
	CHECK(uml_nt_con_ring_push(&r, src, UML_NT_CON_RING_CAP) ==
	      UML_NT_CON_RING_CAP);
	CHECK(uml_nt_con_ring_push(&r, src, 100) == 0);
	CHECK(r.drops == 100);
	CHECK(uml_nt_con_ring_pop(&r, out, 64) == 64);
	CHECK(uml_nt_con_ring_push(&r, src + 100, 100) == 64);
	CHECK(r.drops == 136);
	/* drain: the queued stream is src[64..CAP) (the first push
	 * minus the 64 popped) then src[100..164) (the surviving 64
	 * of the last push) — FIFO across the wrap, in order */
	{
		unsigned int got = 0, n, k;

		while ((n = uml_nt_con_ring_pop(&r, out,
						sizeof(out))) != 0) {
			for (k = 0; k < n; k++) {
				unsigned char want =
					got + k < UML_NT_CON_RING_CAP - 64 ?
					src[64 + got + k] :
					src[100 + (got + k -
						   (UML_NT_CON_RING_CAP - 64))];
				CHECK(out[k] == want);
			}
			got += n;
		}
		CHECK(got == UML_NT_CON_RING_CAP);
	}

	/* bad shapes */
	CHECK(uml_nt_con_ring_push((void *)0, src, 1) == 0);
	CHECK(uml_nt_con_ring_push(&r, (void *)0, 1) == 0);
	CHECK(uml_nt_con_ring_pop((void *)0, out, 1) == 0);
	CHECK(uml_nt_con_ring_pop(&r, (void *)0, 1) == 0);
	CHECK(uml_nt_con_ring_pending((void *)0) == 0);

	printf("test_console: ring ok\n");
	return 0;
}

int main(void)
{
	/* the spurious wake family — the reader lives */
	CHECK(nt_con_status_class(0x00000000LL) == NT_CON_RETRY);
	CHECK(nt_con_status_class(0x00000101LL) == NT_CON_RETRY);
	CHECK(nt_con_status_class(0x00000102LL) == NT_CON_RETRY);
	CHECK(nt_con_status_class(0x00000103LL) == NT_CON_RETRY);

	/* the real death family — the reader parks loud */
	CHECK(nt_con_status_class(0xC0000011LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0xC0000008LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0xC0000234LL) == NT_CON_FATAL);

	/* anything else is fatal (positive-status garbage included:
	 * NT_SUCCESS would call 0x1ffff fine — the classifier must
	 * NOT, only the four wake statuses retry) */
	CHECK(nt_con_status_class(0x00000104LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0x00000105LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0xC0000005LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(0x80000017LL) == NT_CON_FATAL);
	CHECK(nt_con_status_class(-1LL) == NT_CON_FATAL);

	if (test_ring() != 0)
		return 1;
	printf("test_console: all ok\n");
	return 0;
}
