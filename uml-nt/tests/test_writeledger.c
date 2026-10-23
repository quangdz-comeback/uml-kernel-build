/* The kernel->guest write ledger (M5.6a D28 follow-up, Shelley 148):
 * the run-keyed ring the TO_GUEST funnel records into and the
 * [imgwatch] fire scans. Host test of the pure sharing code.
 *
 * Why run-keyed: the writer may live in a DIFFERENT mm than the one
 * whose image run it corrupts (the run was freed/re-handed across
 * processes), so a VA-keyed ledger cannot see it. The run offset is
 * the hardware's assembly key.
 */
#include <stdio.h>
#include "writeledger_model.h"

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
	} } while (0)

int main(void)
{
	struct uml_nt_write_ledger l;
	int idx[8];
	int i, n;

	/* 1. empty ledger finds nothing */
	uml_nt_writeledger_init(&l);
	CHECK(uml_nt_writeledger_find(&l, 0x10000, idx, 8) == 0);

	/* 2. put/find by run: only the matching run's entries come back,
	 * newest first (the fire wants the last writer) */
	uml_nt_writeledger_put(&l, 0x4380000, 0x6001b000, 16, 257);
	uml_nt_writeledger_put(&l, 0x9990000, 0x70000000, 8, 0);
	uml_nt_writeledger_put(&l, 0x4380000, 0x6001b010, 64, 257);
	n = uml_nt_writeledger_find(&l, 0x4380000, idx, 8);
	CHECK(n == 2);
	CHECK(l.e[idx[0]].va == 0x6001b010 && l.e[idx[0]].len == 64);
	CHECK(l.e[idx[1]].va == 0x6001b000 && l.e[idx[1]].len == 16);
	CHECK(l.e[idx[0]].nr == 257);

	/* 3. the cap bound: max caps the returned indices */
	CHECK(uml_nt_writeledger_find(&l, 0x4380000, idx, 1) == 1);

	/* 4. wraparound: the ring keeps the NEWEST N; an old entry falls
	 * out and cannot be found again */
	for (i = 0; i < UML_NT_WRITELEDGER_N; i++)
		uml_nt_writeledger_put(&l, 0x1000000 + (unsigned long long)i * 0x10000,
				       (unsigned long long)i, 4, 0);
	CHECK(uml_nt_writeledger_find(&l, 0x4380000, idx, 8) == 0);
	CHECK(uml_nt_writeledger_find(&l,
	     0x1000000 + (unsigned long long)(UML_NT_WRITELEDGER_N - 1) * 0x10000,
	     idx, 8) == 1);

	/* 5. a zero-length write is not a writer (never recorded) */
	uml_nt_writeledger_put(&l, 0x5550000, 0, 0, 7);
	CHECK(uml_nt_writeledger_find(&l, 0x5550000, idx, 8) == 0);

	if (fails) {
		fprintf(stderr, "test_writeledger: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_writeledger: all ok\n");
	return 0;
}
