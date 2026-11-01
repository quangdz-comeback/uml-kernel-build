// SPDX-License-Identifier: GPL-2.0
/*
 * tests/ans_free_live_fake.c — recording fake for the release witness.
 *
 * Deliberately a real definition (not a weak no-op): any harness that links
 * vma.c must link this file, so the witness can never quietly become a no-op in
 * the host build. The recording is bounded and the overflow is counted, so a
 * runaway loop shows up as a number rather than as silence.
 */
#include "ans_free_live_fake.h"

#define FAKE_MAX 32

static int n_calls;
static unsigned long long rec_lo[FAKE_MAX];
static unsigned long long rec_hi[FAKE_MAX];
static const char *rec_why[FAKE_MAX];

void uml_nt_ans_free_live(unsigned long long lo, unsigned long long hi,
			  const char *why)
{
	if (n_calls < FAKE_MAX) {
		rec_lo[n_calls] = lo;
		rec_hi[n_calls] = hi;
		rec_why[n_calls] = why;
	}
	n_calls++;
}

void ans_free_live_fake_reset(void)
{
	n_calls = 0;
}

int ans_free_live_fake_count(void)
{
	return n_calls;
}

unsigned long long ans_free_live_fake_lo(int i)
{
	return (i >= 0 && i < FAKE_MAX) ? rec_lo[i] : 0ull;
}

unsigned long long ans_free_live_fake_hi(int i)
{
	return (i >= 0 && i < FAKE_MAX) ? rec_hi[i] : 0ull;
}

const char *ans_free_live_fake_why(int i)
{
	return (i >= 0 && i < FAKE_MAX) ? rec_why[i] : (const char *)0;
}
