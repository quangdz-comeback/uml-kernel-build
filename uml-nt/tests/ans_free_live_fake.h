// SPDX-License-Identifier: GPL-2.0
/*
 * tests/ans_free_live_fake.h — host-test stand-in for the release witness
 *
 * vma.c calls uml_nt_ans_free_live() on every VMA it releases. The real
 * implementation lives in stub_ctl.c and cannot be linked on the host, so the
 * pure harnesses link this recording fake instead and assert that the mm-drop
 * path reports the exact range it released, with the reason it released it.
 *
 * This is a test double, not a production weak symbol: the kernel build still
 * gets the real witness, and a harness that forgets to link the fake fails to
 * link instead of silently passing with a no-op.
 */
#ifndef ANS_FREE_LIVE_FAKE_H
#define ANS_FREE_LIVE_FAKE_H

void uml_nt_ans_free_live(unsigned long long lo, unsigned long long hi,
			  const char *why);

/* Test-side view of what the code under test reported. */
void ans_free_live_fake_reset(void);
int ans_free_live_fake_count(void);
unsigned long long ans_free_live_fake_lo(int i);
unsigned long long ans_free_live_fake_hi(int i);
const char *ans_free_live_fake_why(int i);

#endif /* ANS_FREE_LIVE_FAKE_H */
