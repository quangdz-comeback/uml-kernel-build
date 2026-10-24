/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uml-nt: the guest TLS guard contract — the pure half.
 *
 * M5.6a login-depth follow-up (to-shelley 148-UPDATE 9/10, Shelley's
 * guard-stability branch): every login conn dies by a pivot to a
 * text-resident stack, and the observed wild pointers are identical
 * across boots. glibc x86-64 derives BOTH TCB secrets from the exec's
 * AT_RANDOM bytes — stack canary = rand[0..7] at fs:0x28, pointer
 * guard = rand[8..15] at fs:0x30 — and PTR_MANGLEs jmp_buf pointers:
 *
 *     mangle(x)   = rol64(x ^ guard, 17)
 *     demangle(v) = ror64(v, 17) ^ guard
 *
 * (sysdeps/x86_64/__longjmp.S / setjmp.S: xor %fs:0x30, rol/ror 17.)
 * A longjmp whose guard changed between setjmp and longjmp demangles
 * the saved rsp/rip into a foreign pointer — a pivot to a wild stack
 * can then be a guard-change symptom, not a clobbered jmp_buf. The
 * kernel probes fs:0x28/0x30 against the conn's AT_RANDOM at TLS
 * init, at every trap, and at a wild-rsp fire; this model pins the
 * arithmetic and the verdicts those probes report.
 *
 * Shared with tests/test_guard.c: no Windows types.
 */
#ifndef UML_NT_GUARD_MODEL_H
#define UML_NT_GUARD_MODEL_H

#define UML_NT_GUARD_ROT 17

/* uml_nt_guard_verdict results. */
#define UML_NT_GUARD_FIRST   1 /* no prior sight: record it */
#define UML_NT_GUARD_STABLE  2 /* same value as the recorded init */
#define UML_NT_GUARD_CHANGED 3 /* a different value — the probe logs */

/* uml_nt_guard_tcb_check result bits. */
#define UML_NT_GUARD_TCB_CANARY 1
#define UML_NT_GUARD_TCB_GUARD  2

static inline unsigned long long
uml_nt_guard_mangle(unsigned long long x, unsigned long long g)
{
	unsigned long long v = x ^ g;

	return (v << UML_NT_GUARD_ROT) | (v >> (64 - UML_NT_GUARD_ROT));
}

static inline unsigned long long
uml_nt_guard_demangle(unsigned long long v, unsigned long long g)
{
	return ((v >> UML_NT_GUARD_ROT) |
		(v << (64 - UML_NT_GUARD_ROT))) ^ g;
}

/* Compare a current fs:0x30 sight against the recorded init and say
 * which transition it is. `seen` = a first sight was recorded. */
static inline int
uml_nt_guard_verdict(unsigned long long init, unsigned long long now,
		     int seen)
{
	if (!seen)
		return UML_NT_GUARD_FIRST;
	return init == now ? UML_NT_GUARD_STABLE : UML_NT_GUARD_CHANGED;
}

/* Which of the observed TCB fields still match what security_init
 * should have copied from the exec's AT_RANDOM bytes. */
static inline int
uml_nt_guard_tcb_check(const unsigned char *rnd16,
		       unsigned long long canary, unsigned long long guard)
{
	unsigned long long c = 0, g = 0;
	int i;

	if (rnd16 == 0)
		return 0;
	for (i = 7; i >= 0; i--) {
		c = (c << 8) | rnd16[i];
		g = (g << 8) | rnd16[8 + i];
	}
	return (c == canary ? UML_NT_GUARD_TCB_CANARY : 0) |
	       (g == guard ? UML_NT_GUARD_TCB_GUARD : 0);
}

#endif /* UML_NT_GUARD_MODEL_H */
