/* Guard-stability model — M5.6a login-depth follow-up (Shelley
 * 148-UPDATE 9/10, "GUARD STABILITY" branch).
 *
 * glibc x86-64 derives both TCB secrets from the exec's AT_RANDOM
 * bytes (rand[0..7] -> fs:0x28 canary, rand[8..15] -> fs:0x30 pointer
 * guard) and PTR_MANGLEs jmp_buf pointers as rol64(x ^ guard, 17).
 * Pinning the arithmetic + the stability verdict + the AT_RANDOM
 * derivation keeps the kernel's fs:0x30 probe honest: a changed guard
 * demangles any jmp_buf into a foreign pointer, and the probe must
 * catch it in the same conn rather than let the wild-rsp pivot read
 * as an unexplained stack slip.
 */
#include <stdio.h>
#include "guard_model.h"

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
	} } while (0)

int main(void)
{
	/* The boot's observed TCB (rt1, HEAD ead6242):
	 *   fs:0x28 canary = 0x0f67327e601cdc00
	 *   fs:0x30 guard  = 0x6ef6510c8eabfd26
	 * and the login conn's normal / wild stack pointers. */
	const unsigned long long g = 0x6ef6510c8eabfd26ull;
	const unsigned long long canary = 0x0f67327e601cdc00ull;
	static const unsigned long long ptrs[] = {
		0x6005d258ull,	/* close(3)'s normal rsp */
		0x6001c228ull,	/* the first wild rsp (ld.so + 0xc228) */
		0x6001c3a0ull,	/* openat's wild rsp */
		0ull,
		~0ull,
	};
	/* AT_RANDOM bytes that would produce the observed TCB (the
	 * derivation, not the boot's literal bytes — those are logged
	 * separately as [auxv-random]). */
	static const unsigned char rnd[16] = {
		0x00, 0xdc, 0x1c, 0x60, 0x7e, 0x32, 0x67, 0x0f,
		0x26, 0xfd, 0xab, 0x8e, 0x0c, 0x51, 0xf6, 0x6e,
	};
	unsigned i;

	/* 1. PTR_MANGLE: xor fs:0x30 then rol 17 (glibc x86-64
	 * __longjmp.S/setjmp.S). Hard vectors, not just round-trips. */
	CHECK(uml_nt_guard_mangle(0x6001c228ull, 0ull) ==
	      0x0000c00384500000ull);
	CHECK(uml_nt_guard_mangle(0xdeadbeefcafebabeull,
				  0x0123456789abcdefull) ==
	      0xf71086aaeea3bf1dull);
	CHECK(uml_nt_guard_demangle(0xf71086aaeea3bf1dull,
				    0x0123456789abcdefull) ==
	      0xdeadbeefcafebabeull);

	/* 2. Round-trip with the boot's real guard. */
	for (i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); i++)
		CHECK(uml_nt_guard_demangle(
			uml_nt_guard_mangle(ptrs[i], g), g) == ptrs[i]);

	/* 3. A different guard does NOT recover the pointer — the
	 * changed-guard class the probe must expose. */
	CHECK(uml_nt_guard_demangle(uml_nt_guard_mangle(0x6005d258ull, g),
				    canary) != 0x6005d258ull);

	/* 4. Stability verdict: first sight, stable, changed. */
	CHECK(uml_nt_guard_verdict(g, g, 0) == UML_NT_GUARD_FIRST);
	CHECK(uml_nt_guard_verdict(g, g, 1) == UML_NT_GUARD_STABLE);
	CHECK(uml_nt_guard_verdict(g, canary, 1) == UML_NT_GUARD_CHANGED);
	CHECK(uml_nt_guard_verdict(0, 0, 1) == UML_NT_GUARD_STABLE);

	/* 5. AT_RANDOM -> TCB derivation. */
	CHECK(uml_nt_guard_tcb_check(rnd, canary, g) ==
	      (UML_NT_GUARD_TCB_CANARY | UML_NT_GUARD_TCB_GUARD));
	CHECK(uml_nt_guard_tcb_check(rnd, g, canary) == 0);
	CHECK(uml_nt_guard_tcb_check(rnd, canary, 0) ==
	      UML_NT_GUARD_TCB_CANARY);
	CHECK(uml_nt_guard_tcb_check(rnd, canary ^ 1ull, g) ==
	      UML_NT_GUARD_TCB_GUARD);
	CHECK(uml_nt_guard_tcb_check(NULL, canary, g) == 0);

	if (fails == 0)
		printf("test_guard: OK\n");
	return fails != 0;
}
