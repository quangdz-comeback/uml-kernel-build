#!/usr/bin/env bash
# S18a: the return slot is sampled AT THE TRAP, through an injectable reader.
#
# The wrapper's success path has no RSP adjustment, so the word a ret takes is
# exactly [rsp]; the postmortem [stackwin] cannot say when it went bad. This
# drives the REAL sampler with a real host buffer whose at-trap and postmortem
# words differ, and checks the caller frame too (SysV puts the caller's return
# address at [rbp+8]).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUB="${1:-$HERE/../stub/stub.c}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
python3 - "$STUB" "$TMP/t.c" <<'PYEXTRACT'
import re, sys
src=open(sys.argv[1]).read(); out=sys.argv[2]
m=re.search(r"static void sample_slot_words_with\(struct uml_nt_stub_data \*sd,\n.*?\n\}\n", src, re.S)
assert m, "sample_slot_words_with missing"
sampler=m.group(0)
prog = r'''
#include <stdio.h>
#include <string.h>
#include <stdint.h>
struct uml_nt_gp_regs { unsigned long long rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
	r8, r9, r10, r11, r12, r13, r14, r15, rip, rflags; };
struct uml_nt_stub_data {
	unsigned long long slot_q0, slot_q8, slot_q16, slot_rbp, slot_rbp8;
	unsigned long long ram_base, ram_size;
	struct uml_nt_gp_regs regs;
};
/* a REAL host buffer standing in for guest memory */
static unsigned char page[0x2000];
#define BASE 0x6086e000ull
static void rd(void *ctx, unsigned long long va, unsigned long long *o)
{
	(void)ctx;
	*o = 0;
	if (va < BASE || va + 8 > BASE + sizeof(page)) return;
	memcpy(o, page + (va - BASE), 8);
}
''' + sampler + r'''
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
static void put(unsigned long long va, unsigned long long v)
{ if (va >= BASE && va + 8 <= BASE + sizeof(page)) memcpy(page + (va - BASE), &v, 8); }
int main(void)
{
	struct uml_nt_stub_data s;
	memset(&s, 0, sizeof(s));
	memset(page, 0, sizeof(page));
	s.regs.rsp = 0x6086eaa8ull;
	s.regs.rbp = 0x6086e100ull;
	/* at the trap: the slot holds a real return address, and the caller
	 * frame has its own return address at [rbp+8] */
	put(0x6086eaa8ull, 0x606c9af7ull);
	put(0x6086eab0ull, 0x0ull);
	put(0x6086eab8ull, 0x61401a3bull);
	put(0x6086e100ull, 0x6086e400ull);	/* saved rbp */
	put(0x6086e108ull, 0x606b1234ull);	/* caller return address */
	sample_slot_words_with(&s, rd, 0);
	CHECK(s.slot_q0 == 0x606c9af7ull);
	CHECK(s.slot_q8 == 0x0);
	CHECK(s.slot_q16 == 0x61401a3bull);
	CHECK(s.slot_rbp == 0x6086e400ull);
	CHECK(s.slot_rbp8 == 0x606b1234ull);

	/* now the POSTMORTEM word changes: the at-trap copy must not follow */
	put(0x6086eaa8ull, 0x1ull);
	CHECK(s.slot_q0 == 0x606c9af7ull);	/* still the trap-time value */
	sample_slot_words_with(&s, rd, 0);	/* a later trap WOULD see 0x1 */
	CHECK(s.slot_q0 == 0x1ull);

	/* out-of-range rsp: zeros, never a stale value */
	s.regs.rsp = 0x1000ull;
	sample_slot_words_with(&s, rd, 0);
	CHECK(s.slot_q0 == 0 && s.slot_q8 == 0 && s.slot_q16 == 0);
	if (fails) { printf("slot_at_trap: %d failure(s)\n", fails); return 1; }
	printf("slot_at_trap: slot and rbp chain sampled at the trap\n");
	return 0;
}
'''
open(out,'w').write(prog)
PYEXTRACT
"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
