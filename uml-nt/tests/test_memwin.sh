#!/usr/bin/env bash
# S16: the death record must read the guest's own memory, and never lie about it.
#
# The kernel can read guest RAM through its section view at postmortem, so the
# two open questions — "what would the ret take?" and "did capget really get
# its data?" — can be answered without ever seeing the fault.
#
# This drives the PRODUCTION header (memwin.h) with fake readers: a valid
# window, a garbage qword, and a page that cannot be read. The unreadable case
# must say so with an error code instead of printing a silent zero window, and
# a return address outside every VMA must be flagged.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <memwin.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

/* a fake guest: a readable window, a readable cap buffer, or a hole */
static int readable = 1;
static int err_code = -14;
static __u64 stack_mem[8];
static unsigned char cap_mem[24];
static int cap_readable = 1;
static int reads;
static __u64 last_va;

static int fake_read(void *ctx, __u64 va, unsigned int len, char *dst)
{
	(void)ctx;
	reads++;
	last_va = va;
	if (va >= 0x60860000ull && va < 0x60870000ull) {
		if (!readable)
			return err_code;
		if (len != sizeof(stack_mem))
			return -2;
		memcpy(dst, stack_mem, len);
		return 0;
	}
	if (va >= 0x40000000ull && va < 0x40010000ull) {
		if (!cap_readable)
			return err_code;
		if (len != sizeof(cap_mem))
			return -3;
		memcpy(dst, cap_mem, len);
		return 0;
	}
	return -1;
}

/* only [0x60000000,0x60800000) is a VMA here */
static void fake_find(void *ctx, __u64 va, struct uml_nt_memwin_vma *out)
{
	(void)ctx;
	uml_nt_memwin_zero(out, sizeof(*out));
	if (va >= 0x60000000ull && va < 0x60800000ull) {
		out->present = 1;
		out->start = 0x60000000ull;
		out->end = 0x60800000ull;
		out->prot = 0x20;
		out->flags = 0x2;
	}
}

int main(void)
{
	struct uml_nt_memwin_stack s;
	struct uml_nt_memwin_capdata d;

	/* 1. a valid window with a return address INSIDE a VMA */
	readable = 1;
	stack_mem[0] = 0x1111; stack_mem[1] = 0x2222;
	stack_mem[2] = 0x3333; stack_mem[3] = 0x4444;
	stack_mem[4] = 0x606c9af7ull;		/* [rsp] = the return address */
	stack_mem[5] = 0x5555; stack_mem[6] = 0x6666; stack_mem[7] = 0x7777;
	uml_nt_memwin_stack(fake_read, 0, fake_find, 0, 0x6086eaa8ull, &s);
	CHECK(s.readable == 1);
	CHECK(s.lo == 0x6086ea88ull);
	CHECK(s.q[4] == 0x606c9af7ull);
	CHECK(s.retaddr_vma == 1);
	CHECK(s.retaddr_where.start == 0x60000000ull);

	/* 2. a garbage return address OUTSIDE every VMA must be flagged */
	stack_mem[4] = 0xdeadbeefdeadbeefull;
	uml_nt_memwin_stack(fake_read, 0, fake_find, 0, 0x6086eaa8ull, &s);
	CHECK(s.readable == 1);
	CHECK(s.retaddr_vma == 0);		/* -> the caller prints LOUD */
	CHECK(s.q[4] == 0xdeadbeefdeadbeefull);

	/* 3. an unreadable page must be reported, not zeroed silently */
	readable = 0;
	uml_nt_memwin_stack(fake_read, 0, fake_find, 0, 0x6086eaa8ull, &s);
	CHECK(s.readable == 0);
	CHECK(s.err == -14);
	CHECK(s.retaddr_vma == 0);

	/* the caller must be able to tell "unreadable" from "all zero" */
	readable = 1;
	memset(stack_mem, 0, sizeof(stack_mem));
	uml_nt_memwin_stack(fake_read, 0, fake_find, 0, 0x6086eaa8ull, &s);
	CHECK(s.readable == 1);
	CHECK(s.q[4] == 0);

	/* 4. capability data: present, absent and unreadable */
	memset(cap_mem, 0, sizeof(cap_mem));
	cap_mem[0] = 0xff; cap_mem[1] = 0xff; cap_mem[2] = 0; cap_mem[3] = 0;
	uml_nt_memwin_capdata(fake_read, 0, 1, 0x40000010ull, &d);
	CHECK(d.attempted == 1);
	CHECK(d.readable == 1);
	CHECK(d.b[0] == 0xff && d.b[3] == 0);
	CHECK(last_va == 0x40000010ull);

	uml_nt_memwin_capdata(fake_read, 0, 0, 0, &d);
	CHECK(d.attempted == 0);

	cap_readable = 0;
	uml_nt_memwin_capdata(fake_read, 0, 1, 0x40000010ull, &d);
	CHECK(d.attempted == 1);
	CHECK(d.readable == 0);
	CHECK(d.err == -14);

	if (fails) {
		printf("memwin: %d failure(s)\n", fails);
		return 1;
	}
	printf("memwin: window, retaddr verdict and capdata all speak\n");
	return 0;
}
EOF

"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/t" "$TMP/t.c"
"$TMP/t"
