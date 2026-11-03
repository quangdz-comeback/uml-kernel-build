#!/usr/bin/env bash
# S16b: the death-record producers must emit ONE framed record each.
#
# The console is shared with the stub's diagnostics, so a record assembled from
# several os_info calls can be split by a competing writer — the hazard S8/S14
# closed for the other emitters. On 49f101e the capdata producer made 26 calls
# for one logical record (prefix, 24 byte fragments, suffix); the header-only
# test could not see it because it never exercised the producer.
#
# This extracts the REAL producers from process.c and runs them against a
# recording os_info that counts every emitted write and injects a competing
# diagnostic between them. One observation = one write, or this fails.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROC="${1:-$HERE/../kernel/overlay/arch/um/os-Windows/skas/process.c}"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

python3 - "$PROC" "$TMP/prod.c" <<'PYEXTRACT'
import re
import sys

src_path, out_path = sys.argv[1], sys.argv[2]
src = open(src_path, encoding="utf-8", errors="replace").read()


def fn(sig):
    m = re.search(sig + r"\n\{.*?\n\}\n", src, re.S)
    if not m:
        raise SystemExit("cannot extract %s" % sig)
    return m.group(0)


prov = re.search(r'(static const char \*const memwin_prov =.*?;)\n', src, re.S)
if not prov:
    raise SystemExit("memwin_prov missing")
prov = prov.group(1)
stackwin = fn(r"static void uml_nt_stackwin_report\(struct uml_nt_stub_conn \*c\)")
capdata = fn(r"static void uml_nt_capdata_report\(struct uml_nt_stub_conn \*c\)")

prog = r"""
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include <diag_record.h>
#include <memwin.h>

typedef struct { unsigned long long start, end; unsigned prot, flags; } vma_t;
struct pt_regs_min { unsigned long long rax, rsp, rip; };
struct stub_data {
	struct pt_regs_min regs;
	unsigned long long req_seq, last_nr;
	unsigned long long args[6];
};
struct uml_nt_stub_conn { int pid; struct stub_data *d; void *mm; unsigned long long last_nr; };

/* ---- the recording console: one entry per emitted write ------------- */
static char writes[64][512];
static int n_writes;
static int competing;

static void os_info(const char *fmt, ...)
{
	va_list ap;
	int n = 0;

	va_start(ap, fmt);
	n = vsnprintf(writes[n_writes < 64 ? n_writes : 63],
		      sizeof(writes[0]), fmt, ap);
	va_end(ap);
	(void)n;
	n_writes++;
	if (competing && n_writes < 64) {
		/* the OTHER writer lands between two guest/kernel writes */
		snprintf(writes[n_writes], sizeof(writes[0]),
			 "[ctx-audit] competing diagnostic\n");
		n_writes++;
	}
}

/* ---- fakes for the memory reader and the VMA table ------------------ */
static unsigned char stack_mem[64];
static unsigned char cap_mem[24];
static int stack_readable = 1, cap_readable = 1;

static int memwin_read(void *ctx, __u64 va, unsigned int len, char *dst)
{
	(void)ctx;
	if (va >= 0x60860000ull && va < 0x60870000ull) {
		if (!stack_readable)
			return -14;
		memcpy(dst, stack_mem, len);
		return 0;
	}
	if (va >= 0x40000000ull && va < 0x40010000ull) {
		if (!cap_readable)
			return -14;
		memcpy(dst, cap_mem, len);
		return 0;
	}
	return -1;
}

static void memwin_find(void *ctx, __u64 va, struct uml_nt_memwin_vma *out)
{
	(void)ctx;
	uml_nt_memwin_zero(out, sizeof(*out));
	if (va >= 0x60000000ull && va < 0x60800000ull) {
		out->present = 1; out->start = 0x60000000ull;
		out->end = 0x60800000ull; out->prot = 0x20; out->flags = 2;
	}
}

""" + prov + "\n" + stackwin + "\n" + capdata + r"""

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

static struct stub_data sd;
static struct uml_nt_stub_conn conn;

static void reset(void)
{
	n_writes = 0;
	competing = 0;
	memset(writes, 0, sizeof(writes));
	memset(&sd, 0, sizeof(sd));
	memset(&conn, 0, sizeof(conn));
	conn.pid = 9148;
	conn.d = &sd;
	conn.mm = (void *)1;
	sd.req_seq = 336;
	sd.regs.rsp = 0x6086eaa8ull;
	sd.last_nr = 125; conn.last_nr = 125;
	sd.args[0] = 0x67d3521cull;
	sd.args[1] = 0x40000010ull;
	stack_readable = cap_readable = 1;
}

/* the logical record: exactly one emitted write, with a competing writer
 * injecting a line between writes (which would split a multi-call record) */
static void test_one_write_per_record(void)
{
	int i;

	reset();
	competing = 1;
	{
		unsigned long long *q = (unsigned long long *)stack_mem;
		q[4] = 0x606c9af7ull;			/* [rsp] inside a VMA */
	}
	uml_nt_stackwin_report(&conn);
	CHECK(n_writes >= 1);
	CHECK(strstr(writes[0], "[stackwin]") != NULL);
	CHECK(strstr(writes[0], "[rsp]=0x606c9af7") != NULL);
	CHECK(strstr(writes[0], "retaddr=in-vma") != NULL);
	CHECK(strstr(writes[0], "postmortem snapshot at last-trap rsp") != NULL);
	/* the competing writer must have its own line, not be spliced in */
	CHECK(strstr(writes[0], "ctx-audit") == NULL);
	for (i = 1; i < n_writes; i++)
		CHECK(strstr(writes[i], "[stackwin]") == NULL);

	/* NO-VMA must be loud, in the SAME single record */
	reset();
	competing = 1;
	((unsigned long long *)stack_mem)[4] = 0xdeadbeefdeadbeefull;
	uml_nt_stackwin_report(&conn);
	CHECK(strstr(writes[0], "retaddr=NO-VMA LOUD") != NULL);
	CHECK(strstr(writes[0], "outside every mapped region") != NULL);
	CHECK(strstr(writes[0], "candidate-ret") != NULL);

	/* unreadable: an error code, never a zeroed window */
	reset();
	competing = 1;
	stack_readable = 0;
	uml_nt_stackwin_report(&conn);
	CHECK(strstr(writes[0], "UNREADABLE err=-14") != NULL);
	CHECK(strstr(writes[0], "cannot be read") != NULL);
}

static void test_capdata_one_write(void)
{
	int hits = 0;

	reset();
	competing = 0;
	memset(cap_mem, 0, sizeof(cap_mem));
	cap_mem[0] = 0xff; cap_mem[1] = 0xff;
	uml_nt_capdata_report(&conn);
	/* ONE emitted write for the whole logical record: on 49f101e this was
	 * a prefix, 24 byte fragments and a suffix — 26 writes. */
	CHECK(n_writes == 1);
	CHECK(strstr(writes[0], "a1=0x40000010") != NULL);
	CHECK(strstr(writes[0], "ffff000000000000") != NULL);
	CHECK(strstr(writes[0], "bytes=ffff000000000000") != NULL);
	CHECK(strstr(writes[0], "not proof capget wrote them") != NULL);
	(void)hits;

	/* unreadable is an observation failure, not zero data */
	reset();
	cap_readable = 0;
	uml_nt_capdata_report(&conn);
	CHECK(strstr(writes[0], "UNREADABLE err=-14") != NULL);
	CHECK(strstr(writes[0], "NOT all-zero data") != NULL);

	/* a NULL data pointer is the version-query shape, not "no round" */
	reset();
	sd.args[1] = 0;
	conn.d->args[1] = 0;
	uml_nt_capdata_report(&conn);
	CHECK(strstr(writes[0], "NULL data: version query shape") != NULL);

	/* and a non-capget round says so, without pretending to read */
	reset();
	sd.last_nr = 3; conn.last_nr = 3;
	uml_nt_capdata_report(&conn);
	CHECK(strstr(writes[0], "no capget round on this conn") != NULL);
}

int main(void)
{
	test_one_write_per_record();
	test_capdata_one_write();

	if (fails) {
		printf("stackwin_capdata: %d failure(s)\n", fails);
		return 1;
	}
	printf("stackwin_capdata: one record, one write; provenance stated\n");
	return 0;
}
"""
open(out_path, "w").write(prog)
print("producers extracted verbatim")
PYEXTRACT

# the extracted producers use the kernel's %llx convention for __u64, which on
# the host is `unsigned long`; the record content is what this test checks.
"$CC" -O1 -Wall -Wextra -Werror -Wno-format -Wno-unused-const-variable \
	-I"$INC" -o "$TMP/prod" "$TMP/prod.c"
"$TMP/prod"
