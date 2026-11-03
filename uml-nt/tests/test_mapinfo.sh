#!/usr/bin/env bash
# S17: the two addresses of interest must be described honestly.
#
# A VMA range and a ledger protection are the ENGINE's view. What decides
# whether code can run at an address is the STUB's real view, and what decides
# which file it came from is the file offset — which the kernel only retains for
# lazy-file regions. This extracts the real producer and drives it with a fake
# VMA, a fake view ledger, a fake lazy region and a recording os_info.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROC="${1:-$HERE/../kernel/overlay/arch/um/os-Windows/skas/process.c}"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
python3 - "$PROC" "$TMP/p.c" <<'PYEXTRACT'
import re, sys
src=open(sys.argv[1]).read(); out=sys.argv[2]
m=re.search(r"static void uml_nt_mapinfo_one\(struct uml_nt_stub_conn \*c, const char \*what,\n.*?\n\}\n", src, re.S)
assert m, "mapinfo producer missing"
one=m.group(0)
prog = r'''
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <diag_record.h>
#include <memwin.h>
#define UML_NT_DIAG_CAP 512u
typedef unsigned long ULONG;
typedef struct { unsigned long State, Protect, Type; unsigned long long BaseAddress, AllocationBase; } MEMORY_BASIC_INFORMATION;
#define MEM_COMMIT 0x1000ul
typedef struct { unsigned long long va, len, off; unsigned prot; } view_t;
struct uml_nt_vma { unsigned long long start, end, run_off; unsigned prot, flags; };
struct lazy_t { unsigned long long start, end, file_off; int used; };
struct uml_nt_stub_conn {
	int pid; void *d, *mm, *proc; unsigned nviews;
	view_t views[8]; struct lazy_t lazy[4];
};
static char last[1024]; static int n_writes;
static void os_info(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	vsnprintf(last, sizeof(last), fmt, ap); va_end(ap); n_writes++;
}
static int memwin_read(void *c, __u64 va, unsigned int len, char *dst)
{ (void)c; (void)va; memcpy(dst, "\x55\x48\x89\xe5", 4); memset(dst+4,0x90,len-4); return 0; }
static struct uml_nt_vma the_vma; static int have_vma = 1;
struct uml_nt_vma *uml_nt_vma_find(void *mm, unsigned long long va)
{ (void)mm; (void)va; return have_vma ? &the_vma : 0; }
/* the NT query: report a fake real view */
static unsigned long long real_state = 0x1000, real_prot = 0x20, real_base = 0x61400000;
struct nt_fake { unsigned long (*VirtualQueryEx)(void *, void *, void *, unsigned long); };
static unsigned long vqe(void *p, void *a, void *mbi, unsigned long n)
{
	unsigned long *w = (unsigned long *)mbi; (void)p; (void)a; (void)n;
	(void)w;
	memset(mbi, 0, 48);
	(void)n;
	*(unsigned long *)((char *)mbi + 0x00) = (unsigned long)real_state;
	*(unsigned long *)((char *)mbi + 0x08) = (unsigned long)real_prot;
	*(unsigned long long *)((char *)mbi + 0x10) = real_base;
	return 48;
}
static struct nt_fake fake_nt = { vqe }; static struct nt_fake *nt = &fake_nt;
''' + one + r'''
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)
int main(void)
{
	struct uml_nt_stub_conn c;
	memset(&c, 0, sizeof(c)); n_writes = 0;
	the_vma.start = 0x61400000; the_vma.end = 0x61410000;
	the_vma.run_off = 0x1b1000; the_vma.prot = 0x40; the_vma.flags = 2;
	c.mm = (void *)1; c.proc = (void *)1; c.nviews = 1;
	c.views[0].va = 0x61400000; c.views[0].len = 0x10000;
	c.views[0].off = 0x1b1000; c.views[0].prot = 0x2;

	uml_nt_mapinfo_one(&c, "ret-candidate", 0x61401a3bull, 0);
	if (getenv("MAPINFO_DEBUG")) printf("DEBUG: %s\n", last);
	CHECK(n_writes == 1);                       /* one record, one write */
	CHECK(strstr(last, "ret-candidate va=0x61401a3b") != NULL);
	CHECK(strstr(last, "vma=[0x61400000,0x61410000)") != NULL);
	CHECK(strstr(last, "ledger_prot=0x40") != NULL);
	/* the engine offset must never be called a file offset */
	CHECK(strstr(last, "file_off=UNKNOWN") != NULL);
	CHECK(strstr(last, "file_path=UNKNOWN") != NULL);
	CHECK(strstr(last, "real_state=0x1000") != NULL);
	CHECK(strstr(last, "real_prot=0x20") != NULL);

	/* a lazy region DOES carry a real file offset */
	c.lazy[0].used = 1; c.lazy[0].start = 0x61400000;
	c.lazy[0].end = 0x61410000; c.lazy[0].file_off = 0x9000;
	n_writes = 0;
	uml_nt_mapinfo_one(&c, "ret-candidate", 0x61401a3bull, 0);
	CHECK(strstr(last, "file_off=0xaa3b") != NULL);	/* 0x9000 + 0x1a3b */

	/* no VMA: says so instead of inventing a range */
	have_vma = 0;
	n_writes = 0;
	uml_nt_mapinfo_one(&c, "ret-candidate", 0x1ull, 0);
	CHECK(strstr(last, "NO-VMA") != NULL);
	CHECK(n_writes == 1);
	have_vma = 1;

	/* bytes for offline disassembly, and an explicit unreadable case */
	n_writes = 0;
	uml_nt_mapinfo_one(&c, "ret-candidate", 0x61401a3bull, 1);
	CHECK(n_writes >= 2);
	if (fails) { printf("mapinfo: %d failure(s)\n", fails); return 1; }
	printf("mapinfo: engine view, real view and file identity labelled\n");
	return 0;
}
'''
open(out,'w').write(prog)
PYEXTRACT
"$CC" -O1 -Wall -Wextra -Werror -Wno-format -I"$INC" -o "$TMP/p" "$TMP/p.c"
"$TMP/p"
