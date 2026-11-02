#!/usr/bin/env bash
# S11b: the capget (nr=125) round witness.
#
# The referees die in a fork child of /sbin/init that never execs, at a glibc
# capget stub, outside every handler. One framed line per round is what says
# which conn, seeded from which parent, which VA pair, whether the data write
# would have been served, what the emulation returned, what the plan held after
# the handler, and where the trap was.
#
# This test extracts the emitter VERBATIM from skas/syscall.c (same pattern as
# the S8 adapter test) and drives it through the production framing helper with
# a recording sink: every field must appear in the record, and the record must
# reach the sink exactly once.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SC="${1:-$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c}"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

python3 - "$SC" "$TMP/witness.c" <<'PYEXTRACT'
import re
import sys

src_path, out_path = sys.argv[1], sys.argv[2]
src = open(src_path, encoding="utf-8", errors="replace").read()


def block(begin, end):
    m = re.search(r"/\* %s[^\n]*\n(.*?)/\* %s \*/" % (begin, end), src, re.S)
    if not m:
        raise SystemExit("markers %s/%s missing in %s" % (begin, end,
                                                          src_path))
    return m.group(1)


struct = block("S11b-REC-BEGIN", "S11b-REC-END")
emit = block("S11b-WITNESS-BEGIN", "S11b-WITNESS-END")

prog = r"""
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <diag_record.h>

#define UML_NT_PHYS_RUN_SIZE 65536

""" + struct + "\n" + emit + r"""

static int fails;
static int sink_calls;
static int sink_len;
static char sink_buf[UML_NT_DIAG_CAP * 2];
static int sink_short;

#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL: %s\n", #c); } } while (0)

static int rec_format(char *buf, unsigned int cap, const char *fmt, va_list ap)
{
	return vsnprintf(buf, cap, fmt, ap);
}

static int rec_sink(const char *buf, unsigned int len)
{
	sink_calls++;
	sink_len = (int)len;
	snprintf(sink_buf, sizeof(sink_buf), "%s", buf);
	if (sink_short)
		return (int)len - 1;
	return (int)len;
}

static const struct uml_nt_diag_ops ops = { rec_format, rec_sink };

int main(void)
{
	struct uml_nt_capget_rec r;
	char buf[UML_NT_DIAG_CAP];
	int rc;

	memset(&r, 0, sizeof(r));
	r.pid = 4242;
	r.parent_pid = 1400;
	r.a0 = 0x6086f100ull;
	r.a1 = 0x6086f200ull;
	r.len = 8;
	r.granted = 1;
	r.why = "ok";
	r.run_off = 0x2050000ull;
	r.run_gen = 0x77ull;
	r.retval = 0;
	r.plan_ops = 3;
	r.trap_rip = 0x606c9af5ull;
	r.fork_seeded = 1;

	sink_calls = 0;
	rc = uml_nt_capget_emit(buf, sizeof(buf), &ops, &r);
	CHECK(sink_calls == 1);			/* one record, one write */
	CHECK(rc == UML_NT_DIAG_OK);
	CHECK(sink_len > 0 && sink_buf[sink_len - 1] == '\n');

	/* every field the death log needs, in the record */
	CHECK(strstr(sink_buf, "pid=4242") != NULL);
	CHECK(strstr(sink_buf, "parent=1400") != NULL);
	CHECK(strstr(sink_buf, "fork_seeded=1") != NULL);
	CHECK(strstr(sink_buf, "a0=0x6086f100") != NULL);
	CHECK(strstr(sink_buf, "a1=0x6086f200") != NULL);
	CHECK(strstr(sink_buf, "len=8") != NULL);
	CHECK(strstr(sink_buf, "uacc=granted") != NULL);
	CHECK(strstr(sink_buf, "why=ok") != NULL);
	CHECK(strstr(sink_buf, "run_off=0x2050000") != NULL);
	CHECK(strstr(sink_buf, "run_gen=0x77") != NULL);
	CHECK(strstr(sink_buf, "ret=0") != NULL);
	CHECK(strstr(sink_buf, "plan_ops=3") != NULL);
	CHECK(strstr(sink_buf, "trap_rip=0x606c9af5") != NULL);
	/* exactly one newline: the framing must not double it */
	{
		int i, nl = 0;

		for (i = 0; i < sink_len; i++)
			if (sink_buf[i] == '\n')
				nl++;
		CHECK(nl == 1);
	}

	/* a refused verdict says so, and says why */
	memset(&r, 0, sizeof(r));
	r.pid = 7;
	r.parent_pid = 0;
	r.why = "refs0";
	r.retval = -14;
	sink_calls = 0;
	rc = uml_nt_capget_emit(buf, sizeof(buf), &ops, &r);
	CHECK(sink_calls == 1);
	CHECK(rc == UML_NT_DIAG_OK);
	CHECK(strstr(sink_buf, "uacc=refused") != NULL);
	CHECK(strstr(sink_buf, "why=refs0") != NULL);
	CHECK(strstr(sink_buf, "fork_seeded=0") != NULL);
	CHECK(strstr(sink_buf, "parent=0") != NULL);
	CHECK(strstr(sink_buf, "ret=-14") != NULL);

	/* a short write is reported, and still exactly one attempt */
	memset(&r, 0, sizeof(r));
	r.pid = 9;
	sink_short = 1;
	sink_calls = 0;
	rc = uml_nt_capget_emit(buf, sizeof(buf), &ops, &r);
	CHECK(sink_calls == 1);
	CHECK(rc == UML_NT_DIAG_SINK_FAIL);
	sink_short = 0;

	if (fails) {
		printf("capget_witness: %d failure(s)\n", fails);
		return 1;
	}
	printf("capget_witness: all ok (%d fields, one sink call per record)\n",
	       13);
	return 0;
}
"""
open(out_path, "w").write(prog)
print("witness emitter extracted")
PYEXTRACT

"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/witness" "$TMP/witness.c"
"$TMP/witness"
