#!/usr/bin/env bash
# S14: the sysbench report must arrive as whole lines.
#
# The guest console is shared with the stub's diagnostics. When a report line
# was assembled from several sys_write calls, a diagnostic could be printed
# inside it — natively the gate saw "events per second: [ctx-audit] ..." and its
# EPS pattern stopped matching.
#
# This test extracts the REAL output helpers and the REAL summary producer from
# guest/sysbench.c (no copied formatting), fakes only sys_write, and injects
# diagnostic text BETWEEN guest writes. Every report line must still arrive
# intact, in ONE write, and the unchanged gate pattern must parse the EPS.
#
# Host framing control only: it does not execute the guest or Windows.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUEST="${1:-$HERE/../guest/sysbench.c}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

python3 - "$GUEST" "$TMP/report.c" <<'PYEXTRACT'
import re
import sys

src_path, out_path = sys.argv[1], sys.argv[2]
src = open(src_path, encoding="utf-8", errors="replace").read()


def between(first, last, what):
    i = src.find(first)
    j = src.find(last)
    if i < 0 or j < 0 or j <= i:
        raise SystemExit("cannot extract %s from %s" % (what, src_path))
    return src[i:j + len(last)]


# the line builder + its writer (verbatim)
helpers = between("struct line_buf {", "static void lb_flush(struct line_buf *l)\n{\n\tif (l->n != 0)\n\t\tsys_write(1, l->b, l->n);\n\tl->n = 0;\n}",
                  "the line builder")
# the summary producer (verbatim)
summary = between("static void report_summary(", "\t(void)events;\n}", "report_summary")

prog = r"""
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* the console the guest writes to; diagnostics are injected between writes */
static char log_buf[4096];
static int log_len;
static int write_calls;
static int last_write_start[64];
static int last_write_len[64];
static int inject;

static long sys_write(int fd, const void *buf, unsigned long len)
{
	(void)fd;
	if (write_calls < 64) {
		last_write_start[write_calls] = log_len;
		last_write_len[write_calls] = (int)len;
	}
	write_calls++;
	if (inject) {
		/* a diagnostic printed by the OTHER writer between guest writes */
		static const char diag[] = "[ctx-audit] pid 0 rounds=42600 snapshots=42600\n";

		memcpy(log_buf + log_len, diag, sizeof(diag) - 1);
		log_len += (int)sizeof(diag) - 1;
	}
	if (log_len + (int)len < (int)sizeof(log_buf)) {
		memcpy(log_buf + log_len, buf, len);
		log_len += (int)len;
	}
	log_buf[log_len] = '\0';
	return (long)len;
}

""" + helpers + "\n\n" + summary + r"""

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

static void reset(int do_inject)
{
	log_len = 0;
	log_buf[0] = '\0';
	write_calls = 0;
	inject = do_inject;
}

/* the gate's OWN pattern, unchanged */
static int gate_eps(long *out)
{
	const char *p = log_buf;
	while ((p = strstr(p, "events per second: ")) != NULL) {
		const char *q = p + strlen("events per second: ");
		if (*q >= '0' && *q <= '9') {
			long v = 0;
			while (*q >= '0' && *q <= '9')
				v = v * 10 + (*q++ - '0');
			if (out)
				*out = v;
			return 1;
		}
		p++;
	}
	return 0;
}

static int line_count(void)
{
	int i, n = 0;

	for (i = 0; i < log_len; i++)
		if (log_buf[i] == '\n')
			n++;
	return n;
}

static void test_clean_summary(void)
{
	long eps = 0;

	reset(0);
	report_summary(42589, 4258.75, 10.25);	/* exact in binary */
	/* two lines, two writes, and the gate reads the number */
	CHECK(write_calls == 2);
	CHECK(line_count() == 2);
	CHECK(strstr(log_buf, "events per second: 4258.75\n") != NULL);
	CHECK(strstr(log_buf, "total time: 10.25s\n") != NULL);
	CHECK(gate_eps(&eps) == 1);
	CHECK(eps == 4258);
}

static void test_diagnostic_between_writes(void)
{
	long eps = 0;

	reset(1);			/* a diagnostic before every guest write */
	report_summary(42589, 4258.75, 10.25);	/* exact in binary */
	/* the guest still issued exactly two writes: one per line */
	CHECK(write_calls == 2);
	CHECK(strstr(log_buf, "events per second: 4258.75\n") != NULL);
	CHECK(strstr(log_buf, "total time: 10.25s\n") != NULL);
	CHECK(gate_eps(&eps) == 1);
	CHECK(eps == 4258);		/* the UNCHANGED gate parses it */
}

static void test_zero_and_padded_fraction(void)
{
	reset(1);
	report_summary(1, 0.00, 0.00);
	CHECK(strstr(log_buf, "events per second: 0.00\n") != NULL);
	CHECK(strstr(log_buf, "total time: 0.00s\n") != NULL);

	reset(1);
	report_summary(1, 7.25, 1.75);	/* a non-zero padded fraction */
	CHECK(strstr(log_buf, "events per second: 7.25\n") != NULL);
	CHECK(strstr(log_buf, "total time: 1.75s\n") != NULL);

	/* the production math TRUNCATES: 99.999 must print 99.99, never 100.00 */
	reset(1);
	report_summary(1, 99.999, 2.0);
	CHECK(strstr(log_buf, "events per second: 99.99\n") != NULL);
}

static void test_large_bounds(void)
{
	reset(1);
	report_summary(4294967296ull, 4294967296.5, 1099511627776.25);
	/* a large whole part still fits one line and one write */
	CHECK(write_calls == 2);
	CHECK(strstr(log_buf, "events per second: 4294967296.50\n") != NULL);
	CHECK(strstr(log_buf, "total time: 1099511627776.25s\n") != NULL);
}

static void test_low_eps_is_not_rounded_up(void)
{
	long eps = 0;

	/* a slow run must still report its real, below-floor number */
	reset(1);
	report_summary(100, 99.99, 10.00);
	CHECK(gate_eps(&eps) == 1);
	CHECK(eps == 99);
	CHECK(eps < 2100);		/* the existing floor still fails it */
}

int main(void)
{
	test_clean_summary();
	test_diagnostic_between_writes();
	test_zero_and_padded_fraction();
	test_large_bounds();
	test_low_eps_is_not_rounded_up();

	if (fails) {
		printf("sysbench_report: %d failure(s)\n", fails);
		return 1;
	}
	printf("sysbench_report: whole lines, one write each, gate parses\n");
	return 0;
}
"""
open(out_path, "w").write(prog)
print("sysbench_report: extracted the production helpers + summary producer")
PYEXTRACT

"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/report" "$TMP/report.c"
"$TMP/report"
