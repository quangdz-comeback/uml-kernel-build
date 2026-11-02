// SPDX-License-Identifier: GPL-2.0
/*
 * tests/test_diag_record.c — the production framing/emission rule, driven
 * through an injectable recording sink.
 *
 * The point of these cases is the rule, not the formatter: one record is one
 * sink call, the record is newline-terminated inside the bounded buffer, a
 * truncated record says so, and nothing outside the record is touched. The
 * sink counts its calls, so "body then newline", "retry the tail", or "write
 * it twice" all show up as a number.
 *
 * This is host logic only. It says nothing about Windows write atomicity.
 */
#include <stdio.h>
#include <string.h>

#include <diag_record.h>

static int fails;

#define CHECK(cond) do { if (!(cond)) { \
	fails++; \
	printf("FAIL %d: %s\n", __LINE__, #cond); \
} } while (0)

/* ---- recording sink ---------------------------------------------------- */
#define SINK_MAX 4

struct sink_rec {
	int calls;
	unsigned int len[SINK_MAX];
	char bytes[SINK_MAX][UML_NT_DIAG_CAP + 8];
	int ret_override;	/* >= 0: report this instead of a full accept */
	int ret_unknown;	/* 1: report SINK_UNKNOWN_VALUE */
};

static struct sink_rec sink;

static void sink_reset(void)
{
	memset(&sink, 0, sizeof(sink));
	sink.ret_override = -2;	/* -2 = normal: accept the whole record */
}

static int record_sink(const char *buf, unsigned int len)
{
	if (sink.calls < SINK_MAX) {
		unsigned int n = len < sizeof(sink.bytes[0]) - 1 ?
				 len : (unsigned int)sizeof(sink.bytes[0]) - 1;

		sink.len[sink.calls] = len;
		memcpy(sink.bytes[sink.calls], buf, n);
		sink.bytes[sink.calls][n] = '\0';
	}
	sink.calls++;
	if (sink.ret_unknown)
		return UML_NT_DIAG_SINK_UNKNOWN_VALUE;
	if (sink.ret_override != -2)
		return sink.ret_override;
	return (int)len;
}

/* ---- formatters -------------------------------------------------------- */
static int fmt_c99(char *buf, unsigned int cap, const char *fmt, va_list ap)
{
	return vsnprintf(buf, cap, fmt, ap);
}

/* msvcrt-style: negative result when the output did not fit. */
static int fmt_negative_on_trunc(char *buf, unsigned int cap, const char *fmt,
				 va_list ap)
{
	int n = vsnprintf(buf, cap, fmt, ap);

	if (n >= 0 && (unsigned int)n >= cap)
		return -1;
	return n;
}

static int fmt_broken(char *buf, unsigned int cap, const char *fmt, va_list ap)
{
	(void)buf;
	(void)cap;
	(void)fmt;
	(void)ap;
	return -1;		/* writes nothing at all */
}

static struct uml_nt_diag_ops ops_c99 = { fmt_c99, record_sink };
static struct uml_nt_diag_ops ops_neg = { fmt_negative_on_trunc, record_sink };
static struct uml_nt_diag_ops ops_broken = { fmt_broken, record_sink };

static void test_plain_record(void)
{
	char buf[UML_NT_DIAG_CAP];
	int r;

	/* a body without a newline gets exactly one */
	sink_reset();
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99,
			       "[teb] pid %lu tid %lu stackbase=0x%llx",
			       696ul, 5640ul, 0x62840000ull);
	CHECK(r == UML_NT_DIAG_OK);
	CHECK(sink.calls == 1);
	CHECK(sink.len[0] == strlen(sink.bytes[0]));
	CHECK(sink.len[0] > 0 && sink.bytes[0][sink.len[0] - 1] == '\n');
	CHECK(strstr(sink.bytes[0], "[teb] pid 696 tid 5640 ") != NULL);
	/* exactly one newline, and no truncation marker */
	{
		int i, nl = 0;

		for (i = 0; i < (int)sink.len[0]; i++)
			if (sink.bytes[0][i] == '\n')
				nl++;
		CHECK(nl == 1);
		CHECK(strstr(sink.bytes[0], "...") == NULL);
	}

	/* a body that already ends with a newline is not given a second one */
	sink_reset();
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "[stack-pre] grew\n");
	CHECK(r == UML_NT_DIAG_OK);
	CHECK(sink.calls == 1);
	CHECK(sink.len[0] == strlen("[stack-pre] grew\n"));
	CHECK(memcmp(sink.bytes[0], "[stack-pre] grew\n", sink.len[0]) == 0);
}

static void test_exact_fit(void)
{
	char buf[UML_NT_DIAG_CAP];
	char body[UML_NT_DIAG_CAP];
	int r, i;

	/* body_cap is cap - 4 (marker), so an exact fit is body_cap-1 visible
	 * characters plus the newline. Build it and check no marker appears. */
	for (i = 0; i < (int)sizeof(body) - 1; i++)
		body[i] = 'x';
	body[sizeof(body) - 1] = '\0';
	body[UML_NT_DIAG_CAP - 5] = '\0';	/* room for '\n' inside body_cap */

	sink_reset();
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "%s", body);
	CHECK(sink.calls == 1);
	CHECK(r == UML_NT_DIAG_OK);
	CHECK(strstr(sink.bytes[0], "...") == NULL);
	CHECK(sink.bytes[0][sink.len[0] - 1] == '\n');
}

static void test_truncation_and_guards(void)
{
	char buf[UML_NT_DIAG_CAP + 8];
	int r, i;
	unsigned int guard_ok = 1;

	/* poison around the record, then check nothing outside it moved */
	memset(buf, 0xAA, sizeof(buf));
	sink_reset();
	r = uml_nt_diag_record(buf, UML_NT_DIAG_CAP, &ops_c99, "%0*d", 4000, 7);
	CHECK(r == UML_NT_DIAG_TRUNCATED);
	CHECK(sink.calls == 1);
	CHECK(sink.len[0] < UML_NT_DIAG_CAP);
	CHECK(sink.len[0] >= 4);
	/* the marker is in the record, right before the framing newline */
	CHECK(sink.bytes[0][sink.len[0] - 1] == '\n');
	CHECK(sink.bytes[0][sink.len[0] - 2] == '.');
	CHECK(sink.bytes[0][sink.len[0] - 3] == '.');
	CHECK(sink.bytes[0][sink.len[0] - 4] == '.');
	for (i = (int)sink.len[0] + 1; i < (int)sizeof(buf); i++)
		if ((unsigned char)buf[i] != 0xAA)
			guard_ok = 0;
	CHECK(guard_ok);

	/* the old truncating formatter says so with a negative result */
	sink_reset();
	r = uml_nt_diag_record(buf, UML_NT_DIAG_CAP, &ops_neg, "%0*d", 4000, 7);
	CHECK(r == UML_NT_DIAG_TRUNCATED);
	CHECK(sink.calls == 1);
	CHECK(sink.bytes[0][sink.len[0] - 2] == '.');

	/* a formatter that writes nothing at all is broken, and still one call */
	sink_reset();
	r = uml_nt_diag_record(buf, UML_NT_DIAG_CAP, &ops_broken, "x");
	CHECK(r == UML_NT_DIAG_FMT_BROKEN);
	CHECK(sink.calls == 1);
	CHECK(sink.len[0] == 1);	/* just the framing newline */
	CHECK(sink.bytes[0][0] == '\n');
}

/* The production stub adapter returns exactly -1 when WriteFile fails. That
 * value must read as a FAILURE, not as "unknown": reporting a known error as
 * an unknown one is how the earlier contract lost the distinction. */
static void test_production_error_values(void)
{
	char buf[UML_NT_DIAG_CAP];
	int r;

	/* -1, exactly what a failed WriteFile produces */
	sink_reset();
	sink.ret_override = -1;
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_FAIL);
	CHECK(sink.calls == 1);

	/* a zero-byte write is a failure, not silence that "worked" */
	sink_reset();
	sink.ret_override = 0;
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_FAIL);
	CHECK(sink.calls == 1);

	/* a short write is a failure, and the missing tail is NOT retried */
	sink_reset();
	sink.ret_override = 4;		/* "hell" of "hello\n" */
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_FAIL);
	CHECK(sink.calls == 1);

	/* UNKNOWN is its own value and must never be confused with -1 */
	CHECK(UML_NT_DIAG_SINK_UNKNOWN_VALUE != -1);
	CHECK(UML_NT_DIAG_SINK_UNKNOWN_VALUE != 0);
	sink_reset();
	sink.ret_unknown = 1;
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_UNKNOWN);
	CHECK(sink.calls == 1);
}

static void test_sink_outcomes(void)
{
	char buf[UML_NT_DIAG_CAP];
	int r;

	/* short write: reported, never retried */
	sink_reset();
	sink.ret_override = 3;
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_FAIL);
	CHECK(sink.calls == 1);

	/* hard failure */
	sink_reset();
	sink.ret_override = -5;
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_FAIL);
	CHECK(sink.calls == 1);

	/* completion not observable (the kernel's void write) */
	sink_reset();
	sink.ret_unknown = 1;
	r = uml_nt_diag_record(buf, sizeof(buf), &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_SINK_UNKNOWN);
	CHECK(sink.calls == 1);

	/* no sink, no call */
	sink_reset();
	r = uml_nt_diag_record(buf, sizeof(buf), (const struct uml_nt_diag_ops *)0,
			       "hello");
	CHECK(r == UML_NT_DIAG_REFUSED);
	CHECK(sink.calls == 0);

	/* capacity too small: refused without touching the sink */
	sink_reset();
	r = uml_nt_diag_record(buf, UML_NT_DIAG_MIN_CAP - 1, &ops_c99, "hello");
	CHECK(r == UML_NT_DIAG_REFUSED);
	CHECK(sink.calls == 0);
}

int main(void)
{
	test_plain_record();
	test_exact_fit();
	test_truncation_and_guards();
	test_production_error_values();
	test_sink_outcomes();

	if (fails) {
		printf("test_diag_record: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_diag_record: all ok\n");
	return 0;
}
