/* SPDX-License-Identifier: GPL-2.0 */
/*
 * diag_record.h — one diagnostic record, one host write.
 *
 * The console is shared by processes that know nothing about each other: the
 * kernel writes printk and guest output through nt_console_write, while a stub
 * writes its own diagnostics through its inherited stderr handle. They append
 * to the same target, and the target keeps no record boundaries — a record
 * built in two writes can have another process's bytes wedged into the middle
 * of it. Observed natively: "[te" + guest "hi" + the rest of "[teb] ...".
 *
 * So the framing lives here, once: build the whole record — body, truncation
 * marker, exactly one trailing newline — in caller-supplied bounded storage,
 * then hand it to the sink EXACTLY ONCE. There is no retry and no fallback:
 * a second write of the same bytes is how a record gets duplicated, and a
 * second write of the tail is how it gets fragmented again.
 *
 * The formatter and the sink are injected because the two sides have
 * different ones (the kernel writes through nt_console_write, the stub writes
 * with WriteFile on its inherited stderr handle; both format with vsnprintf).
 * What is shared, and what the host tests drive, is the framing and the
 * emission rule.
 */
#ifndef UML_NT_DIAG_RECORD_H
#define UML_NT_DIAG_RECORD_H

/* The kernel builds freestanding (no libc headers) and brings its own
 * va_list; the stub and the host tests have the usual one. */
#ifdef __KERNEL__
#include <linux/stdarg.h>
#else
#include <stdarg.h>
#endif

/* A record never exceeds this, marker and newline included. */
#define UML_NT_DIAG_CAP		512u

/* Smallest capacity the framing can work in: one visible character, the
 * truncation marker and the newline, plus room for the terminator. */
#define UML_NT_DIAG_MIN_CAP	8u

/* What the framing did. Callers that keep ignoring the result are no worse
 * off than they were ignoring fprintf's, but the result is truthful. */
#define UML_NT_DIAG_OK		0	/* one call, whole record handed over */
#define UML_NT_DIAG_TRUNCATED	1	/* one call, record cut with "..." */
#define UML_NT_DIAG_SINK_UNKNOWN 2	/* one call; delivery not observable */
#define UML_NT_DIAG_SINK_FAIL	3	/* one call; sink reported short/fail */
#define UML_NT_DIAG_REFUSED	4	/* no call: no sink, or capacity too small */
#define UML_NT_DIAG_FMT_BROKEN	5	/* one call, but the formatter failed */

/* Sink contract: return the number of bytes it accepted. Returning len is a
 * complete record; every other value is a failure — including -1, which is
 * exactly what a failed WriteFile looks like, and 0, which is a zero-byte
 * write. A sink that cannot observe completion at all (the kernel's
 * nt_console_write is void) says so with the dedicated sentinel below, which
 * is deliberately NOT the ordinary error value: treating -1 as "unknown"
 * would report a known failure as an unknown one. */
#define UML_NT_DIAG_SINK_UNKNOWN_VALUE (-2147483647)

/* Formatter contract: C99 vsnprintf returns the length it would have
 * written; older msvcrt returns a negative value when it truncated. Both are
 * handled, and neither is trusted for the length actually in the buffer —
 * that is measured with a bounded scan. */
typedef int (*uml_nt_diag_format_fn)(char *buf, unsigned int cap,
				     const char *fmt, va_list ap);
typedef int (*uml_nt_diag_sink_fn)(const char *buf, unsigned int len);

struct uml_nt_diag_ops {
	uml_nt_diag_format_fn format;
	uml_nt_diag_sink_fn sink;
};

/* Length of a NUL-terminated string, never reading past `cap` bytes. */
static inline unsigned int uml_nt_diag_strnlen(const char *s, unsigned int cap)
{
	unsigned int n = 0;

	while (n < cap && s[n] != '\0')
		n++;
	return n;
}

/*
 * Frame and emit one record.
 *
 * `buf` is caller storage of `cap` bytes. On return the bytes [0, ret_len)
 * hold the record. The helper does use scratch bytes inside `buf` while it
 * works — the formatter writes the body, `buf[body_cap - 1]` is pinned to NUL
 * as a terminator, and a final NUL follows the record — so the guarantee is
 * "never writes past cap", not "writes only the record". `*ret_len` is always
 * set when it is not NULL. The sink is called at most once, and only with a
 * NUL-terminated record.
 */
static inline int uml_nt_diag_emit(char *buf, unsigned int cap,
				   const struct uml_nt_diag_ops *ops,
				   const char *fmt, va_list ap,
				   unsigned int *ret_len)
{
	/* "...\n" — the explicit marker plus the framing newline. */
	unsigned int marker = 4;	/* "...\n" */
	unsigned int body_cap, len, total;
	int n, r, truncated = 0, fmt_broken = 0;

	if (ret_len != (unsigned int *)0)
		*ret_len = 0;
	if (buf == (char *)0 || ops == (const struct uml_nt_diag_ops *)0 ||
	    ops->format == (uml_nt_diag_format_fn)0 ||
	    ops->sink == (uml_nt_diag_sink_fn)0 || fmt == (const char *)0 ||
	    cap < UML_NT_DIAG_MIN_CAP)
		return UML_NT_DIAG_REFUSED;

	/* Reserve the marker so a truncated record can still say so. */
	body_cap = cap - marker;
	buf[0] = '\0';
	buf[body_cap - 1] = '\0';
	n = ops->format(buf, body_cap, fmt, ap);
	buf[body_cap - 1] = '\0';	/* whatever the formatter claimed */
	len = uml_nt_diag_strnlen(buf, body_cap);

	/* Three ways to know the body did not fit: the C99 would-have-written
	 * length, the old negative truncation result, and a body that fills the
	 * reserved space exactly. None of them is trusted for the length; `len`
	 * above is what is really there. */
	if (n < 0) {
		/* msvcrt: negative means truncation, not "no characters". A
		 * formatter that wrote nothing at all is the broken case. */
		if (len == 0)
			fmt_broken = 1;
		else
			truncated = 1;
	} else if ((unsigned int)n >= body_cap) {
		/* C99: the length it would have written. Both sides' formatters
		 * return that (the kernel's vsnprintf included), so a value that
		 * does not reach body_cap means the body really did fit. */
		truncated = 1;
	}

	/* Framing newline: appended when the body does not already end in
	 * one. A body with interior newlines is passed through unchanged, so
	 * this is "add one if missing", not "reduce to exactly one". The
	 * guest's bytes are never touched — this is the diagnostic's own
	 * framing. */
	total = len;
	if (truncated) {
		buf[total++] = '.';
		buf[total++] = '.';
		buf[total++] = '.';
		buf[total++] = '\n';
	} else if (total == 0 || buf[total - 1] != '\n') {
		buf[total++] = '\n';
	}
	buf[total] = '\0';

	if (ret_len != (unsigned int *)0)
		*ret_len = total;

	/* One attempt. No retry, no fallback, no second write of any part. */
	r = ops->sink(buf, total);
	if (r == UML_NT_DIAG_SINK_UNKNOWN_VALUE)
		return fmt_broken ? UML_NT_DIAG_FMT_BROKEN :
		       UML_NT_DIAG_SINK_UNKNOWN;
	if (r != (int)total)
		return UML_NT_DIAG_SINK_FAIL;
	if (fmt_broken)
		return UML_NT_DIAG_FMT_BROKEN;
	return truncated ? UML_NT_DIAG_TRUNCATED : UML_NT_DIAG_OK;
}

/* Variadic convenience wrapper. */
static inline int uml_nt_diag_record(char *buf, unsigned int cap,
				     const struct uml_nt_diag_ops *ops,
				     const char *fmt, ...)
{
	va_list ap;
	int r;
	unsigned int len = 0;

	va_start(ap, fmt);
	r = uml_nt_diag_emit(buf, cap, ops, fmt, ap, &len);
	va_end(ap);
	return r;
}

#endif /* UML_NT_DIAG_RECORD_H */
