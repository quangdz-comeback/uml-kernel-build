/* SPDX-License-Identifier: GPL-2.0 */
/*
 * diag_str.h — one way to put guest bytes in a log line.
 *
 * The console chain talks to the rest of the system through /dev/log, not
 * through the console: agetty's error paths go openlog(3)/vsyslog(3) and the
 * text lands in journald, where a referee's systemd.log never sees it. Run
 * 42274124035 ended the console reader with a 89-byte sendto to /dev/log and
 * nothing in the log said what the message was (report 380).
 *
 * Reading that payload back out of guest memory is worth nothing if the copy
 * can carry control bytes into the log: a stray '\n' breaks the one-record-per-
 * line contract the referee greps, and an escape sequence rewrites the terminal.
 * So the copy is PRINTABLE ONLY — every byte outside 0x20..0x7e becomes '.' —
 * and it is clamped to the caller's buffer, always NUL-terminated.
 *
 * Pure and header-only, like the feedgate helpers: the unit harness compiles
 * exactly this code (tests/test_syslog_peek.sh).
 */
#ifndef UML_NT_DIAG_STR_H
#define UML_NT_DIAG_STR_H

/* Copy at most dstmax-1 bytes of src, mapping non-printable bytes to '.'.
 * Returns the number of bytes written (not counting the terminator). */
static inline unsigned uml_nt_diag_sanitize(char *dst, unsigned dstmax,
					    const char *src, unsigned len)
{
	unsigned i, o = 0;

	if (dst == 0 || dstmax == 0)
		return 0;
	for (i = 0; i < len && o + 1 < dstmax; i++) {
		unsigned char ch = (unsigned char)src[i];

		dst[o++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.';
	}
	dst[o] = 0;
	return o;
}

#endif /* UML_NT_DIAG_STR_H */
