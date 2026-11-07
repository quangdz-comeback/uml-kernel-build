/* SPDX-License-Identifier: GPL-2.0 */
/*
 * feedgate.h — the console feed follows the prompts, and the prompt is a LINE.
 *
 * The referee feeds credentials on stdin from the moment the guest starts, so
 * the bytes are pending long before login asks. login's own
 * tcsetattr(TCSAFLUSH) then discards them — correctly — and the feed is wiped at
 * the moment it was needed (referee 42078765811: three "[confeed] dropped ... at
 * a tty input flush", no "Password:").
 *
 * The first attempt matched prompts inside a single write and never armed: a
 * prompt can arrive split across writes, and kernel log lines interleave with
 * guest output character by character (the "[commit-ahead]" line landing inside
 * "login: " is exactly that). So the gate scans the ACCUMULATED line — bytes are
 * appended, the line is examined as a whole, and only a newline starts a new one.
 */
#ifndef UML_NT_FEEDGATE_H
#define UML_NT_FEEDGATE_H

#define UML_NT_FEED_LINE_MAX 160

struct uml_nt_feed_gate {
	int armed;	/* a prompt is waiting for one line */
	int src;	/* which door produced the last bytes */
	int stage;	/* 0 = before login, 1 = user, 2 = password, 3 = shell */
	int lines;	/* lines released so far */
	int last_armed_stage;	/* for the one-shot arm record */
	int dbg_n;		/* records printed for this console (cap 8) */
	int arm_n;		/* times this console armed a line */
	/* S45: one line per SOURCE. A kernel log line arriving between two halves
	 * of the guest's prompt must not reset the guest's line — the two doors
	 * feed one state machine, but they must not share a buffer. */
	unsigned len[2];	/* 0 = tty write, 1 = printk */
	char line[2][UML_NT_FEED_LINE_MAX];
	char last_tail[40];	/* the previous tail record's text (dedupe) */
	/* S47: a line that no longer starts where it began cannot be trusted for
	 * matching — truncating the head of "[pivot-wslot] … /bin/login:" removed
	 * the '/' that told the matcher it was a path, and the gate armed on a
	 * kernel line. Overflow now DROPS the write and marks the line. */
	int truncated[2];
	int match_src;		/* which buffer produced the last arm */
};

static inline void uml_nt_feed_gate_reset(struct uml_nt_feed_gate *g)
{
	g->armed = 0;
	g->stage = 0;
	g->lines = 0;
	g->last_armed_stage = 0;
	g->dbg_n = 0;
	g->len[0] = 0;
	g->len[1] = 0;
	g->last_tail[0] = 0;
	g->truncated[0] = 0;
	g->truncated[1] = 0;
	g->match_src = 0;
	g->arm_n = 0;
	g->len[0] = 0;
	g->len[1] = 0;
}

static inline int uml_nt_feed_find(const char *hay, unsigned len,
				   const char *tok)
{
	unsigned n = 0, i;

	while (tok[n] != 0)
		n++;
	if (n == 0 || len < n)
		return 0;
	for (i = 0; i + n <= len; i++) {
		unsigned k = 0;

		while (k < n && hay[i + k] == tok[k])
			k++;
		if (k == n)
			return 1;
	}
	return 0;
}

/*
 * The console carries colour: systemd writes "\e[0;1;38;5;100m" before its
 * text and the run showed such a sequence landing inside a line. Prompt matching
 * therefore looks at the line with escape sequences removed — CSI sequences
 * ("ESC [ ... final-byte") and the two-byte "ESC <char>" form.
 */
static inline unsigned uml_nt_feed_strip_esc(char *dst, unsigned dstmax,
					     const char *src, unsigned len)
{
	unsigned i = 0, o = 0;

	while (i < len && o + 1 < dstmax) {
		if ((unsigned char)src[i] == 0x1b) {
			if (i + 1 < len && src[i + 1] == '[') {
				i += 2;
				while (i < len &&
				       !((src[i] >= 'A' && src[i] <= 'Z') ||
					 (src[i] >= 'a' && src[i] <= 'z')))
					i++;
				if (i < len)
					i++;	/* the final byte */
				continue;
			}
			i += 2;			/* ESC + one char */
			continue;
		}
		dst[o++] = src[i++];
	}
	dst[o] = 0;
	return o;
}

/* A prompt token, but not a path that merely ends in it: "/bin/login:" is a
 * log line, and the referee's own output produced exactly that false positive. */
static inline int uml_nt_feed_find_prompt(const char *hay, unsigned len,
					  const char *tok)
{
	unsigned n = 0, i;

	while (tok[n] != 0)
		n++;
	if (n == 0 || len < n)
		return 0;
	for (i = 0; i + n <= len; i++) {
		unsigned k = 0;

		if (i > 0 && hay[i - 1] == '/')
			continue;
		while (k < n && hay[i + k] == tok[k])
			k++;
		if (k == n)
			return 1;
	}
	return 0;
}

/* Examine the accumulated line and arm what it asks for. */
static inline void uml_nt_feed_gate_line(struct uml_nt_feed_gate *g,
					 int src)
{
	char clean[UML_NT_FEED_LINE_MAX];
	unsigned clen;

	if (g->len[src] == 0 || g->truncated[src])
		return;		/* a headless line may match anything: never use it */
	clen = uml_nt_feed_strip_esc(clean, sizeof(clean), g->line[src],
				      g->len[src]);
	/* S90: systemd's own complaints about the login unit are not prompts.
	 * "login.service: Control process exited, code=exited, status=6/ABRT"
	 * armed the feed on the "login:" inside it (referee 42312661055) — the
	 * third time an instrument ate its own log. An explicit blacklist, not a
	 * position rule: a real prompt may carry a hostname ("uml login: ") and
	 * S45 splits one across a kernel line, but no prompt is a status line. */
	if (uml_nt_feed_find(clean, clen, "systemd[") ||
	    uml_nt_feed_find(clean, clen, "status=") ||
	    uml_nt_feed_find(clean, clen, "code=exited"))
		return;
	/* the MOST RECENT prompt wins: a line can still carry the login prompt
	 * when the password prompt is printed after it, so the later stage is
	 * checked first */
	if (uml_nt_feed_find_prompt(clean, clen, "Password:")) {
		g->armed = 1;
		g->stage = 2;
		g->match_src = src;
		return;
	}
	if (g->stage >= 2 &&
	    (uml_nt_feed_find(clean, clen, "# ") ||
	     uml_nt_feed_find(clean, clen, "$ "))) {
		g->armed = 1;
		g->stage = 3;
		g->match_src = src;
		return;
	}
	if (uml_nt_feed_find_prompt(clean, clen, "login:")) {
		g->armed = 1;
		g->stage = 1;
		g->match_src = src;
	}
}

/*
 * S81: is this write the PORT's own voice rather than the guest's console?
 *
 * Every path that prints ends in one choke point (nt_console_write), so the gate
 * reads the kernel's diagnostic records as well as the guest's output. That was
 * harmless while the records were ours alone — until an instrument echoed guest
 * bytes back: on run 42279051954 a [syslog] record carrying
 * "pam_unix(login:account)" armed the feed on the "login:" inside it (report
 * 380, rule #24: the measurement fed the mechanism it measures).
 *
 * A record is framed: one write that begins with '[' , closes its tag within the
 * first few bytes, and ends with the record's newline. A guest prompt fragment
 * is not framed like that (it neither starts with '[' nor ends with a newline),
 * so prompts still reach the matcher — which is why the check is this and not
 * "anything starting with a bracket".
 */
static inline int uml_nt_feed_port_voice(const char *s, unsigned n)
{
	int k;

	if (s == 0 || n < 3 || s[0] != '[' || s[n - 1] != '\n')
		return 0;
	for (k = 1; k < (int)n && k < 24; k++)
		if (s[k] == ']')
			return 1;
	return 0;
}

/* Append console output from one source; a newline ends THAT source's line. */
static inline void uml_nt_feed_gate_scan(struct uml_nt_feed_gate *g,
					 const char *out, unsigned len, int src)
{
	unsigned i;

	if (g == 0 || out == 0 || src < 0 || src > 1)
		return;
	g->src = src;
	for (i = 0; i < len; i++) {
		char ch = out[i];

		if (ch == '\n' || ch == '\r') {
			g->len[src] = 0;
			g->truncated[src] = 0;
			continue;
		}
		if (g->len[src] + 1 < UML_NT_FEED_LINE_MAX) {
			g->line[src][g->len[src]++] = ch;
		} else {
			/* overflow: keep what we have, stop growing, and mark the
			 * line as headless so nothing is matched against it */
			g->truncated[src] = 1;
			continue;
		}
		g->line[src][g->len[src]] = 0;
		uml_nt_feed_gate_line(g, src);
	}
}

/* Consume one allowance; returns 1 when a feed line may be released. */
static inline int uml_nt_feed_gate_take(struct uml_nt_feed_gate *g)
{
	if (g == 0 || !g->armed)
		return 0;
	g->armed = 0;
	g->lines++;
	return 1;
}

#endif /* UML_NT_FEEDGATE_H */
