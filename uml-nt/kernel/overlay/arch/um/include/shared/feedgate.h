/* SPDX-License-Identifier: GPL-2.0 */
/*
 * feedgate.h — the console feed follows the prompts, not the clock.
 *
 * The referee feeds credentials on stdin from the moment the guest starts, so
 * the bytes arrive long before login asks anything. login's own
 * tcsetattr(TCSAFLUSH) then discards whatever is pending — correctly, that is
 * what TCSAFLUSH means — and the feed is wiped at the exact moment it was
 * needed (referee 42078765811: three "[confeed] dropped ... at a tty input
 * flush", and no "Password:" ever appeared).
 *
 * So the feed waits for the prompt. This is a small state machine on the
 * console's OUTPUT: a line that begins "login: " arms the first line, a
 * "Password:" arms the second, and a shell prompt arms the rest. "/bin/login:"
 * in a log message is not a prompt — the preceding byte is '/', and that is
 * exactly the false positive the log itself produced.
 */
#ifndef UML_NT_FEEDGATE_H
#define UML_NT_FEEDGATE_H

/* how many feed lines are held back until their prompt appears */
struct uml_nt_feed_gate {
	int armed;	/* a prompt is waiting for one line */
	int stage;	/* 0 = before login, 1 = after username, 2 = shell */
	int lines;	/* lines released so far */
};

static inline void uml_nt_feed_gate_reset(struct uml_nt_feed_gate *g)
{
	g->armed = 0;
	g->stage = 0;
	g->lines = 0;
}

/* true when out[i..] starts a token at the beginning of a line */
static inline int uml_nt_feed_at_line_start(const char *out, unsigned len,
					    unsigned i)
{
	(void)len;
	if (i == 0)
		return 1;
	return out[i - 1] == '\n' || out[i - 1] == '\r';
}

static inline int uml_nt_feed_tok(const char *out, unsigned len, unsigned i,
				  const char *tok)
{
	unsigned n = 0;

	while (tok[n] != 0) {
		if (i + n >= len || out[i + n] != tok[n])
			return 0;
		n++;
	}
	return 1;
}

/* Scan console output. Arms one line per prompt seen, in order. */
static inline void uml_nt_feed_gate_scan(struct uml_nt_feed_gate *g,
					 const char *out, unsigned len)
{
	unsigned i;

	if (g == 0 || out == 0)
		return;
	for (i = 0; i < len; i++) {
		if (uml_nt_feed_tok(out, len, i, "login:") &&
		    (i == 0 || out[i - 1] == '\n' || out[i - 1] == '\r' ||
		     out[i - 1] == ' ')) {
			g->armed = 1;
			g->stage = 1;
			continue;
		}
		if (uml_nt_feed_tok(out, len, i, "Password:")) {
			g->armed = 1;
			g->stage = 2;
			continue;
		}
		/* a shell prompt after login — one more line may go */
		if (g->stage >= 2 &&
		    (uml_nt_feed_tok(out, len, i, "# ") ||
		     uml_nt_feed_tok(out, len, i, "$ "))) {
			g->armed = 1;
			g->stage = 3;
		}
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
