/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ttymodel.h — the console's termios answers, in one testable place.
 *
 * /bin/login asks the console what it is before it prompts: TCGETS first, then
 * the window size and the process group, and it sets the terminal back with
 * TCSETS/TCFLSH as it goes. This port's console is not a kernel tty, so the
 * generic ioctl path answered ENOTTY (referee 42069926848:
 * "ioctl(0x5401) -> -25") and login had nothing to talk to.
 *
 * S81: the answers are STATEFUL. They used to be a constant, and that constant
 * was a lie of exactly the kind a correct libc catches: Debian's glibc 2.36
 * tcsetattr() runs TCGETS -> TCSETS -> TCGETS and compares the read-back with
 * the state it saw first. A model that returns the same bytes no matter what
 * was set reads as "the set never took effect", and when the only difference
 * asked for is PARENB/CREAD/CSIZE glibc returns EINVAL (libc+0xfd44b). That is
 * precisely how agetty died on run 42279051954:
 *
 *   [syslog] pid 1604 len=89 msg="… agetty[94]: tty0: failed to set terminal
 *   attributes: Invalid argument"
 *
 * eleven seconds after it had read the fed "root\n" — before execv(/bin/login).
 * A terminal that accepts TCSETS and then reads back something else is broken;
 * so the model remembers what it was given, starting from a cooked console.
 *
 * The shapes live here rather than in the syscall switch so a host test can call
 * them: the layout is the x86-64 kernel's (four flag words, a line discipline
 * byte, NCCS=19 control characters, then the two speed words glibc fills in).
 */
#ifndef UML_NT_TTYMODEL_H
#define UML_NT_TTYMODEL_H

#define UML_NT_TCGETS		0x5401u
#define UML_NT_TCSETS		0x5402u
#define UML_NT_TCSETSW		0x5403u
#define UML_NT_TCSETSF		0x5404u
#define UML_NT_TCFLSH		0x540bu
#define UML_NT_TIOCGPGRP	0x540fu
#define UML_NT_TIOCSPGRP	0x5410u
#define UML_NT_TIOCGWINSZ	0x5413u
#define UML_NT_TIOCSWINSZ	0x5414u
#define UML_NT_FIONREAD		0x541bu

/* struct termios, x86-64 kernel shape: 4 * u32 + c_line + c_cc[19] + 2 pad +
 * c_ispeed + c_ospeed. The pad keeps the speeds 4-byte aligned. */
#define UML_NT_TERMIOS_SIZE	40

/* flags: a sane cooked console — what agetty/login expect to read back */
#define UML_NT_T_I_ICRNL	0x00000100u
#define UML_NT_T_I_IXON		0x00000400u
#define UML_NT_T_O_OPOST	0x00000001u
#define UML_NT_T_O_ONLCR	0x00000004u
#define UML_NT_T_C_CS8		0x00000030u
#define UML_NT_T_C_CREAD	0x00000080u
#define UML_NT_T_C_B38400	0x00000f00u
#define UML_NT_T_L_ISIG		0x00000001u
#define UML_NT_T_L_ICANON	0x00000002u
#define UML_NT_T_L_ECHO		0x00000008u
#define UML_NT_T_L_ECHOE	0x00000010u
#define UML_NT_T_L_ECHOK	0x00000020u
#define UML_NT_T_L_IEXTEN	0x00008000u

#define UML_NT_T_VERASE_IDX	2	/* c_cc[VERASE] — backspace, 8a5e6cf */
#define UML_NT_T_VMIN_IDX	6
#define UML_NT_T_VTIME_IDX	5

struct uml_nt_winsize {
	unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel;
};

/* One terminal's termios, as this port answers it. `valid` is what makes the
 * difference between "never asked" (answer the cooked default) and "the guest
 * set this" (answer exactly that back). */
struct uml_nt_tty_model {
	unsigned char termios[UML_NT_TERMIOS_SIZE];
	int valid;
};

/* per-conn storage in the stub conn is zeroed at birth: no memset needed */
static inline void uml_nt_tty_model_init(struct uml_nt_tty_model *m,
					 unsigned char *out)
{
	unsigned int *w = (unsigned int *)out;
	unsigned char *cc;
	int i;

	for (i = 0; i < UML_NT_TERMIOS_SIZE; i++)
		out[i] = 0;
	w[0] = UML_NT_T_I_ICRNL | UML_NT_T_I_IXON;
	w[1] = UML_NT_T_O_OPOST | UML_NT_T_O_ONLCR;
	w[2] = UML_NT_T_C_B38400 | UML_NT_T_C_CS8 | UML_NT_T_C_CREAD;
	w[3] = UML_NT_T_L_ISIG | UML_NT_T_L_ICANON | UML_NT_T_L_ECHO |
	       UML_NT_T_L_ECHOE | UML_NT_T_L_ECHOK | UML_NT_T_L_IEXTEN;
	cc = out + 16;			/* c_line then c_cc[] */
	cc[0] = 0;			/* c_line = N_TTY */
	cc[1 + UML_NT_T_VERASE_IDX] = 0x7f;	/* DEL, the console */
	cc[1 + UML_NT_T_VMIN_IDX] = 1;
	cc[1 + UML_NT_T_VTIME_IDX] = 0;
	if (m != 0) {
		for (i = 0; i < UML_NT_TERMIOS_SIZE; i++)
			m->termios[i] = out[i];
		m->valid = 1;
	}
}

/*
 * Fill the reply for one ioctl request. `in` is the guest's buffer for the
 * requests that carry one (TCSETS/TCSETSW/TCSETSF/TCFLSH); it may be NULL when
 * the caller could not read it. Returns the number of bytes to write back to
 * guest memory (0 when the request needs no reply), or -1 when this is not a
 * request the console answers.
 */
static inline int uml_nt_tty_ioctl_fill(struct uml_nt_tty_model *m,
					unsigned int req,
					const unsigned char *in,
					unsigned char *out, unsigned len)
{
	int i;

	switch (req) {
	case UML_NT_TCGETS: {
		if (out == 0 || len < UML_NT_TERMIOS_SIZE)
			return -1;
		if (m == 0 || !m->valid) {
			/* first question of a fresh descriptor: the cooked
			 * console, and that becomes the remembered state */
			uml_nt_tty_model_init(m, out);
			return UML_NT_TERMIOS_SIZE;
		}
		for (i = 0; i < UML_NT_TERMIOS_SIZE; i++)
			out[i] = m->termios[i];
		return UML_NT_TERMIOS_SIZE;
	}
	case UML_NT_TCSETS:
	case UML_NT_TCSETSW:
	case UML_NT_TCSETSF:
		/* S81: remember it. The next TCGETS must answer exactly this —
		 * that is what "the set took effect" means to a caller. */
		if (m != 0 && in != 0) {
			for (i = 0; i < UML_NT_TERMIOS_SIZE; i++)
				m->termios[i] = in[i];
			m->valid = 1;
		}
		return 0;
	case UML_NT_TIOCGWINSZ: {
		struct uml_nt_winsize ws;

		if (out == 0 || len < sizeof(ws))
			return -1;
		ws.ws_row = 24;
		ws.ws_col = 80;
		ws.ws_xpixel = 0;
		ws.ws_ypixel = 0;
		for (i = 0; i < (int)sizeof(ws); i++)
			out[i] = ((unsigned char *)&ws)[i];
		return (int)sizeof(ws);
	}
	case UML_NT_TIOCGPGRP:
		if (out == 0 || len < 4)
			return -1;
		for (i = 0; i < 4; i++)
			out[i] = 0;		/* no job control on this console */
		return 4;
	case UML_NT_FIONREAD:
		if (out == 0 || len < 4)
			return -1;
		for (i = 0; i < 4; i++)
			out[i] = 0;		/* nothing buffered here */
		return 4;
	/* flushes and the rest of the writes: accepted, nothing to return */
	case UML_NT_TCFLSH:
	case UML_NT_TIOCSPGRP:
	case UML_NT_TIOCSWINSZ:
		return 0;
	}
	return -1;
}

#endif /* UML_NT_TTYMODEL_H */
