/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dbg_map.h — how a debug event is answered, as a pure function.
 *
 * A debug port has exactly one consumer and exactly one rule per event kind;
 * getting either wrong leaves the debuggee stopped (nothing arrives after the
 * create event) or swallows the exception we are trying to see. Keeping the
 * rule in a header lets the host tests check it without Windows.
 */
#ifndef UML_NT_DBG_MAP_H
#define UML_NT_DBG_MAP_H

#define UML_NT_DBG_EV_EXCEPTION	1u
#define UML_NT_DBG_EV_EXIT_PROCESS	5u

#define UML_NT_DBG_ANS_CONTINUE	0u	/* DBG_CONTINUE */
#define UML_NT_DBG_ANS_NOT_HANDLED	1u	/* DBG_EXCEPTION_NOT_HANDLED */

#define UML_NT_STATUS_BREAKPOINT 0x80000003u

/* first_bp: in/out — the loader's breakpoint is continued, every later one
 * is left to the debuggee like any other exception. */
static inline unsigned uml_nt_dbg_answer(unsigned ev_code, unsigned exc_code,
					 int *first_bp)
{
	if (ev_code != UML_NT_DBG_EV_EXCEPTION) {
		/* create/load/thread/exit and everything else: the debuggee
		 * must be allowed to run */
		return UML_NT_DBG_ANS_CONTINUE;
	}
	if (exc_code == UML_NT_STATUS_BREAKPOINT &&
	    first_bp != 0 && *first_bp == 0) {
		*first_bp = 1;
		return UML_NT_DBG_ANS_CONTINUE;
	}
	/* never steal: the debuggee's own handlers see it exactly as they
	 * would without a debugger */
	return UML_NT_DBG_ANS_NOT_HANDLED;
}

#endif
