/* SPDX-License-Identifier: GPL-2.0 */
/*
 * threadrole.h — WHICH host thread is running, answered per thread.
 *
 * The port already had a role string (uml_nt_thread_role) and it is a single
 * global: the timer thread sets it to "timer" at startup, so the crash report
 * prints "thread=timer" for whatever thread actually faulted. Report 381 §3
 * could not read a fault's owner because of it, and the console flush needs a
 * real answer — kernel tty code may only run on a conn/vCPU thread (D19).
 *
 * Claims are explicit: each aux thread claims its role at entry, keyed by its
 * own host thread id. Anything unclaimed is a conn thread, which is the
 * default this port's history assumes (the vCPU threads never claim).
 */
#ifndef UML_NT_THREADROLE_H
#define UML_NT_THREADROLE_H

#define UML_NT_THREAD_SLOTS 8

struct uml_nt_thread_slot {
	unsigned long long tid;
	const char *role;
};

/* Claim a role for `tid`. Re-claiming the same thread replaces the role. A
 * full table leaves the caller unclaimed (and therefore a conn thread) rather
 * than stealing another thread's slot. */
static inline const char *uml_nt_thread_claim(struct uml_nt_thread_slot *t,
					      int n, unsigned long long tid,
					      const char *role)
{
	int i, free_slot = -1;

	for (i = 0; i < n; i++) {
		if (t[i].role == 0) {
			if (free_slot < 0)
				free_slot = i;
			continue;
		}
		if (t[i].tid == tid) {
			t[i].role = role;
			return role;
		}
	}
	if (free_slot >= 0) {
		t[free_slot].tid = tid;
		t[free_slot].role = role;
	}
	return role;
}

/* The role of `tid`, "conn" when it never claimed one. */
static inline const char *uml_nt_thread_role_at(const struct uml_nt_thread_slot *t,
						int n, unsigned long long tid)
{
	int i;

	for (i = 0; i < n; i++)
		if (t[i].role != 0 && t[i].tid == tid)
			return t[i].role;
	return "conn";
}

/* Is this a conn/vCPU thread (the only kind allowed to run kernel tty code)? */
static inline int uml_nt_thread_is_conn_role(const char *role)
{
	return role != 0 && role[0] == 'c' && role[1] == 'o';
}

/* The console flush's door rule (S82, D19): a flush runs only from a conn
 * thread, whatever door asked and whatever is pending. */
static inline int uml_nt_flush_door_ok(const char *role)
{
	return uml_nt_thread_is_conn_role(role);
}

#endif /* UML_NT_THREADROLE_H */
