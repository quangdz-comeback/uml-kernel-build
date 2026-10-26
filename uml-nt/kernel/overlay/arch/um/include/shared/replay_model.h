/* REPLAY FOLLOWS CONTENT — Shelley 180 (D-level).
 *
 * D20 said the patch follows the content: a code replay is only valid if
 * the bytes it patches are still the bytes it read. A store replay obeys
 * the same law, one word at a time:
 *
 *   now == before  -> WRITE    nobody has written since we read it; the
 *                              store has not happened, replay it.
 *   now == want    -> ALREADY  the store's own value is there; it already
 *                              happened (the skip path or a twin view).
 *                              Never replay again.
 *   anything else  -> FOREIGN  someone newer wrote this word. Replaying
 *                              would overwrite fresh data with an older
 *                              intent — the entropy-buffer class this
 *                              model exists to stop.
 *
 * Pure logic, red-first in test_resume.c section 21.
 */
#ifndef _UML_NT_REPLAY_MODEL_H
#define _UML_NT_REPLAY_MODEL_H

enum uml_nt_replay_verdict {
	UML_NT_REPLAY_WRITE = 0,
	UML_NT_REPLAY_ALREADY = 1,
	UML_NT_REPLAY_FOREIGN = 2,
	UML_NT_REPLAY_STALE = 3,
};

/* A ledger entry describes ONE round. If the round has moved on, the
 * entry's before/want belong to a different instant and classifying
 * against them measures the ledger, not the race — the 70 "FOREIGN" hits
 * of referee 40358989413 were exactly that (an ASCII "SYSTEMD_" landing
 * where the entry expected two pointers). Shelley 181. */
static inline int uml_nt_replay_fresh(unsigned long long entry_seq,
				      unsigned long long now_seq)
{
	return entry_seq != 0 && entry_seq == now_seq;
}

static inline int uml_nt_replay_verdict(unsigned long long now,
					unsigned long long before,
					unsigned long long want)
{
	if (now == before)
		return UML_NT_REPLAY_WRITE;
	if (now == want)
		return UML_NT_REPLAY_ALREADY;
	return UML_NT_REPLAY_FOREIGN;
}

static inline int uml_nt_replay_verdict_seq(unsigned long long now,
					    unsigned long long before,
					    unsigned long long want,
					    int fresh)
{
	if (!fresh)
		return UML_NT_REPLAY_STALE;
	return uml_nt_replay_verdict(now, before, want);
}

/* May the replay write this word? Exactly one verdict says yes. */
static inline int uml_nt_replay_may_write(unsigned long long now,
					  unsigned long long before,
					  unsigned long long want)
{
	return uml_nt_replay_verdict(now, before, want) == UML_NT_REPLAY_WRITE;
}

static inline const char *uml_nt_replay_name(int v)
{
	switch (v) {
	case UML_NT_REPLAY_WRITE:
		return "WRITE";
	case UML_NT_REPLAY_ALREADY:
		return "SKIP-ALREADY";
	case UML_NT_REPLAY_STALE:
		return "STALE";
	default:
		return "SKIP-FOREIGN";
	}
}

#endif
