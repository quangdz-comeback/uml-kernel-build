/* SPDX-License-Identifier: GPL-2.0 */
/* Does a child conn inherit "this is the login chain"?
 *
 * The debugger is worth its freeze tax only on the conn we are chasing.
 * A conn is on the chain when it execed a login/getty binary itself, or
 * when one of its ancestors did and it was forked (not re-execed) from
 * that ancestor. The rule is deliberately tiny so it can be tested
 * without a guest: inherit the parent's flag, or discover it now.
 */
#ifndef _CHAIN_MODEL_H
#define _CHAIN_MODEL_H

static inline int uml_nt_chain_child(int parent_chain, int parent_is_login)
{
	return (parent_chain != 0) || (parent_is_login != 0);
}

#endif
