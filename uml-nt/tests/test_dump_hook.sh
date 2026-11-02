#!/usr/bin/env bash
# S11a: the dump hook must have a weak DEFAULT, not only a weak declaration.
#
# The kernel ELF is linked without the launcher, and the launcher is the only
# place that defines uml_nt_dump_hook. With a declaration alone the symbol is
# undefined and weak, so it resolves to address 0 — and the guard reads its
# VALUE (`if (uml_nt_dump_hook != NULL)`), which is a load from address 0.
# Natively that killed the death path at 0x60033dd9 (`mov (%rax),%rax` with
# rax=0) before uml_nt_death_site / [site] / [crumbs] / the dump ever ran.
#
# This test links the guard WITHOUT the launcher definition, the way the kernel
# is linked, and evaluates it in a forked child: a load from 0 kills the child
# (red), a defined weak default takes the no-hook branch and survives (green).
#
# It extracts the declaration/definition verbatim from process.c (same pattern
# as the S8 adapter test) so it cannot drift from the real source.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROC="${1:-$HERE/../kernel/overlay/arch/um/os-Windows/skas/process.c}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

python3 - "$PROC" "$TMP/hook.c" <<'PYEXTRACT'
import re
import sys

src_path, out_path = sys.argv[1], sys.argv[2]
src = open(src_path, encoding="utf-8", errors="replace").read()
m = re.search(r"/\* S11a-HOOK-BEGIN[^\n]*\n(.*?)/\* S11a-HOOK-END \*/", src,
              re.S)
if not m:
    raise SystemExit("S11a hook markers missing in " + src_path)
decl = m.group(1)

prog = r"""
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

""" + decl + r"""

int main(void)
{
	pid_t pid;
	int status = 0;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 2;
	}
	if (pid == 0) {
		/* THE guard, exactly as the kernel runs it: read the hook's
		 * value, not the address of the object. */
		if (uml_nt_dump_hook != NULL) {
			(void)uml_nt_dump_hook(1ul);
			_exit(10);	/* took the hook branch */
		}
		_exit(0);		/* no-hook branch, survived */
	}
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return 2;
	}
	if (WIFSIGNALED(status)) {
		printf("dump_hook: child died from signal %d (the guard read "
		       "through a null symbol)\n", WTERMSIG(status));
		return 1;
	}
	if (!WIFEXITED(status)) {
		printf("dump_hook: child did not exit normally\n");
		return 1;
	}
	if (WEXITSTATUS(status) != 0) {
		printf("dump_hook: child took the hook branch (exit %d) — no "
		       "weak default\n", WEXITSTATUS(status));
		return 1;
	}
	printf("dump_hook: no-hook branch taken and survived\n");
	return 0;
}
"""
open(out_path, "w").write(prog)
print("hook declaration extracted")
PYEXTRACT

# A weak data definition does not need -fcommon; the object is defined once.
"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/hook" "$TMP/hook.c"
"$TMP/hook"
