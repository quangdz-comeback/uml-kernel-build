// SPDX-License-Identifier: GPL-2.0
/*
 * elf_split.c — S4: split the packed exec-string blob into argv/envp
 * host pointer arrays.
 *
 * Pure logic, unit-tested (tests/test_elf.c): NO kernel includes, no
 * os layer — the blob is caller-supplied bytes.
 *
 * copy_strings packs the strings BACKWARD from the stack top (fs/
 * exec.c: "We're going to work our way backwards"): do_execveat_
 * common copies the filename first (highest), then the envp block,
 * then argv — each call walking its array from the last element
 * down. The blob therefore reads from the LOW byte up as:
 *
 *	argv[0] argv[1] .. argv[argc-1] envp[0] .. envp[envc-1] filename
 *
 * every string NUL-terminated, packed with no gaps (bprm->p = the
 * blob start, bprm->exec = the filename start, the blob end = the
 * filename's NUL). The empty-argv rule ("") from do_execveat_common
 * lands as a zero-length argv[0] and splits fine.
 */
#include <elf.h>

int uml_nt_elf_split_args(unsigned char *blob, unsigned long long len,
			  int argc, int envc, const char **out_argv,
			  const char **out_envp)
{
	unsigned long long i = 0;
	int n;

	if (blob == (unsigned char *)0 || len == 0)
		return -1;
	if (argc < 0 || envc < 0 || argc > UML_NT_ELF_MAX_STR ||
	    envc > UML_NT_ELF_MAX_STR)
		return -1;

	for (n = 0; n < argc; n++) {
		if (i >= len)
			return -1;
		out_argv[n] = (const char *)(blob + i);
		while (i < len && blob[i] != 0)
			i++;
		if (i >= len)
			return -1; /* string ran past the blob */
		i++; /* its NUL */
	}
	for (n = 0; n < envc; n++) {
		if (i >= len)
			return -1;
		out_envp[n] = (const char *)(blob + i);
		while (i < len && blob[i] != 0)
			i++;
		if (i >= len)
			return -1;
		i++;
	}

	/* The filename closes the blob: exactly one string left — and
	 * it must be NON-empty (a filename is never ""), so a wrong
	 * argc/envc pair cannot eat the real filename as a string and
	 * alias the layout. */
	if (i >= len)
		return -1;
	if (blob[i] == 0)
		return -1;
	while (i < len && blob[i] != 0)
		i++;
	if (i != len - 1 || blob[i] != 0)
		return -1;
	return 0;
}
