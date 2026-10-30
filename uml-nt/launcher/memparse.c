/* SPDX-License-Identifier: GPL-2.0 */
#include "memparse.h"

#include <stddef.h>

/* "128M", "1g", "134217728", "512MB" — a leading number, one optional
 * unit letter, an optional 'B'. Anything else is refused loudly rather
 * than silently treated as bytes. */
int uml_nt_parse_size(const char *s, unsigned long long *out)
{
	unsigned long long v = 0;
	unsigned long long mul = 1;
	int digits = 0;

	if (s == NULL || out == NULL)
		return -1;
	while (*s == ' ')
		s++;
	while (*s >= '0' && *s <= '9') {
		unsigned long long d = (unsigned long long)(*s - '0');

		if (v > (~0ull - d) / 10)
			return -1;	/* overflow */
		v = v * 10 + d;
		digits++;
		s++;
	}
	if (digits == 0)
		return -1;
	switch (*s) {
	case 'k': case 'K':
		mul = 1ull << 10;
		s++;
		break;
	case 'm': case 'M':
		mul = 1ull << 20;
		s++;
		break;
	case 'g': case 'G':
		mul = 1ull << 30;
		s++;
		break;
	default:
		break;
	}
	if (*s == 'b' || *s == 'B')
		s++;
	if (*s != 0)
		return -1;
	if (v != 0 && v > (~0ull) / mul)
		return -1;
	*out = v * mul;
	return *out == 0 ? -1 : 1;
}

int uml_nt_mem_arg(int argc, char **argv, unsigned long long *out)
{
	int i;

	if (argv == NULL || out == NULL)
		return 0;
	for (i = 1; i < argc; i++) {
		if (argv[i] != NULL && argv[i][0] == 'm' && argv[i][1] == 'e' &&
		    argv[i][2] == 'm' && argv[i][3] == '=')
			return uml_nt_parse_size(argv[i] + 4, out);
	}
	return 0;
}

unsigned long long uml_nt_mem_section_size(unsigned long long mem)
{
	unsigned long long sz = (mem + UML_NT_MEM_PAGE - 1) &
				~(UML_NT_MEM_PAGE - 1);

	sz = (sz + UML_NT_MEM_MIB - 1) & ~(UML_NT_MEM_MIB - 1);
	if (sz < UML_NT_MEM_DEFAULT && mem <= UML_NT_MEM_DEFAULT)
		sz = UML_NT_MEM_DEFAULT;
	return sz;
}
