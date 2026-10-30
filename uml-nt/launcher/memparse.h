/* SPDX-License-Identifier: GPL-2.0 */
/*
 * memparse.h — the launcher's mem= contract, kept separate so it can be
 * tested on the host with a plain C compiler (the launcher itself is
 * Windows-only).
 *
 * The section that backs guest RAM is the ceiling the kernel may map; the
 * kernel's own mem= picks how much of it it uses. They are not the same
 * number, and until now the launcher ignored mem= entirely: a user asking
 * for 512M got a 128MiB section, the kernel tried to map 512MiB, and the
 * failure surfaced as "setup_physmem - mapping ... failed errno=-1" followed
 * by os_dump_core — a message that names neither the cause nor the number.
 */
#ifndef UML_NT_MEMPARE_H
#define UML_NT_MEMPARE_H

#define UML_NT_MEM_DEFAULT	(128ull << 20)
#define UML_NT_MEM_PAGE		(64ull << 10)	/* run granularity */
#define UML_NT_MEM_MIB		(1ull << 20)

/* Parse "mem=" out of an argument vector. Accepts 512M, 1G, 134217728 and
 * the same with a trailing 'b'/'B'. Returns 1 when found and valid, 0 when
 * absent (out untouched), -1 when present but unusable. */
int uml_nt_mem_arg(int argc, char **argv, unsigned long long *out);

/* Parse a size expression on its own ("512M", "134217728"). 1 ok, -1 bad. */
int uml_nt_parse_size(const char *s, unsigned long long *out);

/* Round a requested size up to the run/page granularity, then to MiB, and
 * clamp the slack above the request to `overhead_max` so a request never
 * pays more than that in waste. Returns the section size to create. */
unsigned long long uml_nt_mem_section_size(unsigned long long mem);

#endif
