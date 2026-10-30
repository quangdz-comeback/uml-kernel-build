/* SPDX-License-Identifier: GPL-2.0 */
/* Red-before-tests for the launcher's mem= contract. */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../launcher/memparse.h"

static int fails;
#define CHECK(c) do { if (!(c)) { \
	fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } \
} while (0)

int main(void)
{
	unsigned long long v = 0;
	char *ok128[] = { "launcher", "vmlinux", "mem=128M" };
	char *ok512[] = { "launcher", "vmlinux", "mem=512M" };
	char *ok1g[] = { "launcher", "vmlinux", "mem=1G" };
	char *oknum[] = { "launcher", "vmlinux", "mem=134217728" };
	char *bad[] = { "launcher", "vmlinux", "mem=12x8" };
	char *bad2[] = { "launcher", "vmlinux", "mem=" };
	char *none[] = { "launcher", "vmlinux" };

	CHECK(uml_nt_parse_size("128M", &v) == 1 && v == (128ull << 20));
	CHECK(uml_nt_parse_size("512M", &v) == 1 && v == (512ull << 20));
	CHECK(uml_nt_parse_size("1G", &v) == 1 && v == (1ull << 30));
	CHECK(uml_nt_parse_size("134217728", &v) == 1 && v == 134217728ull);
	CHECK(uml_nt_parse_size("512MB", &v) == 1 && v == (512ull << 20));
	CHECK(uml_nt_parse_size("12x8", &v) == -1);
	CHECK(uml_nt_parse_size("", &v) == -1);
	CHECK(uml_nt_parse_size(NULL, &v) == -1);
	CHECK(uml_nt_parse_size("999999999999999999999G", &v) == -1);

	CHECK(uml_nt_mem_arg(3, ok128, &v) == 1 && v == (128ull << 20));
	CHECK(uml_nt_mem_arg(3, ok512, &v) == 1 && v == (512ull << 20));
	CHECK(uml_nt_mem_arg(3, ok1g, &v) == 1 && v == (1ull << 30));
	CHECK(uml_nt_mem_arg(3, oknum, &v) == 1 && v == 134217728ull);
	CHECK(uml_nt_mem_arg(3, bad, &v) == -1);
	CHECK(uml_nt_mem_arg(3, bad2, &v) == -1);
	CHECK(uml_nt_mem_arg(2, none, &v) == 0);

	/* the ceiling arithmetic: a 120M request must still create the same
	 * 128MiB section the tree has always used, or the referee changes
	 * meaning */
	CHECK(uml_nt_mem_section_size(120ull << 20) == (128ull << 20));
	CHECK(uml_nt_mem_section_size(128ull << 20) == (128ull << 20));
	CHECK(uml_nt_mem_section_size(129ull << 20) == (129ull << 20));
	CHECK(uml_nt_mem_section_size(313ull << 20) == (313ull << 20));

	if (fails) {
		fprintf(stderr, "test_memparse: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_memparse: all checks passed\n");
	return 0;
}
