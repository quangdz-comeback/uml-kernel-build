// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/uaccess_walk.c — guest VA walker (D15). See
 * uaccess_walk.h. Self-contained by design: compiled as-is by the
 * Linux CI unit test (with vma.c + physalloc.c).
 *
 * No <string.h>: this file compiles BOTH freestanding in the kernel
 * (no host headers, D1) and in the unit test — the few byte ops are
 * spelled out here.
 */
#include <uaccess_walk.h>

#define UACC_PAGE 0x1000ull
#define UACC_PAGE_OFF(va) ((va) & (UACC_PAGE - 1))

static void uacc_bcopy(char *dst, const char *src, unsigned long long n)
{
	while (n--)
		*dst++ = *src++;
}

static void uacc_bzero(char *dst, unsigned long long n)
{
	while (n--)
		*dst++ = 0;
}

static unsigned long long uacc_bstrnlen(const char *s,
					unsigned long long max)
{
	unsigned long long n = 0;

	while (n < max && s[n])
		n++;
	return n;
}

int uml_nt_uacc_walk(const struct uml_nt_mm *mm, char *base,
		     unsigned long long va, unsigned long long len,
		     char *buf, int op)
{
	while (len) {
		unsigned long long chunk = UACC_PAGE - UACC_PAGE_OFF(va);
		long long off;

		if (chunk > len)
			chunk = len;
		off = uml_nt_vma_translate(mm, va, chunk);
		if (off < 0)
			return -1;
		switch (op) {
		case UML_NT_UACC_FROM_GUEST:
			uacc_bcopy(buf, base + off, chunk);
			buf += chunk;
			break;
		case UML_NT_UACC_TO_GUEST:
			uacc_bcopy(base + off, buf, chunk);
			buf += chunk;
			break;
		case UML_NT_UACC_ZERO_GUEST:
			uacc_bzero(base + off, chunk);
			break;
		}
		va += chunk;
		len -= chunk;
	}
	return 0;
}

static long long uacc_str_walk(char *dst, const struct uml_nt_mm *mm,
			       char *base, unsigned long long va,
			       unsigned long long maxlen, int want_nul_incl)
{
	unsigned long long done = 0;

	while (done < maxlen) {
		unsigned long long chunk = UACC_PAGE - UACC_PAGE_OFF(va);
		long long off, n;

		if (chunk > maxlen - done)
			chunk = maxlen - done;
		off = uml_nt_vma_translate(mm, va, chunk);
		if (off < 0)
			return want_nul_incl ? 0 : -1;
		n = (long long)uacc_bstrnlen(base + off, chunk);
		if (n < (long long)chunk) {
			/* NUL inside this chunk: copy it too, done. */
			if (dst)
				uacc_bcopy(dst + done, base + off,
					   (unsigned long long)n + 1);
			if (want_nul_incl)
				return done + n + 1; /* incl NUL */
			return done + n;
		}
		if (dst)
			uacc_bcopy(dst + done, base + off, chunk);
		done += chunk;
		va += chunk;
	}
	/* ran out without NUL: strnlen_user reports 0 (fault class),
	 * strncpy_from_user reports EFAULT (-1). */
	return want_nul_incl ? 0 : -1;
}

long long uml_nt_uacc_strncpy(char *dst, const struct uml_nt_mm *mm,
			      char *base, unsigned long long va,
			      unsigned long long maxlen)
{
	return uacc_str_walk(dst, mm, base, va, maxlen, 0);
}

long long uml_nt_uacc_strnlen(const struct uml_nt_mm *mm, char *base,
			      unsigned long long va,
			      unsigned long long maxlen)
{
	return uacc_str_walk((char *)0, mm, base, va, maxlen, 1);
}
