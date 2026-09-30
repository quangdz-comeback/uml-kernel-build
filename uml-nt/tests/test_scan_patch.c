/* Unit test for os-Windows/skas/scan_patch.c — runs on Linux CI.
 * Builds the decoder directly from the overlay file (self-contained)
 * and asserts: boundary-decoded 0F 05 is patched, `0F 05` bytes
 * hiding inside immediates are NOT (the R3 false-positive guard). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off, void *mark);

/* M5.1c.6b: the caller owns the mark scratch (the kernel allocates
 * it — the old alloca(len) buried neighbouring task stacks on
 * whole-image execs). */
static unsigned char mark[8192];

static int fails;

static void check(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok" : "not ok", what);
	if (!ok)
		fails++;
}

/* mov eax,1; mov edi,1; lea rsi,[rip+3]; mov edx,3; syscall; ret */
static const unsigned char blob_syscall[] = {
	0xb8, 0x01, 0x00, 0x00, 0x00,
	0xbf, 0x01, 0x00, 0x00, 0x00,
	0x48, 0x8d, 0x35, 0x03, 0x00, 0x00, 0x00,
	0xba, 0x03, 0x00, 0x00, 0x00,
	0x0f, 0x05,
	0xc3,
};

int main(void)
{
	unsigned char buf[64];
	unsigned long n;

	/* 1: real syscall instruction at a boundary → patched to ud2. */
	memcpy(buf, blob_syscall, sizeof(blob_syscall));
	n = uml_nt_patch_syscalls(buf, sizeof(blob_syscall), 0, mark);
	check("syscall at boundary patched", n == 1);
	check("syscall replaced by ud2",
	      buf[sizeof(blob_syscall) - 3] == 0x0f &&
	      buf[sizeof(blob_syscall) - 2] == 0x0b);

	/* 2: `0F 05` inside a mov-immediate (b8 0f 05 00 00) → the
	 * decoder sweeps OVER the immediate and must not patch. */
	{
		unsigned char imm[] = { 0xb8, 0x0f, 0x05, 0x00, 0x00, 0xc3 };
		memcpy(buf, imm, sizeof(imm));
		n = uml_nt_patch_syscalls(buf, sizeof(imm), 0, mark);
		check("0f05 inside immediate untouched", n == 0);
		check("immediate bytes intact",
		      buf[1] == 0x0f && buf[2] == 0x05);
	}

	/* 3: `0F 05` as the imm32 of `mov dword [rip+d], imm32`
	 * (C7 05 d32 0F 05 00 00) — addr_len+imm skips it whole. */
	{
		unsigned char store[] = {
			0xc7, 0x05, 0x10, 0x00, 0x00, 0x00,
			0x0f, 0x05, 0x00, 0x00,
			0xc3,
		};
		memcpy(buf, store, sizeof(store));
		n = uml_nt_patch_syscalls(buf, sizeof(store), 0, mark);
		check("0f05 in stored imm32 untouched", n == 0);
		check("stored imm32 bytes intact",
		      buf[6] == 0x0f && buf[7] == 0x05);
	}

	/* 4: entry_off sweep finds the syscall when offset 0 decode is
	 * led astray by data (the S6 two-pass entry trick). */
	{
		unsigned char two[] = {
			0xb8, 0x0f, 0x05, 0x00, 0x00, /* fake in imm */
			0x0f, 0x05,                   /* real, at entry */
			0xc3,
		};
		memcpy(buf, two, sizeof(two));
		n = uml_nt_patch_syscalls(buf, sizeof(two), 5, mark);
		check("entry pass patches the real syscall", n == 1);
		check("ud2 written at entry",
		      buf[6] == 0x0b && buf[5] == 0x0f);
	}

	printf(fails ? "# FAIL\n" : "# all ok\n");
	return fails != 0;
}
