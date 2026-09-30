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

	/* 5: every instruction shape the S6-era decoder mis-sized, each
	 * directly followed by a real `syscall`. A wrong length lands
	 * the sweep inside the next bytes and the syscall stays raw (the
	 * M5.1c busybox kept 4 of 115: mprotect, socket, open, futex). */
	{
		static const struct {
			const char *what;
			unsigned char len;
			unsigned char insn[8];
		} cases[] = {
			{ "81 /4 imm32 needs its ModRM (and rsi,imm32)", 7,
			  { 0x48, 0x81, 0xe6, 0x00, 0xf0, 0xff, 0xff } },
			{ "63 MOVSXD (movslq esi,rsi)", 3,
			  { 0x48, 0x63, 0xf6 } },
			{ "66 25 imm16 (and ax,imm16)", 4,
			  { 0x66, 0x25, 0x00, 0xfb } },
			{ "66 c7 imm16 (movw $2,4(rbx))", 6,
			  { 0x66, 0xc7, 0x43, 0x04, 0x02, 0x00 } },
			{ "66 f7 /0 imm16 (test di,imm16)", 5,
			  { 0x66, 0xf7, 0xc7, 0xc0, 0x0f } },
			{ "0f ba /4 imm8 (bt eax,11)", 4,
			  { 0x0f, 0xba, 0xe0, 0x0b } },
			{ "f0 0f c1 (lock xadd)", 4,
			  { 0xf0, 0x0f, 0xc1, 0x07 } },
			{ "0f a4 imm8 (shld)", 5,
			  { 0x4c, 0x0f, 0xa4, 0xf0, 0x3e } },
			{ "0f 38 (pshufb)", 5,
			  { 0x66, 0x0f, 0x38, 0x00, 0xc1 } },
			{ "0f 3a imm8 (palignr)", 6,
			  { 0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08 } },
			{ "VEX c5 (vmovdqa xmm0,[rsi])", 4,
			  { 0xc5, 0xf9, 0x6f, 0x06 } },
			{ "VEX c4 map 0F3A imm8 (vpalignr)", 6,
			  { 0xc4, 0xe3, 0x71, 0x0f, 0xc2, 0x08 } },
			{ "EVEX 62 (vmovdqu64 zmm0,[rsi])", 6,
			  { 0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x06 } },
		};
		unsigned int i;

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			unsigned int L = cases[i].len;

			memcpy(buf, cases[i].insn, L);
			buf[L] = 0x0f;
			buf[L + 1] = 0x05;
			buf[L + 2] = 0xc3;
			n = uml_nt_patch_syscalls(buf, L + 3, 0, mark);
			check(cases[i].what,
			      n == 1 && buf[L] == 0x0f && buf[L + 1] == 0x0b &&
			      memcmp(buf, cases[i].insn, L) == 0);
		}
	}

	/* 6: 0x66 shrinks the immediate to 16 bits — a `0F 05` that IS
	 * the imm16 stays data. */
	{
		unsigned char imm16[] = { 0x66, 0x25, 0x0f, 0x05, 0xc3 };

		memcpy(buf, imm16, sizeof(imm16));
		n = uml_nt_patch_syscalls(buf, sizeof(imm16), 0, mark);
		check("0f05 as a 66-prefixed imm16 untouched",
		      n == 0 && buf[2] == 0x0f && buf[3] == 0x05);
	}

	printf(fails ? "# FAIL\n" : "# all ok\n");
	return fails != 0;
}
