// SPDX-License-Identifier: GPL-2.0
/*
 * os-Windows/skas/scan_patch.c — central syscall→ud2 patcher (§5.1).
 *
 * Upstream seccomp UML lets guest `syscall` instructions hit a
 * SECCOMP_RET_TRAP filter. There is no seccomp on NT: instead every
 * guest `0F 05` (syscall) is patched to `0F 0B` (ud2) ONCE in the
 * shared physmem section — every stub maps the same physical pages
 * and sees the patch immediately. R3 false-positive risk: immediates
 * and jump tables may contain `0F 05` bytes — only patch what a
 * linear-sweep length decoder confirms as an instruction boundary
 * (M0/S6: 0 FP on the busybox/libc corpus).
 *
 * Decoder ported verbatim from spikes/s6_scan.c (freestanding now).
 * Unknown opcode → bail on the sweep position (conservative: never
 * patch what we cannot decode).
 *
 * Self-contained on purpose: tests/test_scan_patch.sh compiles this
 * file directly on Linux CI (no kernel headers in scope). No libc
 * calls — the kernel build has none (-nostdlib).
 */
typedef unsigned char u8_scan;

static int addr_len(const u8_scan *p, const u8_scan *end)
{
	u8_scan m, mod, rm, s;
	int n = 1;

	if (p >= end)
		return -1;
	m = *p++; mod = m >> 6; rm = m & 7;
	if (mod == 3)
		return 1;
	if (rm == 4) {
		if (p >= end)
			return -1;
		s = *p++; n++;
		if ((s & 7) == 5 && mod == 0)
			n += 4;
	} else if (mod == 0 && rm == 5) {
		n += 4;
	}
	if (mod == 1)
		n += 1;
	else if (mod == 2)
		n += 4;
	return n;
}

/* ModRM (+SIB/disp) plus a trailing immediate; 0 = truncated. */
static int modrm_imm(const u8_scan *s, const u8_scan *p,
		     const u8_scan *end, int imm)
{
	int al = addr_len(p, end);

	if (al < 0 || p + al + imm > end)
		return 0;
	return (int)(p - s) + al + imm;
}

/* Length of the opcode + operands that follow a map selector: `map`
 * 1 = 0F, 2 = 0F 38, 3 = 0F 3A. Shared by the legacy escapes and the
 * VEX/EVEX prefixes (which name the map instead of spelling it). */
static int map_len(const u8_scan *s, const u8_scan *p, const u8_scan *end,
		   int map)
{
	u8_scan o2;

	if (p >= end)
		return 0;
	o2 = *p++;
	if (map == 2)
		return modrm_imm(s, p, end, 0);
	if (map == 3)
		return modrm_imm(s, p, end, 1);

	if (o2 >= 0x80 && o2 <= 0x8F) /* jcc rel32 */
		return p + 4 > end ? 0 : (int)(p - s) + 4;
	if ((o2 >= 0x05 && o2 <= 0x09) || o2 == 0x0B || o2 == 0x0E ||
	    (o2 >= 0x30 && o2 <= 0x37) || o2 == 0x77 ||
	    o2 == 0xA0 || o2 == 0xA1 || o2 == 0xA2 || o2 == 0xA8 ||
	    o2 == 0xA9 || o2 == 0xAA || (o2 >= 0xC8 && o2 <= 0xCF))
		return (int)(p - s); /* no operands */
	if (o2 == 0x04 || o2 == 0x0A || o2 == 0x0C ||
	    (o2 >= 0x24 && o2 <= 0x27) || o2 == 0x36 || o2 == 0x39 ||
	    (o2 >= 0x3B && o2 <= 0x3F) || o2 == 0x7A || o2 == 0x7B)
		return 0; /* undefined */
	if ((o2 >= 0x70 && o2 <= 0x73) || o2 == 0xA4 || o2 == 0xAC ||
	    o2 == 0xBA || o2 == 0xC2 || (o2 >= 0xC4 && o2 <= 0xC6) ||
	    o2 == 0x0F /* 3DNow! suffix byte */)
		return modrm_imm(s, p, end, 1);
	return modrm_imm(s, p, end, 0); /* every other 0F xx has ModRM */
}

/*
 * x86-64 instruction length. Every defined one-byte opcode, the 0F /
 * 0F 38 / 0F 3A maps and the VEX/EVEX encodings are sized exactly; a
 * wrong length desyncs the sweep and silently skips the next
 * `syscall` — the M5.1c busybox had 4 of 115 left raw (MOVSXD 0x63
 * missing, 0x81 without its ModRM, 0x66 imm16 ignored, 0F BA/C1/A4/AC
 * missing), and a raw `syscall` runs an NT system service with Linux
 * arguments. Invalid-in-64-bit opcodes return 0 (the sweep steps one
 * byte and resyncs).
 */
static int insn_len(const u8_scan *p, const u8_scan *end)
{
	const u8_scan *s = p;
	u8_scan b, op;
	int rexw = 0, opsz16 = 0, adsz32 = 0, immz;

	for (;;) {
		if (p >= end)
			return 0;
		b = *p;
		if (b == 0x66) {
			opsz16 = 1;
			p++;
			continue;
		}
		if (b == 0x67) {
			adsz32 = 1;
			p++;
			continue;
		}
		if (b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x3E ||
		    b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65 ||
		    b == 0xF0) {
			p++;
			continue;
		}
		if (b >= 0x40 && b <= 0x4F) {
			/* REX binds only when it directly precedes the
			 * opcode; a later prefix voids it (harmless for
			 * lengths either way). */
			rexw = (b & 8) != 0;
			p++;
			continue;
		}
		break;
	}
	if (p >= end)
		return 0;
	op = *p++;
	/* REX.W wins over 0x66 for operand size. */
	immz = (opsz16 && !rexw) ? 2 : 4;

	if (op == 0x0F) {
		if (p >= end)
			return 0;
		if (*p == 0x38)
			return map_len(s, p + 1, end, 2);
		if (*p == 0x3A)
			return map_len(s, p + 1, end, 3);
		return map_len(s, p, end, 1);
	}

	/* VEX: C5 = 2-byte (implied map 0F), C4 = 3-byte (map in the
	 * low 5 bits of the first payload byte). Always VEX in 64-bit
	 * mode. */
	if (op == 0xC5) {
		if (p >= end)
			return 0;
		return map_len(s, p + 1, end, 1);
	}
	if (op == 0xC4) {
		int map;

		if (p + 2 > end)
			return 0;
		map = p[0] & 0x1F;
		if (map < 1 || map > 3)
			return 0;
		return map_len(s, p + 2, end, map);
	}
	/* EVEX: 62 P0 P1 P2, map in P0's low bits (disp8*N keeps the
	 * one-byte displacement size). */
	if (op == 0x62) {
		int map;

		if (p + 3 > end)
			return 0;
		map = p[0] & 0x07;
		if (map < 1 || map > 3)
			return 0;
		return map_len(s, p + 3, end, map);
	}

	if (op < 0x40) {
		switch (op & 7) {
		case 0: case 1: case 2: case 3:
			return modrm_imm(s, p, end, 0);
		case 4:
			return p + 1 > end ? 0 : (int)(p - s) + 1;
		case 5:
			return p + immz > end ? 0 : (int)(p - s) + immz;
		default:
			return 0; /* 06/07/0E/16/17/1E/1F/27/2F/37/3F:
				   * invalid in 64-bit (prefixes and 0F
				   * were consumed above) */
		}
	}
	if (op >= 0x50 && op <= 0x5F)
		return (int)(p - s);
	if (op == 0x63)
		return modrm_imm(s, p, end, 0);
	if (op == 0x68)
		return p + immz > end ? 0 : (int)(p - s) + immz;
	if (op == 0x69)
		return modrm_imm(s, p, end, immz);
	if (op == 0x6A)
		return p + 1 > end ? 0 : (int)(p - s) + 1;
	if (op == 0x6B)
		return modrm_imm(s, p, end, 1);
	if (op >= 0x6C && op <= 0x6F)
		return (int)(p - s);
	if (op >= 0x70 && op <= 0x7F)
		return p + 1 > end ? 0 : (int)(p - s) + 1;
	if (op == 0x80 || op == 0x83)
		return modrm_imm(s, p, end, 1);
	if (op == 0x81)
		return modrm_imm(s, p, end, immz);
	if (op >= 0x84 && op <= 0x8F)
		return modrm_imm(s, p, end, 0);
	if (op >= 0x90 && op <= 0x99)
		return (int)(p - s);
	if (op >= 0x9B && op <= 0x9F)
		return (int)(p - s);
	if (op >= 0xA0 && op <= 0xA3) {
		int moffs = adsz32 ? 4 : 8;

		return p + moffs > end ? 0 : (int)(p - s) + moffs;
	}
	if ((op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF))
		return (int)(p - s);
	if (op == 0xA8)
		return p + 1 > end ? 0 : (int)(p - s) + 1;
	if (op == 0xA9)
		return p + immz > end ? 0 : (int)(p - s) + immz;
	if (op >= 0xB0 && op <= 0xB7)
		return p + 1 > end ? 0 : (int)(p - s) + 1;
	if (op >= 0xB8 && op <= 0xBF) {
		int n = rexw ? 8 : (opsz16 ? 2 : 4);

		return p + n > end ? 0 : (int)(p - s) + n;
	}
	if (op == 0xC0 || op == 0xC1 || op == 0xC6)
		return modrm_imm(s, p, end, 1);
	if (op == 0xC7)
		return modrm_imm(s, p, end, immz);
	if (op == 0xC2 || op == 0xCA)
		return p + 2 > end ? 0 : (int)(p - s) + 2;
	if (op == 0xC8)
		return p + 3 > end ? 0 : (int)(p - s) + 3;
	if (op == 0xC3 || op == 0xC9 || op == 0xCB || op == 0xCC ||
	    op == 0xCF)
		return (int)(p - s);
	if (op == 0xCD)
		return p + 1 > end ? 0 : (int)(p - s) + 1;
	if ((op >= 0xD0 && op <= 0xD3) || (op >= 0xD8 && op <= 0xDF))
		return modrm_imm(s, p, end, 0);
	if (op == 0xD7)
		return (int)(p - s);
	if ((op >= 0xE0 && op <= 0xE7) || op == 0xEB)
		return p + 1 > end ? 0 : (int)(p - s) + 1;
	if (op == 0xE8 || op == 0xE9)
		return p + 4 > end ? 0 : (int)(p - s) + 4;
	if (op >= 0xEC && op <= 0xEF)
		return (int)(p - s);
	if (op == 0xF1 || op == 0xF4 || op == 0xF5 ||
	    (op >= 0xF8 && op <= 0xFD))
		return (int)(p - s);
	if (op == 0xF6 || op == 0xF7) {
		/* group 3: only TEST (/0, /1) carries an immediate */
		if (p >= end)
			return 0;
		if ((p[0] & 0x38) <= 0x08)
			return modrm_imm(s, p, end, op == 0xF6 ? 1 : immz);
		return modrm_imm(s, p, end, 0);
	}
	if (op == 0xFE || op == 0xFF)
		return modrm_imm(s, p, end, 0);
	return 0; /* invalid in 64-bit mode → the sweep steps a byte */
}

/*
 * Scan [buf, len) from `entry_off` (plus a sweep from offset 0 — same
 * two-pass trick as S6) and patch every decoded `0F 05` to `0F 0B`.
 * Returns the number of patches applied.
 *
 * `markp` = caller-provided scratch of at least `len` bytes. M5.1c.6b:
 * this used to be `__builtin_alloca(len)` with the note "caller keeps
 * len small (M2 init)" — the exec loader broke that promise the first
 * time it loaded a real image (busybox text segment = 0x30000): the
 * alloca sank rsp ~192KB below the THREAD_SIZE kernel stack, and the
 * memset over it zeroed the four neighbouring vmalloc task stacks
 * (the off-CPU pad guard caught the fill at rip 6001d362 = memset_orig,
 * rdx=0x30000) and sprayed the mark bytes — 0/1 per decoded byte — over
 * suspended tasks' schedule chains, which killed the net reader
 * (ret-to-0x1000100) the moment the vector channel went live.
 */
unsigned long uml_nt_patch_syscalls(void *buf, unsigned long len,
				    unsigned long entry_off, void *markp)
{
	u8_scan *b = buf, *end = b + len;
	u8_scan *mark = markp;
	unsigned long o, patched = 0;
	int pass;

	if (len < 2 || markp == 0)
		return 0;
	__builtin_memset(mark, 0, len);

	for (pass = 0; pass < 2; pass++) {
		o = (pass == 0) ? 0 : entry_off;
		if (pass == 1 && entry_off >= len)
			continue;
		while (o + 2 <= len) {
			int L = insn_len(b + o, end);

			if (L <= 0 || o + L > (unsigned long)len) {
				o++;
				continue;
			}
			mark[o] = 1;
			o += L;
		}
	}

	for (o = 0; o + 2 <= len; o++) {
		if (mark[o] && b[o] == 0x0F && b[o + 1] == 0x05) {
			b[o + 1] = 0x0B;
			patched++;
		}
	}
	return patched;
}
