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

static int insn_len(const u8_scan *p, const u8_scan *end)
{
	const u8_scan *s = p;
	u8_scan b, op, o2;
	int rexw = 0, al, imm = 0;

	for (;;) {
		if (p >= end)
			return 0;
		b = *p;
		if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 ||
		    b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
		    b == 0x64 || b == 0x65 || b == 0xF0) {
			p++;
			continue;
		}
		if (b >= 0x40 && b <= 0x4F) {
			rexw = (b & 8) != 0;
			p++;
			continue;
		}
		break;
	}
	if (p >= end)
		return 0;
	op = *p++;

	if (op == 0x0F) {
		if (p >= end)
			return 0;
		o2 = *p++;
		if (o2 == 0x05 || o2 == 0x0B || o2 == 0x34 || o2 == 0x35 ||
		    o2 == 0x31 || o2 == 0xA2 || (o2 >= 0xC8 && o2 <= 0xCF))
			return (int)(p - s);
		if (o2 == 0x38 || o2 == 0x3A)
			return 0;
		if (o2 >= 0x80 && o2 <= 0x8F) {
			if (p + 4 > end)
				return 0;
			return (int)(p - s) + 4;
		}
		if (o2 == 0x70 || o2 == 0x71 || o2 == 0x72 || o2 == 0x73 ||
		    o2 == 0xC6) {
			al = addr_len(p, end);
			if (al < 0)
				return 0;
			return (int)(p - s) + al + 1;
		}
		if ((o2 >= 0x40 && o2 <= 0x4F) || (o2 >= 0x90 && o2 <= 0x9F) ||
		    o2 == 0x1F || (o2 >= 0x10 && o2 <= 0x17) ||
		    (o2 >= 0x28 && o2 <= 0x2F) || (o2 >= 0x51 && o2 <= 0x5F) ||
		    (o2 >= 0x60 && o2 <= 0x6F) || o2 == 0x7E || o2 == 0x7F ||
		    (o2 >= 0xA3 && o2 <= 0xA7) || (o2 >= 0xAB && o2 <= 0xAF) ||
		    (o2 >= 0xB0 && o2 <= 0xB7) || (o2 >= 0xBC && o2 <= 0xBF) ||
		    (o2 >= 0xD0 && o2 <= 0xFE) || o2 == 0x18 || o2 == 0x1E ||
		    o2 == 0xA2 || o2 == 0xA8) {
			al = addr_len(p, end);
			if (al < 0)
				return 0;
			return (int)(p - s) + al;
		}
		return 0;
	}

	if (op < 0x40 && (op & 7) == 4)
		imm = 1;
	if (op < 0x40 && (op & 7) == 5)
		imm = 4;
	if (op >= 0x70 && op <= 0x7F)
		imm = 1;
	if (op == 0x6A || op == 0xA8 || op == 0xCD)
		imm = 1;
	if (op == 0xC0 || op == 0xC1) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al + 1;
	}
	if (op >= 0xB0 && op <= 0xB7)
		imm = 1;
	if (op >= 0xB8 && op <= 0xBF)
		imm = rexw ? 8 : 4;
	if (op == 0x68 || op == 0xA9 || op == 0x81)
		imm = 4;
	if (op == 0x69) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al + 4;
	}
	if (op == 0x6B) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al + 1;
	}
	if (op == 0x80) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al + 1;
	}
	if (op == 0x83) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al + 1;
	}
	if (op == 0xC6 || op == 0xC7) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al + (op == 0xC6 ? 1 : 4);
	}
	if (op == 0xF6 || op == 0xF7) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		if (op == 0xF6) {
			if ((p[0] & 0x38) <= 0x08)
				return (int)(p - s) + al + 1;
		} else {
			if ((p[0] & 0x38) <= 0x08)
				return (int)(p - s) + al + 4;
		}
		return (int)(p - s) + al;
	}
	if (op >= 0xA0 && op <= 0xA3)
		imm = 8;
	if (op == 0xE8 || op == 0xE9)
		imm = 4;
	if (op == 0xEB || (op >= 0xE0 && op <= 0xE3))
		imm = 1;
	if (op == 0xC2)
		imm = 2;
	if (op == 0xC8)
		imm = 3;
	if (imm) {
		if (p + imm > end)
			return 0;
		return (int)(p - s) + imm;
	}
	if (op <= 0x3F || (op >= 0x84 && op <= 0x8B) ||
	    (op >= 0x8C && op <= 0x8F) || (op >= 0xD0 && op <= 0xD3) ||
	    (op >= 0xD8 && op <= 0xDF) || op == 0xFE || op == 0xFF) {
		al = addr_len(p, end);
		if (al < 0)
			return 0;
		return (int)(p - s) + al;
	}
	if ((op >= 0x50 && op <= 0x5F) || (op >= 0x90 && op <= 0x9F) ||
	    (op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF) ||
	    op == 0x98 || op == 0x99 || op == 0x9B || op == 0x9C ||
	    op == 0x9D || op == 0x9E || op == 0x9F || op == 0xC3 ||
	    op == 0xC9 || op == 0xCC || op == 0xCE || op == 0xCF ||
	    op == 0xF4 || op == 0xF5 || (op >= 0xF8 && op <= 0xFD) ||
	    op == 0xEC || op == 0xED || op == 0xEE || op == 0xEF ||
	    op == 0xD7 || op == 0xF1)
		return (int)(p - s);
	return 0; /* unknown → bail */
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
