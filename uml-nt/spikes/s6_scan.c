/* S6: syscall-instruction scanner PoC (ARCHITECTURE.md 5.1, risk R3).
 * Question: how many false positives would naive `0F 05` patching cause in
 * real binaries, and how much does a linear-sweep mini-decoder reduce it?
 * Ground truth (ELF + objdump available): objdump -d syscall addresses.
 * Portable C — runs on Linux and Windows alike.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#define popen  _popen
#define pclose _pclose
#endif

typedef struct { uint8_t  e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags; uint16_t e_ehsize, e_phentsize,
    e_phnum, e_shentsize, e_shnum, e_shstrndx; } ehdr_t;
typedef struct { uint32_t sh_name, sh_type; uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info; uint64_t sh_addralign, sh_entsize; } shdr_t;

/* --- tiny hash set of addresses --- */
#define HS_CAP (1u << 21)
static uint64_t *hs;
static void hs_init(void) { hs = calloc(HS_CAP, 8); }
static void hs_add(uint64_t v) {
    uint64_t h = (v * 0x9E3779B97F4A7C15ULL) & (HS_CAP - 1);
    while (hs[h]) { if (hs[h] == v) return; h = (h + 1) & (HS_CAP - 1); }
    hs[h] = v; /* 0 reserved as sentinel */
}
static int hs_has(uint64_t v) {
    if (!v) return 0;
    uint64_t h = (v * 0x9E3779B97F4A7C15ULL) & (HS_CAP - 1);
    while (hs[h]) { if (hs[h] == v) return 1; h = (h + 1) & (HS_CAP - 1); }
    return 0;
}

/* --- x86-64 length decoder (subset; 0 = bail) --- */
static int addr_len(const uint8_t *p, const uint8_t *end) {
    if (p >= end) return -1;
    uint8_t m = *p++, mod = m >> 6, rm = m & 7;
    if (mod == 3) return 1;
    int n = 1;
    if (rm == 4) {
        if (p >= end) return -1;
        uint8_t s = *p++; n++;
        if ((s & 7) == 5 && mod == 0) n += 4;
    } else if (mod == 0 && rm == 5) n += 4;
    if (mod == 1) n += 1; else if (mod == 2) n += 4;
    return n;
}

static int insn_len(const uint8_t *p, const uint8_t *end) {
    const uint8_t *s = p;
    int rexw = 0;
    for (;;) {
        if (p >= end) return 0;
        uint8_t b = *p;
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0x2E ||
            b == 0x3E || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65 || b == 0xF0) { p++; continue; }
        if (b >= 0x40 && b <= 0x4F) { rexw = (b & 8) != 0; p++; continue; }
        break;
    }
    if (p >= end) return 0;
    uint8_t op = *p++;
    int al, imm = 0;
    if (op == 0x0F) {
        if (p >= end) return 0;
        uint8_t o2 = *p++;
        if (o2 == 0x05 || o2 == 0x0B || o2 == 0x34 || o2 == 0x35 || o2 == 0x31 ||
            o2 == 0xA2 || (o2 >= 0xC8 && o2 <= 0xCF)) return (int)(p - s);
        if (o2 == 0x38 || o2 == 0x3A) return 0;
        if (o2 >= 0x80 && o2 <= 0x8F) { if (p + 4 > end) return 0; return (int)(p - s) + 4; }
        if (o2 == 0x70 || o2 == 0x71 || o2 == 0x72 || o2 == 0x73 || o2 == 0xC6) {
            al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al + 1;
        }
        if ((o2 >= 0x40 && o2 <= 0x4F) || (o2 >= 0x90 && o2 <= 0x9F) || o2 == 0x1F ||
            (o2 >= 0x10 && o2 <= 0x17) || (o2 >= 0x28 && o2 <= 0x2F) ||
            (o2 >= 0x51 && o2 <= 0x5F) || (o2 >= 0x60 && o2 <= 0x6F) ||
            o2 == 0x7E || o2 == 0x7F || (o2 >= 0xA3 && o2 <= 0xA7) ||
            (o2 >= 0xAB && o2 <= 0xAF) || (o2 >= 0xB0 && o2 <= 0xB7) ||
            (o2 >= 0xBC && o2 <= 0xBF) || (o2 >= 0xD0 && o2 <= 0xFE) ||
            o2 == 0x18 || o2 == 0x1E || o2 == 0xA2 || o2 == 0xA8) {
            al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al;
        }
        return 0;
    }
    if (op < 0x40 && (op & 7) == 4) imm = 1;
    if (op < 0x40 && (op & 7) == 5) imm = 4;
    if (op >= 0x70 && op <= 0x7F) imm = 1;
    if (op == 0x6A || op == 0xA8 || op == 0xCD) imm = 1;
    if (op == 0xC0 || op == 0xC1) {
        al = addr_len(p, end); if (al < 0) return 0;
        return (int)(p - s) + al + 1;
    }
    if (op == 0xB0 || (op >= 0xB0 && op <= 0xB7)) imm = 1;
    if (op >= 0xB8 && op <= 0xBF) imm = rexw ? 8 : 4;
    if (op == 0x68 || op == 0xA9 || op == 0x81) imm = 4;
    if (op == 0x69) { al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al + 4; }
    if (op == 0x6B) { al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al + 1; }
    if (op == 0x80) { al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al + 1; }
    if (op == 0x83) { al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al + 1; }
    if (op == 0xC6 || op == 0xC7) {
        al = addr_len(p, end); if (al < 0) return 0;
        return (int)(p - s) + al + (op == 0xC6 ? 1 : 4);
    }
    if (op == 0xF6 || op == 0xF7) {
        al = addr_len(p, end); if (al < 0) return 0;
        if (op == 0xF6) { if ((p[0] & 0x38) <= 0x08) return (int)(p - s) + al + 1; }
        else            { if ((p[0] & 0x38) <= 0x08) return (int)(p - s) + al + 4; }
        return (int)(p - s) + al;
    }
    if (op >= 0xA0 && op <= 0xA3) imm = 8;
    if (op == 0xE8 || op == 0xE9) imm = 4;
    if (op == 0xEB || (op >= 0xE0 && op <= 0xE3)) imm = 1;
    if (op == 0xC2) imm = 2;
    if (op == 0xC8) imm = 3;
    if (imm) { if (p + imm > end) return 0; return (int)(p - s) + imm; }
    if (op <= 0x3F || (op >= 0x84 && op <= 0x8B) ||
        (op >= 0x8C && op <= 0x8F) || (op >= 0xD0 && op <= 0xD3) ||
        (op >= 0xD8 && op <= 0xDF) || op == 0xFE || op == 0xFF) {
        al = addr_len(p, end); if (al < 0) return 0; return (int)(p - s) + al;
    }
    if ((op >= 0x50 && op <= 0x5F) || (op >= 0x90 && op <= 0x9F) ||
        (op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF) ||
        op == 0x98 || op == 0x99 || op == 0x9B || op == 0x9C || op == 0x9D ||
        op == 0x9E || op == 0x9F || op == 0xC3 || op == 0xC9 || op == 0xCC ||
        op == 0xCE || op == 0xCF || op == 0xF4 || op == 0xF5 ||
        (op >= 0xF8 && op <= 0xFD) || op == 0xEC || op == 0xED ||
        op == 0xEE || op == 0xEF || op == 0xD7 || op == 0xF1) return (int)(p - s);
    return 0; /* unknown → bail */
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: s6_scan <elf> [elf...]\n"); return 1; }
    hs_init();
    for (int fi = 1; fi < argc; fi++) {
        FILE *f = fopen(argv[fi], "rb");
        if (!f) { fprintf(stderr, "[s6] cannot open %s\n", argv[fi]); continue; }
        ehdr_t eh;
        if (fread(&eh, sizeof(eh), 1, f) != 1 || memcmp(eh.e_ident, "\x7f""ELF", 4)) {
            fprintf(stderr, "[s6] %s: not ELF\n", argv[fi]); fclose(f); continue;
        }
        shdr_t *sh = calloc(eh.e_shnum, eh.e_shentsize);
        fseek(f, (long)eh.e_shoff, SEEK_SET);
        fread(sh, eh.e_shentsize, eh.e_shnum, f);
        uint8_t *strs = NULL;
        if (eh.e_shstrndx < eh.e_shnum) {
            strs = malloc(sh[eh.e_shstrndx].sh_size + 1);
            fseek(f, (long)sh[eh.e_shstrndx].sh_offset, SEEK_SET);
            fread(strs, 1, sh[eh.e_shstrndx].sh_size, f);
        }
        long naive = 0, decoded = 0, gt_here = 0, fp_naive = 0, fn_naive = 0, fp_dec = 0, fn_dec = 0;
        int have_gt = 0;
        for (int i = 0; i < eh.e_shnum; i++) {
            if (!(sh[i].sh_flags & 0x4 /* EXECINSTR */) || sh[i].sh_size == 0) continue;
            uint8_t *buf = malloc(sh[i].sh_size);
            fseek(f, (long)sh[i].sh_offset, SEEK_SET);
            if (fread(buf, 1, sh[i].sh_size, f) != sh[i].sh_size) { free(buf); continue; }
            const uint8_t *end = buf + sh[i].sh_size;
            for (long o = 0; o + 2 <= (long)sh[i].sh_size; o++)
                if (buf[o] == 0x0F && buf[o + 1] == 0x05) {
                    naive++;
                    uint64_t va = sh[i].sh_addr + o;
                    if (have_gt && !hs_has(va)) fp_naive++;
                    if (have_gt && hs_has(va)) gt_here++;
                }
            /* linear sweep from section start (+ entry if inside), deduped */
            uint8_t *mark = calloc(sh[i].sh_size, 1);
            for (int pass = 0; pass < 2; pass++) {
                long o = 0;
                if (pass == 1) {
                    if (eh.e_entry < sh[i].sh_addr || eh.e_entry >= sh[i].sh_addr + sh[i].sh_size) continue;
                    o = (long)(eh.e_entry - sh[i].sh_addr);
                }
                while (o + 2 <= (long)sh[i].sh_size) {
                    int L = insn_len(buf + o, end);
                    if (L <= 0 || o + L > (long)sh[i].sh_size) { o++; continue; }
                    mark[o] = 1;
                    o += L;
                }
            }
            for (long o = 0; o + 2 <= (long)sh[i].sh_size; o++)
                if (mark[o] && buf[o] == 0x0F && buf[o + 1] == 0x05) {
                    decoded++;
                    uint64_t va = sh[i].sh_addr + o;
                    if (have_gt) { if (!hs_has(va)) fp_dec++; } 
                }
            if (have_gt) {
                for (int k = 0; k < (int)sh[i].sh_size; k++)
                    if (buf[k] == 0x0F && buf[k+1] == 0x05 && !mark[k] && hs_has(sh[i].sh_addr + k)) fn_dec++;
            }
            free(mark); free(buf);
        }
        /* ground truth via objdump */
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "objdump -d --no-show-raw-insn \"%s\" 2>/dev/null", argv[fi]);
        FILE *od = popen(cmd, "r");
        long gt_count = -1;
        if (od) {
            char line[512]; gt_count = 0; have_gt = 1;
            /* first pass: collect addresses */
            while (fgets(line, sizeof(line), od)) {
                char *colon = strchr(line, ':');
                if (!colon || colon == line) continue;
                uint64_t va = strtoull(line, NULL, 16);
                if (strstr(colon, "\tsyscall") || strstr(colon, " syscall")) { hs_add(va); gt_count++; }
            }
            pclose(od);
            /* recompute FP/FN with complete set */
            for (int i = 0; i < eh.e_shnum; i++) {
                if (!(sh[i].sh_flags & 0x4) || sh[i].sh_size == 0) continue;
                uint8_t *buf = malloc(sh[i].sh_size);
                fseek(f, (long)sh[i].sh_offset, SEEK_SET);
                if (fread(buf, 1, sh[i].sh_size, f) != sh[i].sh_size) { free(buf); continue; }
                for (long o = 0; o + 2 <= (long)sh[i].sh_size; o++)
                    if (buf[o] == 0x0F && buf[o + 1] == 0x05) {
                        uint64_t va = sh[i].sh_addr + o;
                        if (!hs_has(va)) fp_naive++; else gt_here++;
                    }
                free(buf);
            }
            fn_naive = gt_count - gt_here;
        }
        printf("{\"file\": \"%s\", \"naive_0f05\": %ld, \"decoded_syscalls\": %ld, "
               "\"objdump_syscalls\": %ld, \"naive_false_positives\": %ld, "
               "\"naive_missed\": %ld, \"decoder_false_positives\": %ld, \"decoder_missed\": %ld}\n",
               argv[fi], naive, decoded, gt_count, have_gt ? fp_naive : -1,
               have_gt ? fn_naive : -1, have_gt ? fp_dec : -1, have_gt ? fn_dec : -1);
        fprintf(stderr, "[s6] %s: naive=%ld decoded=%ld gt=%ld fp_naive=%ld fn_naive=%ld fp_dec=%ld\n",
                argv[fi], naive, decoded, gt_count, fp_naive, fn_naive, fp_dec);
        free(sh); free(strs); fclose(f);
    }
    return 0;
}
