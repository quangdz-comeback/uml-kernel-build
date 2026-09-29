/* S3: ELF ET_EXEC launcher PoC — validates the S3+S4 pair (ARCHITECTURE.md 2/D2):
 * map a freestanding Linux ELF (built by clang+lld on Windows) into this PE
 * process at its fixed vaddrs, call its entry, verify it wrote a magic into a
 * shared window mapped at a fixed VA (the kernel↔host memory contract).
 */
#include "spike_common.h"

#define WIN_ADDR  ((LPVOID)(uintptr_t)0x50000000ULL)
#define EXPECTED  0xC0FFEE42u

typedef struct { uint8_t  e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags; uint16_t e_ehsize, e_phentsize,
    e_phnum, e_shentsize, e_shnum, e_shstrndx; } elf64_ehdr;
typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr, p_paddr,
    p_filesz, p_memsz, p_align; } elf64_phdr;

int main(int argc, char **argv) {
    FILE *f = fopen("results/s3_launcher.json", "w");
    if (!f) { perror("results/"); return 1; }
    sc_init();
    if (argc < 2) { fprintf(f, "{\"ok\": false, \"error\": \"usage: s3_launcher payload.elf\"}\n"); return 1; }

    FILE *ef = fopen(argv[1], "rb");
    if (!ef) { fprintf(f, "{\"ok\": false, \"error\": \"open payload\"}\n"); return 1; }
    elf64_ehdr eh;
    if (fread(&eh, sizeof(eh), 1, ef) != 1 || memcmp(eh.e_ident, "\x7f""ELF", 4) != 0
        || eh.e_ident[4] != 2 /* 64-bit */ || eh.e_type != 2 /* ET_EXEC */) {
        fprintf(f, "{\"ok\": false, \"error\": \"not a static ELF64 ET_EXEC\"}\n");
        return 1;
    }

    HANDLE sec = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    void *win = MapViewOfFileEx(sec, FILE_MAP_ALL_ACCESS, 0, 0, 0, WIN_ADDR);
    if (!win) { fprintf(f, "{\"ok\": false, \"error\": \"fixed VA window busy\"}\n"); return 1; }

    elf64_phdr *ph = calloc(eh.e_phnum, eh.e_phentsize);
    fseek(ef, (long)eh.e_phoff, SEEK_SET);
    if (fread(ph, eh.e_phentsize, eh.e_phnum, ef) != eh.e_phnum) { fprintf(f, "{\"ok\": false}\n"); return 1; }

    int segs = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        elf64_phdr *p = (elf64_phdr *)((char *)ph + (size_t)i * eh.e_phentsize);
        if (p->p_type != 1 /* PT_LOAD */ || p->p_memsz == 0) continue;
        LPVOID base = VirtualAlloc((LPVOID)(uintptr_t)p->p_vaddr, p->p_memsz,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if ((uintptr_t)base != p->p_vaddr) {
            fprintf(f, "{\"ok\": false, \"error\": \"VirtualAlloc at fixed VA %llu\", \"gle\": %lu}\n",
                    (unsigned long long)p->p_vaddr, GetLastError());
            return 1;
        }
        fseek(ef, (long)p->p_offset, SEEK_SET);
        if (p->p_filesz && fread((void *)(uintptr_t)p->p_vaddr, 1, p->p_filesz, ef) != p->p_filesz) {
            fprintf(f, "{\"ok\": false, \"error\": \"short read\"}\n"); return 1;
        }
        DWORD prot = (p->p_flags & 1) ? PAGE_EXECUTE_READ : PAGE_READONLY;
        if (p->p_flags & 2) prot = (p->p_flags & 1) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        DWORD old;
        VirtualProtect((LPVOID)(uintptr_t)p->p_vaddr, p->p_memsz, prot, &old);
        segs++;
    }
    fclose(ef);

    fprintf(stderr, "[s3] mapped %d PT_LOAD segs, entry=0x%llx, calling...\n",
            segs, (unsigned long long)eh.e_entry);
    ((void (*)(void))(uintptr_t)eh.e_entry)();

    uint32_t got = *(volatile uint32_t *)WIN_ADDR;
    int ok = (got == EXPECTED);
    fprintf(stderr, "[s3] payload magic=0x%08x expected=0x%08x → %s\n", got, EXPECTED, ok ? "PASS" : "FAIL");
    fprintf(f, "{\"ok\": %s, \"segments\": %d, \"entry\": %llu, \"magic\": %u}\n",
            ok ? "true" : "false", segs, (unsigned long long)eh.e_entry, got);
    fclose(f);
    return ok ? 0 : 1;
}
