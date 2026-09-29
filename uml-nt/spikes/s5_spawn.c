/* S5: CreateProcess latency + DiscardVirtualMemory + fixed-base section map
 * (ARCHITECTURE.md 4/5.3, risks R4; nt-api-notes 3.4/5.1/5.2).
 */
#include "spike_common.h"

#define FIXED_BASE ((LPVOID)(uintptr_t)0x0000020000000000ULL)
#define CHILD_MAGIC 0x5B5B1234LL

int main(int argc, char **argv) {
    FILE *f = fopen("results/s5_spawn.json", "w");
    if (!f) { perror("results/"); return 1; }
    sc_init();

    if (argc >= 2 && !strcmp(argv[1], "--noop")) return 0;
    if (argc >= 3 && !strcmp(argv[1], "--mapfix")) {
        HANDLE sec = (HANDLE)(uintptr_t)strtoull(argv[2], NULL, 10);
        void *p = MapViewOfFileEx(sec, FILE_MAP_ALL_ACCESS, 0, 0, 0, FIXED_BASE);
        if (!p) return 3;                    /* base busy → signal failure */
        InterlockedExchange64((volatile LONG64 *)p, CHILD_MAGIC);
        return 0;
    }

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    char exe[MAX_PATH], cmd[MAX_PATH * 2];
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);

    /* --- spawn bench: suspended then killed (stub-pool model) --- */
    const int NS = 120, NF = 40;
    double *ss = malloc(NS * sizeof(double)), *ff = malloc(NF * sizeof(double));
    for (int i = 0; i < NS; i++) {
        snprintf(cmd, sizeof(cmd), "\"%s\" --noop", exe);
        int64_t t0 = sc_now();
        BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED,
                                 NULL, NULL, &si, &pi);
        int64_t t1 = sc_now();
        if (ok) { TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
                  CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
        ss[i] = ok ? sc_ns(t1 - t0) / 1e6 : -1.0;
    }
    /* --- spawn bench: run-to-exit (fork model) --- */
    for (int i = 0; i < NF; i++) {
        snprintf(cmd, sizeof(cmd), "\"%s\" --noop", exe);
        int64_t t0 = sc_now();
        BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if (ok) { WaitForSingleObject(pi.hProcess, 10000);
                  CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
        int64_t t1 = sc_now();
        ff[i] = ok ? sc_ns(t1 - t0) / 1e6 : -1.0;
    }

    /* --- DiscardVirtualMemory: private alloc + pagefile-section view --- */
    DWORD derr1 = 0, derr2 = 0;
    int disc_priv = 0, disc_view = 0;
    BYTE *big = VirtualAlloc(NULL, 16 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (big) {
        memset(big, 0xAA, 16 << 20);
        if (!DiscardVirtualMemory(big, 16 << 20)) derr1 = GetLastError();
        else { disc_priv = (big[0] == 0xAA || big[0] != 0xAA); /* still usable */ memset(big, 0x55, 16); }
        VirtualFree(big, 0, MEM_RELEASE);
    }
    HANDLE sec2 = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 8 << 20, NULL);
    if (sec2) {
        BYTE *v = MapViewOfFile(sec2, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (v) {
            memset(v, 0xBB, 8 << 20);
            if (!DiscardVirtualMemory(v, 8 << 20)) derr2 = GetLastError();
            else disc_view = 1;
            UnmapViewOfFile(v);
        }
        CloseHandle(sec2);
    }

    /* --- fixed-base map in a second process (stub bootstrap pattern) --- */
    HANDLE sec3 = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 4096, NULL);
    snprintf(cmd, sizeof(cmd), "\"%s\" --mapfix %llu", exe,
             (unsigned long long)(uintptr_t)sec3);
    int child_mapfix_ok = 0, parent_sees_magic = 0;
    if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD xc = 999; GetExitCodeProcess(pi.hProcess, &xc);
        child_mapfix_ok = (xc == 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        void *p = MapViewOfFileEx(sec3, FILE_MAP_ALL_ACCESS, 0, 0, 0, FIXED_BASE);
        if (p) parent_sees_magic = (*(volatile LONG64 *)p == CHILD_MAGIC);
    }

    fprintf(stderr, "[s5] done. spawn_susp p50=%.1fms full=%.1fms disc(priv=%d view=%d e1=%lu e2=%lu) mapfix=%d/%d\n",
            ss[NS / 2], ff[NF / 2], disc_priv, disc_view,
            (unsigned long)derr1, (unsigned long)derr2, child_mapfix_ok, parent_sees_magic);
    fprintf(f, "{\"ok\": true, \"discard_private_ok\": %s, \"discard_view_ok\": %s, "
               "\"discard_err_priv\": %lu, \"discard_err_view\": %lu, "
               "\"child_mapfix_ok\": %s, \"parent_sees_magic\": %s, ",
            disc_priv ? "true" : "false", disc_view ? "true" : "false",
            (unsigned long)derr1, (unsigned long)derr2,
            child_mapfix_ok ? "true" : "false", parent_sees_magic ? "true" : "false");
    sc_stats(f, "createprocess_suspended_ms", ss, NS); fprintf(f, ", ");
    sc_stats(f, "createprocess_full_ms", ff, NF);
    fprintf(f, "}\n");
    fclose(f);
    free(ss); free(ff);
    return 0;
}
