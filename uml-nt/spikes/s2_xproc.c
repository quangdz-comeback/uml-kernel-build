/* S2: cross-process sync protocol PoC (ARCHITECTURE.md 5.3, risk R2).
 * - pagefile section + inherited handles + auto-reset events (event RT)
 * - parent-side spin on shared slot w/ event fallback (event+spin RT)
 * - both-side spin (pure shared-memory RT; child ignores event)
 * - WaitOnAddress: same-process positive control + cross-process attempt
 *   (nt-api-notes: expected NOT to wake — docs say same-process only)
 * - InterlockedIncrement coherence across processes on shared section
 */
#include "spike_common.h"

enum { CMD_ECHO = 1, CMD_COHERENCE = 2, CMD_WAKE = 3, CMD_EXIT = 4 };

typedef struct {
    volatile LONG   cmd;
    volatile LONG   ack;
    volatile LONG   spin_mode;   /* 0: child waits on event; 1: child spins on cmd */
    volatile LONG64 counter;
    volatile LONG64 waitslot;
    volatile LONG64 magic;
    char _pad[4096 - 6 * 8];
} shared_t;

static shared_t *sh;
static HANDLE ev_stub, ev_kern;

/* WaitOnAddress family: Win8+ API-set. Resolved dynamically because the
 * import library differs per toolchain (Debian cross-mingw: only in
 * libsynchronization.a; MSYS2 mingw64: not linked from kernel32 stub).
 * NULL => API unavailable; results are then reported as such. */
static BOOL (WINAPI *pWaitOnAddress)(PVOID, PVOID, SIZE_T, DWORD);
static VOID (WINAPI *pWakeByAddressSingle)(PVOID);

static void resolve_woa(void) {
    HMODULE h = GetModuleHandleA("api-ms-win-core-synch-l1-2-0.dll");
    if (!h) h = GetModuleHandleA("kernel32.dll");
    if (!h) return;
    pWaitOnAddress       = (BOOL (WINAPI *)(PVOID, PVOID, SIZE_T, DWORD))(void *)GetProcAddress(h, "WaitOnAddress");
    pWakeByAddressSingle = (VOID (WINAPI *)(PVOID))(void *)GetProcAddress(h, "WakeByAddressSingle");
}

static void child_loop(void) {
    LONG last = 0;
    for (;;) {
        if (!sh->spin_mode) {
            if (WaitForSingleObject(ev_stub, 15000) != WAIT_OBJECT_0) return;
        }
        LONG c = sh->cmd;
        if (c == last) {                       /* duplicate observation:
                                                   spin mode must dedupe too,
                                                   else a command is executed
                                                   several times (coherence
                                                   failed on real Windows) */
            if (sh->spin_mode) YieldProcessor();
            continue;
        }
        last = c;
        if (c == CMD_EXIT) { InterlockedExchange(&sh->ack, c); return; }
        switch (c) {
        case CMD_COHERENCE: for (int k = 0; k < 500000; k++) InterlockedIncrement64(&sh->counter); break;
        case CMD_WAKE:      if (pWakeByAddressSingle) pWakeByAddressSingle((PVOID)&sh->waitslot); break;
        default:            break; /* CMD_ECHO + synthetic echo cmds (>=1000) */
        }
        InterlockedExchange(&sh->ack, c);
        if (!sh->spin_mode) SetEvent(ev_kern);
    }
}

static void op_event(LONG c) {
    InterlockedExchange(&sh->cmd, c);
    SetEvent(ev_stub);
    if (WaitForSingleObject(ev_kern, 10000) != WAIT_OBJECT_0)
        fprintf(stderr, "[s2] WARN: event RT timeout on cmd=%ld\n", (long)c);
}

static void op_spin(LONG c) {
    InterlockedExchange(&sh->cmd, c);
    long spins = 0;
    while (sh->ack != c) {
        if (++spins > (1L << 24)) { op_event(c); return; } /* fallback */
        YieldProcessor();
    }
}

typedef struct { volatile LONG64 *addr; int result; } waiter_arg_t;
/* result: 0 = API unavailable, 1 = wait returned w/o wake (timeout/fail), 2 = woke */

static DWORD WINAPI waiter_thread(LPVOID p) {
    waiter_arg_t *a = (waiter_arg_t *)p;
    LONG64 expect = 1;
    if (!pWaitOnAddress) { a->result = 0; return 0; }
    a->result = pWaitOnAddress((PVOID)a->addr, &expect, sizeof(LONG64), 700) ? 2 : 1;
    return 0;
}

int main(int argc, char **argv) {
    FILE *f = fopen("results/s2_xproc.json", "w");
    if (!f) { perror("results/"); return 1; }
    sc_init();
    resolve_woa();

    if (argc >= 5 && !strcmp(argv[1], "--stub")) {
        HANDLE sec = (HANDLE)(uintptr_t)strtoull(argv[2], NULL, 10);
        ev_stub    = (HANDLE)(uintptr_t)strtoull(argv[3], NULL, 10);
        ev_kern    = (HANDLE)(uintptr_t)strtoull(argv[4], NULL, 10);
        sh = (shared_t *)MapViewOfFile(sec, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!sh) return 2;
        InterlockedExchange64(&sh->magic, 0xC0FFEEC0DELL);  /* prove sharing */
        child_loop();
        return 0;
    }

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE sec = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 65536, NULL);
    sh = (shared_t *)MapViewOfFile(sec, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    ev_stub = CreateEventA(&sa, FALSE, FALSE, NULL);
    ev_kern = CreateEventA(&sa, FALSE, FALSE, NULL);
    if (!sec || !sh || !ev_stub || !ev_kern) { fprintf(f, "{\"ok\": false}\n"); return 1; }

    char cmd[MAX_PATH * 2], exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    snprintf(cmd, sizeof(cmd), "\"%s\" --stub %llu %llu %llu", exe,
             (unsigned long long)(uintptr_t)sec,
             (unsigned long long)(uintptr_t)ev_stub,
             (unsigned long long)(uintptr_t)ev_kern);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(f, "{\"ok\": false, \"error\": \"CreateProcess %lu\"}\n", GetLastError());
        return 1;
    }

    /* wait for child to map + write magic (poll, then event sync) */
    for (int i = 0; i < 100 && sh->magic != 0xC0FFEEC0DELL; i++) Sleep(10);
    int magic_ok = (sh->magic == 0xC0FFEEC0DELL);
    op_event(CMD_ECHO); /* full sync */

    const int N_EV = 100000, N_SPIN1 = 100000, N_SPIN2 = 50000;
    double *s1s = malloc(N_EV * sizeof(double));
    double *s2s = malloc(N_SPIN1 * sizeof(double));
    double *s3s = malloc(N_SPIN2 * sizeof(double));

    sh->spin_mode = 0;
    for (int i = 0; i < N_EV; i++) {
        int64_t t0 = sc_now(); op_event(1000 + i); s1s[i] = sc_ns(sc_now() - t0);
    }
    sh->spin_mode = 1;
    for (int i = 0; i < N_SPIN1; i++) {
        int64_t t0 = sc_now(); op_spin(100000 + i); s2s[i] = sc_ns(sc_now() - t0);
    }
    for (int i = 0; i < N_SPIN2; i++) {
        int64_t t0 = sc_now(); op_spin(200000 + i); s3s[i] = sc_ns(sc_now() - t0);
    }
    sh->spin_mode = 0;

    /* WaitOnAddress: positive control (same-process) */
    LONG64 local = 1;
    waiter_arg_t wa = { &local, 0 };
    HANDLE ht = CreateThread(NULL, 0, waiter_thread, &wa, 0, NULL);
    Sleep(50);
    if (pWakeByAddressSingle) pWakeByAddressSingle((PVOID)&local);
    WaitForSingleObject(ht, 2000); CloseHandle(ht);
    int inproc_woke = (wa.result == 2);

    /* WaitOnAddress: cross-process attempt (child wakes its own VA of the slot) */
    waiter_arg_t wb = { &sh->waitslot, 0 };
    sh->waitslot = 1;
    ht = CreateThread(NULL, 0, waiter_thread, &wb, 0, NULL);
    Sleep(100);
    op_event(CMD_WAKE);
    WaitForSingleObject(ht, 3000); CloseHandle(ht);
    int cross_woke = (wb.result == 2);

    /* Interlocked coherence: parent 500k, child 500k */
    op_event(CMD_COHERENCE);
    for (int k = 0; k < 500000; k++) InterlockedIncrement64(&sh->counter);
    int coherence_ok = (sh->counter == 1000000);

    op_event(CMD_EXIT);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    fprintf(stderr, "[s2] magic=%d coherence=%d waitOnAddr api=%d inproc=%d cross=%d\n",
            magic_ok, coherence_ok, !!pWaitOnAddress, inproc_woke, cross_woke);
    fprintf(f, "{\"ok\": true, \"magic_ok\": %s, \"interlocked_coherence\": %s, "
               "\"waitonaddress_available\": %s, "
               "\"waitonaddress_inproc_wake\": %s, \"waitonaddress_crossproc_wake\": %s, ",
            magic_ok ? "true" : "false", coherence_ok ? "true" : "false",
            pWaitOnAddress ? "true" : "false",
            inproc_woke ? "true" : "false", cross_woke ? "true" : "false");
    sc_stats(f, "rt_event", s1s, N_EV);          fprintf(f, ", ");
    sc_stats(f, "rt_parent_spin", s2s, N_SPIN1); fprintf(f, ", ");
    sc_stats(f, "rt_both_spin", s3s, N_SPIN2);
    fprintf(f, "}\n");
    fclose(f);
    free(s1s); free(s2s); free(s3s);
    return 0;
}
