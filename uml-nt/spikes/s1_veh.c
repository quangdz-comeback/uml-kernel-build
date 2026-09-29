/* S1: VEH trap/resume PoC (ARCHITECTURE.md 5.2, risk R1).
 * A. EXCEPTION_CONTINUE_EXECUTION honors modified CONTEXT (Rax visible, RIP+2 skips ud2)
 * B. RIP redirect to an arbitrary function works
 * C. page-fault address via ExceptionInformation[1] + read/write flag
 * D. callee-saved reg (r12) survives kernel exception round-trip
 * E. ns per ud2 trap and per page fault (sampled percentiles + batch avg)
 */
#include "spike_common.h"

static volatile LONG     g_traps;
static volatile int      g_do_redirect;
static volatile int      g_redirect_done;
static volatile int      g_pf_ok;
static volatile uint64_t g_pf_addr, g_pf_rw;
static volatile uint64_t g_r12_after, g_rax_after;

static void after_redirect(void) { g_redirect_done = 1; }

/* Resume point inside fault_site's own frame — landing on a label keeps
 * RSP/frame valid (a bare-ret target gets inlined into main and unwinds it).
 * The opaque condition stops GCC from proving the store always faults and
 * dead-coding the label into a re-executing loop. */
static void *g_fault_resume;
static volatile int g_do_fault = 1;
static volatile int g_fault_landed;

static __attribute__((noinline)) void fault_site(void) {
    g_fault_resume = &&fault_return;
    if (g_do_fault)
        *(volatile int *)0 = 1;
    else
        g_fault_landed = 2;             /* never taken; keeps fallthrough live */
fault_return:
    g_fault_landed = 1;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    PEXCEPTION_RECORD er = ep->ExceptionRecord;
    PCONTEXT c = ep->ContextRecord;
    if (er->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
        InterlockedIncrement(&g_traps);
        c->Rax = 0x4142434445464748ULL;              /* prove reg writes stick */
        if (g_do_redirect) {
            /* Redirect like a CALL: push the resume point (RIP+2) so the
             * target can return normally — jumping bare would make its RET
             * pop garbage and land in an unmapped/exec-fault loop. */
            g_do_redirect = 0;
            c->Rsp -= 8;
            *(uint64_t *)(c->Rsp) = c->Rip + 2;
            c->Rip = (DWORD64)(uintptr_t)after_redirect;
        } else {
            c->Rip += 2;                              /* skip ud2 */
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (er->ExceptionCode == STATUS_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        g_pf_addr = er->ExceptionInformation[1];     /* faulting VA (CR2 analog) */
        g_pf_rw   = er->ExceptionInformation[0];     /* 0=read 1=write 8=DEP */
        if (g_pf_addr == 0) {
            g_pf_ok = 1;
            c->Rip = (DWORD64)(uintptr_t)g_fault_resume;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        /* unexpected fault: pass it on instead of re-faulting forever */
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void regtest(void) {
    __asm__ volatile(
        "movabs $0x1122334455667788, %%r12 \n\t"
        "ud2 \n\t"
        "movq %%r12, %0 \n\t"
        "movq %%rax, %1 \n\t"
        : "=m"(g_r12_after), "=m"(g_rax_after)
        :
        : "r12", "rax");
}

int main(void) {
    FILE *f = fopen("results/s1_veh.json", "w");
    if (!f) { perror("results/"); return 1; }
    sc_init();
    fprintf(stderr, "[s1] VEH trap/resume PoC\n");
    AddVectoredExceptionHandler(1, veh);

    int a_ctx = 0, a_redirect = 0, a_regs = 0;
    int r;
    __asm__ volatile("movl $7, %%eax \n\t ud2 \n\t movl %%eax, %0" : "=r"(r) :: "eax");
    a_ctx = (r == 0x45464748);

    g_do_redirect = 1;
    __asm__ volatile("ud2");
    a_redirect = g_redirect_done;

    regtest();
    a_regs = (g_r12_after == 0x1122334455667788ULL) &&
             (g_rax_after == 0x4142434445464748ULL);

    fault_site();
    int a_pf = g_pf_ok && g_pf_addr == 0 && g_pf_rw == 1 && g_fault_landed == 1;

    const int S = 100000, B = 2000000, PFS = 20000;
    double *smp = malloc(S * sizeof(double));
    for (int i = 0; i < S; i++) {
        int64_t t0 = sc_now(); __asm__ volatile("ud2"); smp[i] = sc_ns(sc_now() - t0);
    }
    int64_t b0 = sc_now();
    for (volatile int i = 0; i < B; i++) { __asm__ volatile("ud2"); }
    double batch_avg = sc_ns(sc_now() - b0) / B;

    double *pf = malloc(PFS * sizeof(double));
    for (int i = 0; i < PFS; i++) {
        int64_t t0 = sc_now(); fault_site(); pf[i] = sc_ns(sc_now() - t0);
    }

    RemoveVectoredExceptionHandler(veh);
    fprintf(stderr, "[s1] ctx_mod=%d rip_redirect=%d regs=%d pf_addr_rw=%d ud2_batch_avg=%.0f ns\n",
            a_ctx, a_redirect, a_regs, a_pf, batch_avg);
    fprintf(f, "{\"ok\": true, \"context_mod_sticks\": %s, \"rip_redirect\": %s, "
               "\"callee_saved_survive\": %s, \"pf_addr_and_rw\": %s, "
               "\"ud2_batch_avg_ns\": %.0f, ",
            a_ctx ? "true" : "false", a_redirect ? "true" : "false",
            a_regs ? "true" : "false", a_pf ? "true" : "false", batch_avg);
    sc_stats(f, "ud2_sampled", smp, S);
    fprintf(f, ", ");
    sc_stats(f, "pagefault_sampled", pf, PFS);
    fprintf(f, "}\n");
    fclose(f);
    free(smp); free(pf);
    return 0;
}
