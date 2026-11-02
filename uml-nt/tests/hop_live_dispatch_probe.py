"""S13 A2 probe: run the REAL raw handler + dispatch with production headers.

Adapted from Astra's skeleton (s13-review305-dispatch-probe.py): the raw
handler, the dispatch wrapper, the begin/finalize/decision helpers and the
SS_STRAY branch are extracted VERBATIM, and <hop_live.h> / <veh_model.h> are
the production headers. The Windows API and the stack switch are faked, and a
controlled body supplies final contexts and outcomes.

Scenarios:
  SYS / FAULT      — armed once, current entry, post-body sequences, the
                     returned LONG and the CONTEXT preserved, reader reports a
                     committed comparable sample after the terminal stores.
  SS_STRAY / TF /  — a genuinely committed PREVIOUS record must not be
  direct / SEARCH    promoted by a newer unsampled return.
  in_veh / refused — the paths that never reach the diagnostic wrapper.
  mid-body read    — reading before final preparation must not show the old
                     record as current.

Usage: python3 hop_live_dispatch_probe.py <stub.c> <include-dir> <tmpdir> <cc>
"""
from pathlib import Path
import re
import subprocess
import sys

source = Path(sys.argv[1])
inc = sys.argv[2]
out = Path(sys.argv[3])
cc = sys.argv[4]
src = source.read_text()


def extract(pattern):
    matches = re.findall(pattern, src, re.S)
    if len(matches) != 1:
        raise SystemExit("expected one source match for %r, got %d"
                         % (pattern, len(matches)))
    return matches[0]


helpers = extract(r"(static int hop_live_arm_kind\(.*?\n\})\n")
helpers += "\n" + extract(r"(static void hop_live_begin_attempt\(void\)\n\{.*?\n\})\n")
helpers += "\n" + extract(
    r"(static void hop_live_finalize\(EXCEPTION_POINTERS \*ep, LONG result\)\n\{.*?\n\})\n")
dispatch = extract(
    r"(static LONG CALLBACK veh_dispatch\(EXCEPTION_POINTERS \*ep\)\n\{.*?\n\})\n")
handler = extract(
    r"(static LONG CALLBACK veh_handler\(EXCEPTION_POINTERS \*ep\)\n\{.*?\n\})\n")
stray = extract(r"(if \(!is_step && cls == UML_NT_SS_STRAY\) \{.*?\n\t\t\})")

prefix = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <hop_live.h>
#include <veh_model.h>
#define CALLBACK
#define EXCEPTION_CONTINUE_EXECUTION (-1L)
#define EXCEPTION_CONTINUE_SEARCH 0L
#define UML_NT_SS_STRAY 11
#define RESUME_SITE(x) do { (void)(x); } while (0)
typedef long LONG;
typedef long long LONG64;
typedef unsigned int DWORD;
typedef struct { unsigned long long Rip, Rax, Rsp; DWORD EFlags; } CONTEXT;
typedef struct { DWORD ExceptionCode; } EXCEPTION_RECORD;
typedef struct { EXCEPTION_RECORD *ExceptionRecord; CONTEXT *ContextRecord; } EXCEPTION_POINTERS;
static struct {
    unsigned long long veh_first, vstage, guest_sp_min, guest_sp_max;
    unsigned long long veh_entries, req_seq, done_seq, ss_page;
} data;
static __typeof__(data) *d = &data;
static struct uml_nt_hop_live rec, hop_live_dummy;
static struct uml_nt_hop_live *volatile fs_live_ptr = &rec;
static unsigned long long hop_entry_id, hop_arm_seq, fs_tramp_target;
static int in_veh;
static struct uml_nt_veh_stack veh_stk;
static unsigned long long veh_save[16];
static void fs_trampoline_sys(void) {}
static void fs_trampoline_fault(void) {}
static void fake_tf(void) {}
static LONG64 InterlockedIncrement64(volatile LONG64 *p) { return ++*p; }
static void entry_stamp(EXCEPTION_POINTERS *ep) { (void)ep; }
static void ctx_audit_snapshot(CONTEXT *c) { (void)c; }
static void publish_unhandled(EXCEPTION_RECORD *r, CONTEXT *c) { (void)r; (void)c; }
static void teb_swap_back(void) {}
static void teb_swap_to_guest(void) {}
static void veh_stk_init(void) {}
static unsigned long long veh_now_sp(void) { return 0x800000ull; }
static void veh_diag(EXCEPTION_POINTERS *ep) { (void)ep; }
static void ss_stray_record(CONTEXT *c, unsigned long long dr6, int x, DWORD code)
{ (void)c; (void)dr6; (void)x; (void)code; }
/* the stack switch itself is faked; the wrapper still runs */
static long veh_switch_call(long (*fn)(EXCEPTION_POINTERS *), EXCEPTION_POINTERS *ep,
                           void *top, unsigned long long *save)
{ (void)top; (void)save; return fn(ep); }
enum { SYS, FAULT, STRAY, TF, DIRECT, SEARCH };
static int mode, body_calls, read_in_body, body_saw_old_current;
static CONTEXT body_final;
static LONG veh_handler_body(EXCEPTION_POINTERS *ep);
"""

body = r"""
static void read_mid_body(void)
{
    struct uml_nt_hop_live_view v;

    if (!read_in_body)
        return;
    uml_nt_hop_live_read(&rec, data.req_seq, data.done_seq, data.veh_entries,
                         &v);
    /* during the body, before final preparation, a previous committed record
     * must not look like this attempt's sample */
    if (v.comparable == 1 && v.entry_id == data.veh_entries)
        body_saw_old_current = 1;
}

static LONG veh_handler_body(EXCEPTION_POINTERS *ep)
{
    CONTEXT *c = ep->ContextRecord;
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    int is_step = 0, cls = (mode == STRAY) ? UML_NT_SS_STRAY : 0;
    unsigned long long dr6 = 0;
    body_calls++;
""" + stray + r"""
    read_mid_body();
    if (mode == SYS || mode == FAULT) {
        d->req_seq++;
        d->done_seq = d->req_seq;
        fs_tramp_target = 0x606c9af7ull;
        c->Rip = (uintptr_t)(mode == SYS ? &fs_trampoline_sys
                                         : &fs_trampoline_fault);
        c->Rax = (mode == SYS) ? 0 : 0x7d;
    } else if (mode == TF) {
        c->Rip = (uintptr_t)&fake_tf;
    } else if (mode == SEARCH) {
        body_final = *c;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    body_final = *c;
    return EXCEPTION_CONTINUE_EXECUTION;
}
"""

main = r"""
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL %d: %s\n", __LINE__, #c); } } while (0)

/* a genuinely committed, comparable record from an EARLIER entry */
static void seed_previous_committed(unsigned long long entry)
{
    memset(&rec, 0, sizeof(rec));
    uml_nt_hop_live_arm(&rec, 77, UML_NT_HOP_KIND_SYS, 0x1000, 0, 367, 367,
                        entry);
    rec.entered = rec.commit = 77;
    rec.kind_obs = UML_NT_HOP_KIND_SYS;
    rec.target_obs = 0x1000;
    rec.rax_obs = 0;
    rec.rsp_obs = 0x800000ull;
}

static void reset(void)
{
    memset(&data, 0, sizeof(data));
    memset(&veh_stk, 0, sizeof(veh_stk));
    veh_stk.buf = 0x100000;
    veh_stk.size = 0x10000;
    data.veh_entries = 9000;
    data.req_seq = data.done_seq = 367;
    in_veh = body_calls = 0;
    read_in_body = body_saw_old_current = 0;
    hop_arm_seq = 0;
    fs_live_ptr = &rec;
}

/* the trampolines' terminal stores, modelled (Assembly has its own controls) */
static void terminal_stores(void)
{
    rec.entered = rec.commit = rec.arm_id;
    rec.kind_obs = rec.kind_exp;
    rec.target_obs = fs_tramp_target;
    rec.rax_obs = body_final.Rax;
    rec.rsp_obs = body_final.Rsp;
}

static void case_supported(int which, const char *name)
{
    CONTEXT c = {0x606c9af5, 0x7d, 0x800000, 0x246};
    EXCEPTION_RECORD er = {0x80000004};
    EXCEPTION_POINTERS ep = {&er, &c};
    struct uml_nt_hop_live_view v;
    unsigned long long seq_before;
    LONG r;

    reset();
    mode = which;
    seq_before = hop_arm_seq;
    seed_previous_committed(0);		/* older entry: must not survive */
    r = veh_handler(&ep);
    CHECK(body_calls == 1);
    CHECK(r == EXCEPTION_CONTINUE_EXECUTION);
    CHECK(memcmp(&c, &body_final, sizeof(c)) == 0);	/* CONTEXT preserved */
    CHECK(data.veh_entries == 9001);
    CHECK(rec.entry_id == data.veh_entries);		/* the CURRENT entry */
    CHECK(hop_arm_seq == seq_before + 1);		/* armed exactly once */
    CHECK(rec.kind_exp == (unsigned)(which == SYS ? UML_NT_HOP_KIND_SYS
                                                  : UML_NT_HOP_KIND_FAULT));
    CHECK(rec.target_exp == fs_tramp_target);
    CHECK(rec.rax_exp == c.Rax);
    CHECK(rec.req_seq == data.req_seq);			/* post-body sequences */
    CHECK(rec.done_seq == data.done_seq);
    terminal_stores();
    uml_nt_hop_live_read(&rec, data.req_seq, data.done_seq, data.veh_entries,
                         &v);
    printf("raw handler -> dispatch [%s]: ret=%ld calls=%d current=%llu "
           "recorded=%llu verdict=%d comparable=%d\n", name, r, body_calls,
           data.veh_entries, (unsigned long long)rec.entry_id, v.verdict,
           v.comparable);
    CHECK(v.verdict == UML_NT_HOP_LIVE_COMMITTED);
    CHECK(v.comparable == 1);
}

static void case_unsampled(int which, const char *name)
{
    CONTEXT c = {0x606c9af5, 0x7d, 0x800000, 0x246};
    EXCEPTION_RECORD er = {0x80000004};
    EXCEPTION_POINTERS ep = {&er, &c};
    struct uml_nt_hop_live_view v;
    LONG r;

    reset();
    mode = which;
    seed_previous_committed(9000);	/* comparable for the OLD entry */
    r = veh_handler(&ep);
    CHECK(body_calls == 1);
    CHECK(data.veh_entries == 9001);
    uml_nt_hop_live_read(&rec, data.req_seq, data.done_seq, data.veh_entries,
                         &v);
    printf("raw handler -> dispatch [%s]: ret=%ld calls=%d current=%llu "
           "recorded=%llu verdict=%d comparable=%d\n", name, r, body_calls,
           data.veh_entries, (unsigned long long)rec.entry_id, v.verdict,
           v.comparable);
    CHECK(v.comparable == 0);		/* never promoted */
    CHECK(rec.arm_id == 0 || v.verdict != UML_NT_HOP_LIVE_COMMITTED);
}

static void case_mid_body_read(void)
{
    CONTEXT c = {0x606c9af5, 0x7d, 0x800000, 0x246};
    EXCEPTION_RECORD er = {0x80000004};
    EXCEPTION_POINTERS ep = {&er, &c};

    reset();
    mode = SYS;
    read_in_body = 1;
    seed_previous_committed(9000);
    (void)veh_handler(&ep);
    CHECK(body_calls == 1);
    CHECK(body_saw_old_current == 0);	/* the old record was invalidated */
}

/* the two paths that never reach the diagnostic wrapper */
static void case_in_veh_search(void)
{
    CONTEXT c = {0x606c9af5, 0x7d, 0x800000, 0x246};
    EXCEPTION_RECORD er = {0x80000004};
    EXCEPTION_POINTERS ep = {&er, &c};
    struct uml_nt_hop_live_view v;
    LONG r;

    reset();
    mode = SYS;
    seed_previous_committed(9000);
    data.veh_entries = 9001;
    in_veh = 1;				/* re-entrant entry: SEARCH before switch */
    r = veh_handler(&ep);
    CHECK(r == EXCEPTION_CONTINUE_SEARCH);
    CHECK(body_calls == 0);
    uml_nt_hop_live_read(&rec, data.req_seq, data.done_seq, data.veh_entries,
                         &v);
    printf("in_veh path: ret=%ld calls=%d current=%llu recorded=%llu "
           "verdict=%d comparable=%d\n", r, body_calls, data.veh_entries,
           (unsigned long long)rec.entry_id, v.verdict, v.comparable);
    CHECK(v.comparable == 0);
}


/* the refused-stack fallback: uml_nt_veh_enter refuses (buf == 0), so the raw
 * handler calls the body DIRECTLY — the diagnostic wrapper never runs, and the
 * old committed record must not be promoted to this entry. */
static void case_refused_stack(void)
{
    CONTEXT c = {0x606c9af5, 0x7d, 0x800000, 0x246};
    EXCEPTION_RECORD er = {0x80000004};
    EXCEPTION_POINTERS ep = {&er, &c};
    struct uml_nt_hop_live_view v;
    unsigned long long seq_before, req_before, done_before;
    LONG r;

    reset();
    mode = DIRECT;
    seed_previous_committed(9000);
    req_before = data.req_seq;
    done_before = data.done_seq;
    seq_before = hop_arm_seq;
    /* the real model refuses when the buffer is absent */
    veh_stk.buf = 0;
    veh_stk.size = 0;
    in_veh = 0;

    r = veh_handler(&ep);
    CHECK(r == EXCEPTION_CONTINUE_EXECUTION);
    CHECK(body_calls == 1);			/* the body ran, the wrapper did not */
    CHECK(data.veh_entries == 9001);		/* the raw handler still counted */
    CHECK(data.req_seq == req_before && data.done_seq == done_before);
    CHECK(hop_arm_seq == seq_before);		/* nothing was armed */
    CHECK(rec.arm_id == 77 && rec.commit == 77);	/* the OLD record intact */
    CHECK(rec.entry_id == 9000);		/* still the old entry */
    uml_nt_hop_live_read(&rec, data.req_seq, data.done_seq, data.veh_entries,
                         &v);
    printf("refused-stack fallback: ret=%ld calls=%d current=%llu "
           "recorded=%llu arm_id=%llu commit=%llu verdict=%d comparable=%d\n",
           r, body_calls, data.veh_entries,
           (unsigned long long)rec.entry_id, (unsigned long long)rec.arm_id,
           (unsigned long long)rec.commit, v.verdict, v.comparable);
    CHECK(v.verdict == UML_NT_HOP_LIVE_STALE);
    CHECK(v.comparable == 0);
}

int main(void)
{
    case_supported(SYS, "sys");
    case_supported(FAULT, "fault");
    case_unsampled(STRAY, "SS_STRAY");
    case_unsampled(TF, "TF");
    case_unsampled(DIRECT, "direct");
    case_unsampled(SEARCH, "SEARCH");
    case_mid_body_read();
    case_in_veh_search();
    case_refused_stack();

    printf("dispatch integration: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
"""

program = prefix + helpers + "\n" + body + "\n" + dispatch + "\n" + handler \
          + "\n" + main
probe = out / "probe.c"
probe.write_text(program)
# -Wno-unused-function only: a replaced/bypassed finalizer must fail at
# RUNTIME, not by a compile-time warning about an unused helper.
build = subprocess.run([cc, "-O1", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-Wno-unused-variable",
                        "-I" + inc,
                        str(probe), "-o", str(out / "probe")],
                       text=True, capture_output=True)
print(build.stdout + build.stderr, end="")
if build.returncode:
    print("hop_dispatch: COMPILE_EXIT=%d" % build.returncode)
    sys.exit(1)
run = subprocess.run([str(out / "probe")], text=True, capture_output=True)
print(run.stdout + run.stderr, end="")
sys.exit(run.returncode)
