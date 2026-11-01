#!/usr/bin/env bash
# S2 regression: the VEH diagnostics must run AFTER the private-stack switch.
#
# This is a SOURCE-ONLY check, deterministic by construction: no build, no
# binary, no tool probe. It is not a Windows runtime proof — it cannot see a
# real rsp — and it is not a binary check either: inspecting the PE is a
# separate command whose exit status speaks for itself. What this test does
# prove is the shape the runtime needs: the two CRT diagnostics are reachable
# only from inside the switched stack, the refused path never calls them, the
# marker tells the incoming sp apart from the body's sp, and no new
# emulated-TLS variable is introduced on the pre-switch path.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$HERE/../stub/stub.c}"

exec python3 - "$SRC" <<'PY'
import re
import sys

path = sys.argv[1]
src = open(path, encoding="utf-8", errors="replace").read()
lines = src.split("\n")
failures = []


def fail(msg):
    failures.append(msg)


def line_of(pattern, start=0):
    """1-based line number of the first match at/after `start` (0-based)."""
    rx = re.compile(pattern)
    for i in range(start, len(lines)):
        if rx.search(lines[i]):
            return i + 1
    return 0


# --- locate the handler and the switch ------------------------------------
switch_ln = line_of(r"veh_switch_call\(\s*\(long \(\*\)\(EXCEPTION_POINTERS \*\)\)")
if switch_ln == 0:
    fail("no veh_switch_call((long (*)(EXCEPTION_POINTERS *)) ... ) call found")

# the function that veh_switch_call runs on the private stack
m = re.search(r"veh_switch_call\(\s*\(long \(\*\)\(EXCEPTION_POINTERS \*\)\)\s*\n?\s*(\w+)",
              src)
switch_target = m.group(1) if m else None
if switch_target is None:
    fail("could not read the function veh_switch_call runs")

# --- the two diagnostics must not run inside the switching function itself -
def function_span(start_ln):
    """(first, last) 1-based line of the braced body that starts at start_ln."""
    depth = 0
    started = False
    for i in range(start_ln - 1, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth <= 0:
            return start_ln, i + 1
    return start_ln, len(lines)


handler_ln = line_of(r"^static LONG CALLBACK veh_handler\(EXCEPTION_POINTERS \*ep\)\s*$")
if handler_ln == 0:
    fail("veh_handler() is not defined")
    handler = ""
else:
    a, b = function_span(handler_ln)
    handler = "\n".join(lines[a - 1:b])

DIAGS = (("fault_forensics", r"\bfault_forensics\(\s*ep\s*\)"),
         ("[veh-enter] fprintf", r'fprintf\(stderr, "\[veh-enter\]'))

for name, pat in DIAGS:
    if not re.search(pat, src):
        fail("%s disappeared: the marker is part of the contract" % name)
        continue
    m2 = re.search(pat, handler)
    if m2:
        ln = handler_ln + handler[:m2.start()].count("\n")
        fail("%s runs at line %d, inside the switching function "
             "(the switch is at line %d)" % (name, ln, switch_ln))

# --- and they must be reached from the switched function ------------------
if switch_target:
    body_ln = line_of(r"static\s+LONG\s+CALLBACK\s+%s\s*\(" % re.escape(switch_target))
    if body_ln == 0:
        fail("the switched function %s() is not defined" % switch_target)
    else:
        end_ln = line_of(r"^\}", body_ln)
        body = "\n".join(lines[body_ln - 1:(end_ln or len(lines))])
        # the diagnostics may sit one helper call deep (veh_diag) — follow
        # the calls this function makes into helpers defined in the file
        reach = body
        for callee in re.findall(r"\b(\w+)\(ep\)\s*;", body):
            c_ln = line_of(r"^static\s+\w+\s+%s\(" % re.escape(callee))
            if c_ln:
                c_a, c_b = function_span(c_ln)
                reach += "\n" + "\n".join(lines[c_a - 1:c_b])
        if not re.search(r"\bfault_forensics\(\s*ep\s*\)", reach):
            fail("%s() cannot reach fault_forensics: the diagnostic left the "
                 "switched stack" % switch_target)
        if not re.search(r'fprintf\(stderr, "\[veh-enter\]', reach):
            fail("%s() cannot reach the [veh-enter] print" % switch_target)
        if not re.search(r"\bveh_handler_body\s*\(", body):
            fail("%s() does not call the exception body" % switch_target)

# --- the refused path must stay silent ------------------------------------
ref_ln = line_of(r"r\s*=\s*veh_handler_body\(ep\);|\br\s*=\s*veh_body\(ep\);")
if ref_ln == 0:
    fail("the refused-switch fallback is gone or was renamed without a test "
         "update")
else:
    around = "\n".join(lines[max(0, ref_ln - 3):ref_ln + 1])
    for pat, name in ((r"\bfault_forensics\(\s*ep\s*\)", "fault_forensics"),
                      (r'fprintf\(stderr, "\[veh-enter\]', "[veh-enter]")):
        if re.search(pat, around):
            fail("the refused path runs %s — it must not" % name)

# --- the marker must distinguish the two stack pointers -------------------
enter_ln = line_of(r'fprintf\(stderr, "\[veh-enter\]')
if enter_ln:
    blk = "\n".join(lines[enter_ln - 1:enter_ln + 8])
    for field in ("incoming_rsp=", "body_rsp=", "in_buf="):
        if field not in blk:
            fail("the [veh-enter] marker does not report %s" % field)

# --- S2b: no fresh emulated-TLS variable on the pre-switch path ----------
# The type may be several words ("unsigned long long"), so the regex has to
# span them; the earlier single-word version evaluated false against the very
# declaration it was written for ("static __thread unsigned long long
# veh_sp_in;") and would have passed a reintroduction silently.
if re.search(r"__thread\b[^;{}]*\b\w*sp_in\s*(\[[^\]]*\])?\s*;", src):
    fail("a __thread *_sp_in variable is back: it puts an emulated-TLS "
         "lookup (__emutls_get_address) before the switch")
if not re.search(r"veh_stk\.guest_sp", src):
    fail("veh_diag no longer reads veh_stk.guest_sp — the incoming sp must "
         "come from the stack model, not from new storage")
# a bare mention in a comment is history, not storage; an assignment is code
if re.search(r"^\s*veh_sp_in\s*=", src, re.M):
    fail("veh_sp_in is assigned again in the source")

# --- and the CRT work must be gated on the private buffer ----------------
if enter_ln:
    # the guard is the block that returns unless body_rsp is inside buf
    guard_ln = line_of(r"body_rsp\s*<\s*buf\s*\|\|\s*body_rsp\s*>=\s*end")
    if guard_ln == 0 or guard_ln > enter_ln:
        fail("no `body_rsp < buf || body_rsp >= end` guard before the CRT "
             "calls")
    if not line_of(r"veh_stk\.buf") or not line_of(r"veh_stk\.size"):
        fail("the buffer bounds do not come from veh_stk.buf/size")

if failures:
    for f in failures:
        print("FAIL: " + f)
    print("test_veh_diag_order: %d failure(s)" % len(failures))
    sys.exit(1)
print("test_veh_diag_order: the diagnostics are on the switched stack")
PY
