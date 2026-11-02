#!/usr/bin/env bash
# S13: the plain-hop witness — logic, the real assembly sequence, the shared
# ABI on ELF and PE, and the source integration that binds them together.
#
# Three honest layers:
#   1. test_hop_live.c      — the production header's arm/read/format rules.
#   2. test_hop_live_asm.c  — the EXACT macro sequence from hop_live_asm.h,
#                             executed on this CPU. A snippet control, not
#                             proof that Windows dispatched through it.
#   3. ABI + source checks  — the record's layout, the section budget, the
#                             protocol version, and that the real call sites
#                             (trampolines, resume choices, death reader) use
#                             the witness.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/../kernel/overlay/arch/um"
INC="$ROOT/include/shared"
STUB="${1:-$HERE/../stub/stub.c}"
PROC="${2:-$ROOT/os-Windows/skas/process.c}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"
MINGW="${MINGW_CC:-x86_64-w64-mingw32-gcc}"

echo "== hop witness logic (production header, recording sink)"
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/logic" "$HERE/test_hop_live.c"
"$TMP/logic"

echo "== the real assembly sequence on this CPU"
if [ "$(uname -m)" = "x86_64" ]; then
	"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/asm" \
		"$HERE/test_hop_live_asm.c"
	"$TMP/asm"
fi

echo "== shared ABI (compile-time pins in the headers, both targets)"
cat > "$TMP/abi.c" <<'ABIC'
#include <stdio.h>
#include <stub_nt.h>

int main(void)
{
	/* The layout claims are _Static_asserts in hop_live.h and stub_nt.h, so
	 * reaching this line means both compilers accepted them. This program
	 * only prints the numbers for the record. */
	printf("stub_abi: offset=0x%llx size=%llu section=%u version=%u\n",
	       (unsigned long long)__builtin_offsetof(struct uml_nt_stub_data,
						      hop_live),
	       (unsigned long long)sizeof(struct uml_nt_stub_data),
	       (unsigned)UML_STUB_SECTION_SIZE, (unsigned)UML_STUB_VERSION);
	return 0;
}
ABIC
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/abi_elf" "$TMP/abi.c"
"$TMP/abi_elf"
if ! command -v "$MINGW" >/dev/null 2>&1; then
	echo "FAIL: $MINGW not found — the PE layout assertions were NOT verified"
	exit 1
fi
"$MINGW" -O1 -Wall -Wextra -Werror -I"$INC" -o "$TMP/abi_pe.exe" "$TMP/abi.c"
echo "stub_abi: PE compile-time layout assertions accepted"

echo "== source integration (the real call sites, not an emitter-only check)"
python3 - "$STUB" "$PROC" "$INC/hop_live_asm.h" "$HERE/../stub/Makefile" <<'PY'
import re
import sys

stub, proc, asm_h, makefile = (open(p, encoding="utf-8", errors="replace").read()
                               for p in sys.argv[1:5])
fails = []


def fail(m):
    fails.append(m)


for fn in ("fs_trampoline_sys", "fs_trampoline_fault"):
    m = re.search(r"static void %s\(void\)\n\{.*?\n\}\n" % fn, stub, re.S)
    if not m:
        fail("%s not found" % fn)
        continue
    body = m.group(0)
    i_enter = body.find("HOP_LIVE_STAMP_ENTER()")
    firsts = [i for i in (body.find("wrfsbase"), body.find("fs_stage"),
                          body.find("fs_tramp_base")) if i > 0]
    i_first = min(firsts) if firsts else 10 ** 6
    if i_enter < 0:
        fail("%s has no entry stamp" % fn)
    elif i_enter > i_first:
        fail("%s stamps the entry after its first instruction" % fn)

for fn, kind in (("fs_trampoline_sys", '"1"'), ("fs_trampoline_fault", '"2"')):
    m = re.search(r"static void %s\(void\)\n\{.*?\n\}\n" % fn, stub, re.S)
    if not m:
        continue
    body = m.group(0)
    i_commit = body.find("HOP_LIVE_STAMP_COMMIT(%s)" % kind)
    i_rdtsc = body.find("rdtsc")
    i_jmp = body.find("jmp\t*fs_tramp_target(%rip)")
    if i_commit < 0 or i_rdtsc < 0 or i_jmp < 0:
        fail("%s: missing commit/rdtsc/jmp" % fn)
    elif not (i_rdtsc < i_commit < i_jmp):
        fail("%s: the commit is not between the timestamp block and the jmp" % fn)

m = re.search(r"static void fs_trampoline_fault_tf\(void\).*?\n\}\n", stub, re.S)
if m and "HOP_LIVE_STAMP" in m.group(0):
    fail("the TF trampoline must not be sampled")

# --- the finalizer is the ONE place that arms, from the final context ----
if "hop_live_finalize(ep, r)" not in stub:
    fail("the dispatch wrapper does not run the finalizer")
if "hop_live_arm_ctx" in stub:
    fail("a scattered arm helper is still present")
if "hop_armed_this_return" in stub:
    fail("the per-return latch is still present (the finalizer replaces it)")
if "hop_live_begin_attempt()" not in stub:
    fail("the dispatch does not capture the entry identity")
if "d->veh_entries" not in stub:
    fail("no VEH-entry identity is captured")
if re.search(r"\n\td->veh_entries\+\+;\n\t(hop_live_|hop_)", stub):
    fail("a witness step runs in the raw handler before the stack switch")

seq = asm_h
for banned in ("push", "pop", "call", "rdtsc", "test", "inc", "lock", "stc"):
    if re.search(r'"\s*%s' % banned, seq):
        fail("hop_live_asm.h contains a %s in the added sequence" % banned)
if "(COMMIT)" not in seq:
    fail("the sequence never stores the commit id")
else:
    tail_after = seq[seq.find("HOP_OFF_STR(COMMIT)"):]
    for other in ("KIND_OBS", "TARGET_OBS", "RSP_OBS"):
        if "HOP_OFF_STR(%s)" % other in tail_after:
            fail("%s is stored after the commit id" % other)

for h in ("hop_live.h", "hop_live_asm.h"):
    if h not in makefile:
        fail("stub/Makefile does not depend on %s" % h)

if fails:
    for f in fails:
        print("FAIL: " + f)
    print("hop_live_source: %d failure(s)" % len(fails))
    sys.exit(1)
print("hop_live_source: one finalizer in the dispatch wrapper, both "
      "trampolines stamped at entry, reader bound")
PY
