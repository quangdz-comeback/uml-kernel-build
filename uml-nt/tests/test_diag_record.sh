#!/usr/bin/env bash
# S8 (Astra): the diagnostic-record emission rule, plus source integration
# checks that the selected emitters actually use it.
#
# Two halves, both honest about what they prove:
#   1. HOST LOGIC — tests/test_diag_record.c drives the PRODUCTION helper
#      (diag_record.h) through a recording sink: one record is one sink call,
#      records are newline-terminated inside their buffer, truncation says so,
#      failures are reported and never retried.
#   2. SOURCE SHAPE — the seven selected stub emitters go through the helper
#      (no bare fprintf(stderr, ...) left for them), and os_info/os_warn hand
#      the whole record to nt_console_write exactly once.
# Neither half is evidence about Windows write atomicity.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUB="${1:-$HERE/../stub/stub.c}"
UTIL="${2:-$HERE/../kernel/overlay/arch/um/os-Windows/util.c}"
INC="$HERE/../kernel/overlay/arch/um/include/shared"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC="${CC:-clang}"

echo "== host logic (production helper + recording sink)"
"$CC" -O1 -Wall -Wextra -Werror -I"$INC" \
	-o "$TMP/test_diag_record" "$HERE/test_diag_record.c"
"$TMP/test_diag_record"

echo "== production adapters (extracted verbatim, driven by API fakes)"
python3 - "$STUB" "$UTIL" "$TMP" <<'PYADAPT'
import re
import sys

stub_path, util_path, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
stub = open(stub_path, encoding="utf-8", errors="replace").read()
util = open(util_path, encoding="utf-8", errors="replace").read()


def extract(src, path):
    m = re.search(r"/\* S8b-ADAPTER-BEGIN.*?\*/(.*?)/\* S8b-ADAPTER-END \*/",
                  src, re.S)
    if not m:
        # No markers: this source predates the adapter contract. Skip the
        # adapter harness and let the source-shape checks below name exactly
        # what is missing — a missing marker must not masquerade as a pass.
        print("adapter markers absent in %s (pre-S8b source)" % path)
        return ""
    return m.group(1)


stub_adapter = extract(stub, stub_path)
kern_adapter = extract(util, util_path)

PRE_STUB = r"""
#include <stdio.h>
#include <string.h>

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
#ifndef NULL
#define NULL ((void *)0)
#endif
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define STD_ERROR_HANDLE ((DWORD)-12)
#define UML_NT_DIAG_SINK_UNKNOWN_VALUE (-2147483647)

static HANDLE fake_handle;
static int fake_write_calls;
static BOOL fake_write_ok;
static DWORD fake_wrote;

HANDLE GetStdHandle(DWORD which) { (void)which; return fake_handle; }
BOOL WriteFile(HANDLE h, const void *b, DWORD n, DWORD *wrote, void *ov)
{
	(void)h; (void)b; (void)n; (void)ov;
	fake_write_calls++;
	*wrote = fake_wrote;
	return fake_write_ok;
}
"""

POST_STUB = r"""
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL: %s\n", #c); } } while (0)

int main(void)
{
	char buf[8] = "abcdefg";
	int r;

	fake_handle = (HANDLE)(long)1234; fake_write_calls = 0;
	fake_write_ok = 1; fake_wrote = 7;
	r = stub_diag_sink(buf, 7);
	CHECK(r == 7);
	CHECK(fake_write_calls == 1);

	fake_handle = (HANDLE)(long)1234; fake_write_calls = 0;
	fake_write_ok = 1; fake_wrote = 3;
	r = stub_diag_sink(buf, 7);
	CHECK(r == 3);
	CHECK(fake_write_calls == 1);

	fake_handle = (HANDLE)(long)1234; fake_write_calls = 0;
	fake_write_ok = 1; fake_wrote = 0;
	r = stub_diag_sink(buf, 7);
	CHECK(r == 0);
	CHECK(fake_write_calls == 1);

	fake_handle = (HANDLE)(long)1234; fake_write_calls = 0;
	fake_write_ok = 0; fake_wrote = 0;
	r = stub_diag_sink(buf, 7);
	CHECK(r == -1);
	CHECK(r != UML_NT_DIAG_SINK_UNKNOWN_VALUE);
	CHECK(fake_write_calls == 1);

	fake_handle = NULL; fake_write_calls = 0;
	fake_write_ok = 1; fake_wrote = 7;
	r = stub_diag_sink(buf, 7);
	CHECK(r == -1);
	CHECK(fake_write_calls == 0);

	fake_handle = INVALID_HANDLE_VALUE; fake_write_calls = 0;
	fake_write_ok = 1; fake_wrote = 7;
	r = stub_diag_sink(buf, 7);
	CHECK(r == -1);
	CHECK(fake_write_calls == 0);

	if (fails) { printf("stub_adapter: %d failure(s)\n", fails); return 1; }
	printf("stub_adapter: all ok\n");
	return 0;
}
"""

PRE_KERN = r"""
#include <stdio.h>

#define UML_NT_DIAG_SINK_UNKNOWN_VALUE (-2147483647)

static int kern_calls;
static unsigned int kern_len;
static const char *kern_buf;

void nt_console_write(const char *s, unsigned int n)
{
	kern_calls++;
	kern_buf = s;
	kern_len = n;
}
"""

POST_KERN = r"""
static int fails;
#define CHECK(c) do { if (!(c)) { fails++; printf("FAIL: %s\n", #c); } } while (0)

int main(void)
{
	const char *rec = "one record\n";
	int r;

	r = diag_console_sink(rec, 11);
	CHECK(r == UML_NT_DIAG_SINK_UNKNOWN_VALUE);
	CHECK(kern_calls == 1);
	CHECK(kern_len == 11);
	CHECK(kern_buf == rec);

	if (fails) { printf("kern_adapter: %d failure(s)\n", fails); return 1; }
	printf("kern_adapter: all ok\n");
	return 0;
}
"""

if stub_adapter and kern_adapter:
    open(outdir + "/stub_adapter.c", "w").write(
        PRE_STUB + stub_adapter + POST_STUB)
    open(outdir + "/kern_adapter.c", "w").write(
        PRE_KERN + kern_adapter + POST_KERN)
    print("adapters extracted")
PYADAPT

if [ -f "$TMP/stub_adapter.c" ]; then
	"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/stub_adapter" \
		"$TMP/stub_adapter.c"
	"$TMP/stub_adapter"
	"$CC" -O1 -Wall -Wextra -Werror -o "$TMP/kern_adapter" \
		"$TMP/kern_adapter.c"
	"$TMP/kern_adapter"
fi

echo "== source shape"
python3 - "$STUB" "$UTIL" "$HERE/../kernel/overlay/arch/um/include/shared/diag_record.h" \
	"$HERE/../kernel/overlay/arch/um/os-Windows/skas/syscall.c" <<'PY'
import re
import sys

stub_path, util_path, diag_path, syscall_path = sys.argv[1:5]
stub = open(stub_path, encoding="utf-8", errors="replace").read()
util = open(util_path, encoding="utf-8", errors="replace").read()
failures = []


def fail(msg):
    failures.append(msg)


# --- the seven selected emitters must go through the record helper ---------
SELECTED = ["[teb]", "[stack-commit]", "[ans-window]", "[ans-bad]",
            "[ans-keep]", "[veh-enter]", "[fault-addr]"]
for tag in SELECTED:
    direct = re.search(r'fprintf\(stderr,\s*"%s' % re.escape(tag), stub)
    via = re.search(r'STUB_DIAG\(\s*\w+\s*,\s*"%s' % re.escape(tag), stub)
    if direct:
        fail("%s is still printed with a bare fprintf(stderr, ...)" % tag)
    if not via:
        fail("%s does not go through the one-write record helper" % tag)

# --- the helper itself must be present and single-attempt ------------------
if "uml_nt_diag_record" not in stub:
    fail("the stub has no record emitter")

# --- no forbidden fallback/retry in the helper ----------------------------
diag_h = open(diag_path, encoding="utf-8", errors="replace").read()
for banned in ("fwrite(", "fputs(", "fprintf(", "fflush(", "goto retry",
               "while (retry"):
    if banned in diag_h:
        fail("diag_record.h contains a fallback/retry path: %s" % banned)
if diag_h.count("ops->sink(") != 1:
    fail("diag_record.h calls the sink %d times, must be exactly once"
         % diag_h.count("ops->sink("))

# --- the adapters and their bindings, not just the shared callback ---------
# A second WriteFile inside stub_diag_sink, or a second nt_console_write inside
# diag_console_sink, would pass a check that only counted sink calls in the
# shared helper. These checks look at the adapters themselves.
def adapter(src, path):
    m = re.search(r"/\* S8b-ADAPTER-BEGIN.*?\*/(.*?)/\* S8b-ADAPTER-END \*/",
                  src, re.S)
    if not m:
        fail("adapter markers missing in " + path)
        return ""
    return m.group(1)


stub_ad = adapter(stub, stub_path)
kern_ad = adapter(util, util_path)
if stub_ad:
    if stub_ad.count("WriteFile(") != 1:
        fail("stub_diag_sink calls WriteFile %d times, must be exactly once"
             % stub_ad.count("WriteFile("))
    if re.search(r"fwrite\(|fprintf\(|fflush\(|fputs\(", stub_ad):
        fail("stub_diag_sink contains a fallback printf/fwrite path")
    if "UML_NT_DIAG_SINK_UNKNOWN_VALUE" in stub_ad:
        fail("stub_diag_sink reports UNKNOWN: a failed write is a known "
             "failure, not an unknown one")
    if "return -1;" not in stub_ad:
        fail("stub_diag_sink does not return the hard-failure value -1")
if kern_ad:
    if kern_ad.count("nt_console_write(") != 1:
        fail("diag_console_sink calls nt_console_write %d times, must be "
             "exactly once" % kern_ad.count("nt_console_write("))
    if "UML_NT_DIAG_SINK_UNKNOWN_VALUE" not in kern_ad:
        fail("diag_console_sink must report UNKNOWN (its write has no status)")

# --- the ops table must bind those very functions -------------------------
if not re.search(r"static const struct uml_nt_diag_ops stub_diag_ops\s*=\s*\{\s*"
                 r"stub_diag_format\s*,\s*stub_diag_sink\s*\}", stub):
    fail("stub_diag_ops does not bind stub_diag_format + stub_diag_sink")
if not re.search(r"static const struct uml_nt_diag_ops diag_console_ops\s*=\s*\{\s*"
                 r"diag_console_format\s*,\s*diag_console_sink\s*\}", util):
    fail("diag_console_ops does not bind diag_console_format + diag_console_sink")

# --- and the selected emitters must reach the helper through the macro ----
m = re.search(r"#define STUB_DIAG\(buf, fmt, \.\.\.\)(.*?)\n\n", stub, re.S)
if not m:
    fail("the STUB_DIAG macro is gone")
elif ("uml_nt_diag_record(" not in m.group(1) or
      "&stub_diag_ops" not in m.group(1)):
    fail("STUB_DIAG does not call uml_nt_diag_record with &stub_diag_ops")

# --- the guest write path must be untouched -------------------------------
syscall_c = open(syscall_path, encoding="utf-8", errors="replace").read()
if "nt_console_write((char *)uml_boot.physmem_base + off," not in syscall_c:
    fail("the guest write path changed (sys_write must pass the guest bytes "
         "straight to nt_console_write)")

# --- os_info/os_warn: one console write per record ------------------------
def body(fn):
    m = re.search(r"void %s\(const char \*fmt, \.\.\.\)\n\{" % fn, util)
    if not m:
        fail("%s() is not defined" % fn)
        return ""
    depth = 0
    i = util.index("{", m.start())
    start = i
    while i < len(util):
        if util[i] == "{":
            depth += 1
        elif util[i] == "}":
            depth -= 1
            if depth == 0:
                return util[start:i + 1]
        i += 1
    return ""


for fn in ("os_info", "os_warn"):
    b = body(fn)
    if not b:
        continue
    n = b.count("nt_console_write(")
    if "uml_nt_diag_emit(" not in b and "DIAG_EMIT_LOGGED" not in b:
        fail("%s() does not use the record emitter" % fn)
    if n != 0:
        fail("%s() calls nt_console_write %d time(s) itself; the emitter owns "
             "the single write" % (fn, n))
    if re.search(r'nt_console_write\("\\n"', b):
        fail("%s() still writes its newline as a second call" % fn)

if failures:
    for f in failures:
        print("FAIL: " + f)
    print("test_diag_record: %d source failure(s)" % len(failures))
    sys.exit(1)
print("test_diag_record: emitters and kernel framing use one write")
PY
