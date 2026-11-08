#!/usr/bin/env bash
# S455: the terminating rip is untrustworthy; the first-chance tail is the record.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../kernel/overlay/arch/um/os-Windows/start_up.c"

grep -q 'av_ring\[32\]' "$S" || { echo "FAIL: no first-chance ring"; exit 1; }
grep -q 'uml_nt_av_note(ep)' "$S" || { echo "FAIL: exceptions are not recorded"; exit 1; }
grep -qF '"[av] tid=%llu code=%08x rip=%llx op=%d "' "$S" 
# the note must happen when the report starts, before any recovery decisions
n=$(grep -n 'uml_nt_av_note(ep)' "$S" | head -1 | cut -d: -f1)
c=$(grep -n 'in_crash_report = 1;' "$S" | head -1 | cut -d: -f1)
[ -n "$n" ] && [ -n "$c" ] && [ "$n" -le "$c" ] || { echo "FAIL: recorded too late"; exit 1; }
echo "av_ring: first-chance exceptions recorded and replayed at termination"
