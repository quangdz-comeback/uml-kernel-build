#!/usr/bin/env bash
# S464: what did the reader actually receive?
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="$HERE/../kernel/overlay/arch/um/os-Windows/skas/stub_ctl.c"

grep -q '\[feed-drain\] pid=%d n=%lu text=' "$K" \
	|| { echo "FAIL: the reader's bytes are not shown"; exit 1; }
grep -q 'uml_nt_phys_read_checked(c, (unsigned long long)ro' "$K" \
	|| { echo "FAIL: the dump does not use the checked reader"; exit 1; }
grep -q 'uml_nt_vma_translate(c->mm, d->args\[1\], rn)' "$K" \
	|| { echo "FAIL: no translation of the read buffer"; exit 1; }
grep -q 'rn > 16' "$K" || { echo "FAIL: unbounded dump"; exit 1; }
echo "feed_drain: reader bytes dumped through the checked path, bounded"
