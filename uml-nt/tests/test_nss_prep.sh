#!/usr/bin/env bash
# S430: the prep must strip systemd from the account databases and prove it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$HERE/../../.github/workflows/uml-nt-m55-systemd.yml"

grep -q 'nsswitch.conf' "$W" || { echo "FAIL: prep never touches nsswitch"; exit 1; }
grep -q '\[prep\] nss_systemd=removed' "$W" \
	|| { echo "FAIL: the prep does not declare the result"; exit 1; }
grep -q '\[prep\] nss_systemd=present' "$W" \
	|| { echo "FAIL: the prep cannot fail on a surviving source"; exit 1; }
grep -q 'refusing to publish' "$W" \
	|| { echo "FAIL: no enforcement"; exit 1; }
# all four account databases are handled, not just passwd
for db in passwd group shadow gshadow; do
	grep -q "^(\\\\\\($db:" "$W" || grep -q "$db:\[\[:space:\]\]\\*files" "$W" \
		|| { echo "FAIL: $db not rewritten"; exit 1; }
done
echo "nss_prep: systemd stripped from all four account databases, declared and enforced"
