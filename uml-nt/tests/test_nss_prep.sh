#!/usr/bin/env bash
# S432: strip the userdb source from nsswitch WITHOUT breaking the parser, and
# prove the image can still resolve accounts by using it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$HERE/../../.github/workflows/uml-nt-m55-systemd.yml"

grep -q 'nsswitch.conf' "$W" || { echo "FAIL: prep never touches nsswitch"; exit 1; }

# 1. no trailing comment may be appended to a database line: glibc stops parsing
#    the whole line, which is exactly how every lookup broke in 42398385638.
if grep -qF '/\(passwd:\)[[:space:]].*#' "$W"; then
	echo "FAIL: the sed appends a comment to the passwd line"; exit 1
fi
for db in passwd group shadow gshadow; do
	grep -q "($db:" "$W" || { echo "FAIL: $db not rewritten"; exit 1; }
done

# 2. enforcement by USE: the image's own parser must resolve both accounts
grep -q 'chroot /mnt/m55a-rootfs getent passwd root' "$W" \
	|| { echo "FAIL: root is not resolved through the image"; exit 1; }
grep -q 'chroot /mnt/m55a-rootfs getent passwd messagebus' "$W" \
	|| { echo "FAIL: messagebus is not verified"; exit 1; }
grep -q '\[prep\] getent-root=FAILED' "$W" \
	|| { echo "FAIL: job does not fail when root is unresolvable"; exit 1; }
grep -q '\[prep\] getent-messagebus=FAILED' "$W" \
	|| { echo "FAIL: job does not fail when messagebus is unresolvable"; exit 1; }
grep -q 'refusing to publish' "$W" \
	|| { echo "FAIL: no enforcement"; exit 1; }
grep -q '\[prep\] pam_systemd=commented active=0' "$W" \
	|| { echo "FAIL: prep does not declare pam_systemd neutralised"; exit 1; }
grep -q '\[prep\] pam_systemd=present active=' "$W" \
	|| { echo "FAIL: prep cannot fail when pam_systemd is active"; exit 1; }
echo "nss_prep: no trailing comments, both accounts resolved by the image itself"
