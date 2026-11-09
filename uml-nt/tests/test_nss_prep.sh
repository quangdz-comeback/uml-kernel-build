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
# S434: the replacement must REPLACE the line, never append a comment above it
if grep -qE "^ *-e .s\|\^session.*pam_systemd.*n&" "$W"; then
	printf "FAIL: the pam_systemd sed still keeps the active line (backslash-n amp)\n"; exit 1
fi
grep -qF 'pam_systemd disabled: no userdbd in this image' "$W" \
	|| { echo "FAIL: no replacement text"; exit 1; }
grep -q '\[prep\] securetty=' "$W" \
	|| { echo "FAIL: securetty is not declared"; exit 1; }
grep -q 'console\\ntty0' "$W" \
	|| { echo "FAIL: the console terminals are not written"; exit 1; }
grep -q '\[prep\] pam_loginuid=commented active=0' "$W" \
	|| { echo "FAIL: loginuid neutralisation is not declared"; exit 1; }
grep -q 'refusing to publish' "$W" || { echo "FAIL: no enforcement"; exit 1; }
# S448: the edit set and the guard set must be the same expression, not a list
grep -q 'LOGINUID_RE=' "$W" || { echo "FAIL: no shared loginuid regex"; exit 1; }
# shellcheck disable=SC2016  # the dollar signs are literal source text we search for
{
grep -qF 'grep -rlE "$LOGINUID_RE" "$PAMD"' "$W" \
	|| { echo "FAIL: the edit loop is not driven by grep -rl"; exit 1; }
grep -qF 'grep -rEc "$LOGINUID_RE" "$PAMD"' "$W" \
	|| { echo "FAIL: the guard does not use the same regex"; exit 1; }
if grep -qF 'for f in "$PAMD/login"' "$W"; then
	echo "FAIL: hardcoded file list is back"; exit 1
fi
}
grep -qF '[prep] session_minimal=1 sessions=1 (pam_unix only)' "$W" \
	|| { echo "FAIL: session reduction is not declared"; exit 1; }
grep -qF '[prep] session_minimal=FAILED' "$W" \
	|| { echo "FAIL: session reduction cannot fail the job"; exit 1; }
grep -qF '[prep] pam_debug=session-lines' "$W" \
	|| { echo "FAIL: no pam debug declaration"; exit 1; }
# D26: every tier-B concession is declared and enforced
grep -qF 'refusing to publish' "$W" || { echo "FAIL: no enforcement"; exit 1; }
grep -qF "mem=\${{ inputs.mem_mb || '192' }}M" "$W" \
	|| { echo "FAIL: memory is not 192M by default"; exit 1; }
grep -qF '[prep] pam_debug=off' "$W" \
	|| { echo "FAIL: pam debug is not off by default"; exit 1; }
# S455b: the msys2 setup gets three attempts and declares which one won
grep -q 'id: msys1' "$W" || { echo "FAIL: no first msys attempt id"; exit 1; }
grep -q 'id: msys3' "$W" || { echo "FAIL: no third attempt"; exit 1; }
grep -qF '[infra] msys2-setup-failed-after-3-attempts' "$W" 	|| { echo "FAIL: no infrastructure verdict"; exit 1; }
grep -qF '[infra] msys=ok' "$W" || { echo "FAIL: the log does not declare the attempt"; exit 1; }
# S456: the symbolizer must read the log the artifact carries, not ./systemd.log
grep -qF "find . -name systemd.log" "$W" || { echo "FAIL: symbolizer cannot find the log"; exit 1; }
grep -qF '[infra] sym=skipped(no-fault)' "$W" \
	|| { echo "FAIL: no-fault is not distinguished from no-file"; exit 1; }
grep -qF "grep -oE '\\[av\\]" "$W" || grep -qF '[av]' "$W" \
	|| { echo "FAIL: first-chance rips are not symbolized"; exit 1; }
grep -qF "stack\\[[0-9.]+\\]" "$W" \
	|| { echo "FAIL: stack return addresses are not symbolized"; exit 1; }
# S472: the referee needs room past the push; the bound is part of the contract
grep -qF "|| '1500' }} ./launcher.exe" "$W" || { echo "FAIL: boot bound is not 1500s"; exit 1; }
grep -qF 'timeout-minutes: 30' "$W" || { echo "FAIL: GitHub backstop not raised"; exit 1; }
echo "nss_prep: no trailing comments, both accounts resolved by the image itself"
