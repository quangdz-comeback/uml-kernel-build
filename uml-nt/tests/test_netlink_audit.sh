#!/usr/bin/env bash
# S436: audit's netlink family must exist, or login dies in pam_loginuid.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="$HERE/../kernel/overlay/arch/um/configs/uml_nt_defconfig"
grep -q '^CONFIG_AUDIT=y' "$D" || { echo "FAIL: CONFIG_AUDIT not enabled"; exit 1; }
grep -q '^CONFIG_AUDITSYSCALL=y' "$D" || { echo "FAIL: CONFIG_AUDITSYSCALL not enabled"; exit 1; }
# netlink core rides CONFIG_NET, already required for the stack
grep -q '^CONFIG_NET=y' "$D" || { echo "FAIL: CONFIG_NET missing"; exit 1; }
grep -q 'NETLINK_AUDIT' "$D" || { echo "FAIL: no note explaining why"; exit 1; }
echo "netlink_audit: audit netlink family enabled, with the reason recorded"
