#!/usr/bin/env bash
# S460: the feed must tell its own story, stage by stage.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U="$HERE/../kernel/overlay/arch/um/os-Windows/util.c"
C="$HERE/../kernel/overlay/arch/um/os-Windows/console.c"

grep -q '\[feed-stage\] from=%d to=%d anchor=' "$U" \
	|| { echo "FAIL: no stage transition line"; exit 1; }
grep -q '\[LOGIN-OK\] guest printed the marker' "$U" \
	|| { echo "FAIL: the marker is not declared"; exit 1; }
grep -q 'static int g_login_ok_seen' "$U" \
	|| { echo "FAIL: no once-only flag"; exit 1; }
# stage payloads: user, password, then the marker command
grep -q '"echo LOGIN-OK\\n"' "$C" || { echo "FAIL: stage 3 payload missing"; exit 1; }
grep -q '"root\\n", "root\\n"' "$C" || { echo "FAIL: user/password stages missing"; exit 1; }
echo "feed_stage: transitions declared, marker declared once, payloads intact"
