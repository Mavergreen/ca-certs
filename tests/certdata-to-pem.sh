#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #2 and #3 -- website-trusted roots only, and none past a distrust-after date
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/capem.XXXXXX")"
trap 'rm -rf "$T"' EXIT
# platform: 10.9's /usr/bin/awk is BWK awk 20070501
AWK=awk; [ -x /usr/bin/awk ] && AWK=/usr/bin/awk
P="$R/build/certdata-to-pem.awk"

out="$("$AWK" -v now=20260925000000 -f "$P" "$R/tests/fixtures/certdata-mini.txt" 2>"$T/err")" \
  || fail "parser failed on the fixture: $(cat "$T/err")"
want="$(printf '%s\n' '# Trusted Root' '-----BEGIN CERTIFICATE-----' 'MAMCAQA=' '-----END CERTIFICATE-----' \
  '# Future Date Root' '-----BEGIN CERTIFICATE-----' 'MAA=' '-----END CERTIFICATE-----')"
[ "$out" = "$want" ] || fail "fixture output was:
$out"
grep -q 'left out "Passed Date Root"' "$T/err" || fail "must say it left out a root whose distrust-after date has passed"
if grep -q 'Email Only Root' "$T/err"; then fail "a root not trusted for websites is simply not a website root; it is not reported"; fi

"$AWK" -v now=20000101000000 -f "$P" "$R/tests/fixtures/certdata-mini.txt" > "$T/early" 2>/dev/null \
  || fail "parser failed with now=2000"
grep -c 'BEGIN CERTIFICATE' "$T/early" | grep -q '^3$' || fail "before its date passes, a dated root is still trusted"

if "$AWK" -f "$P" "$R/tests/fixtures/certdata-mini.txt" >/dev/null 2>&1; then fail "a missing now= must be refused"; fi
if "$AWK" -v now=2026 -f "$P" "$R/tests/fixtures/certdata-mini.txt" >/dev/null 2>&1; then fail "a malformed now= must be refused"; fi

sed '/CKO_NSS_TRUST/,$d' "$R/tests/fixtures/certdata-mini.txt" > "$T/orphan.txt"
if "$AWK" -v now=20260925000000 -f "$P" "$T/orphan.txt" >/dev/null 2>"$T/err2"; then
  fail "a certificate with no trust object must fail the parse"
fi
grep -q 'no trust object for "Trusted Root"' "$T/err2" || fail "the orphan must be named: $(cat "$T/err2")"
echo "certdata-to-pem: ok"
