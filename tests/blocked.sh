#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #14 -- blocked.md is the authority; blocked/ holds exactly its certificates, each an intermediate Mozilla's OneCRL blocks
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
[ -f "$R/blocked.md" ] || fail "blocked.md is missing"
rows="$(sed -n 's/^| .* | `\([0-9A-F]\{64\}\)` | .*/\1/p' "$R/blocked.md")"
[ -n "$rows" ] || fail "blocked.md lists no certificates"
for s in $rows; do
  f="$R/blocked/$s.pem"
  [ -f "$f" ] || fail "blocked.md lists $s but blocked/$s.pem is missing"
  got="$(openssl x509 -noout -fingerprint -sha256 -in "$f" | sed 's/.*=//' | tr -d :)" || fail "$f does not parse"
  [ "$got" = "$s" ] || fail "blocked/$s.pem holds a certificate whose SHA-256 is $got"
  [ "$(openssl x509 -noout -subject -nameopt RFC2253 -in "$f")" != "subject=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$f" | sed 's/^issuer=//')" ] \
    || fail "blocked/$s.pem is self-signed: a root Mozilla withdrew belongs in withdrawn.md"
done
for f in "$R"/blocked/*.pem; do
  s="$(basename "$f" .pem)"
  printf '%s\n' "$rows" | grep -q "^$s\$" || fail "blocked/$s.pem has no row in blocked.md"
done
grep -q 'https://bugzilla.mozilla.org/show_bug.cgi?id=[0-9]' "$R/blocked.md" || fail "blocked.md must cite the Mozilla bug behind each OneCRL entry"

echo "blocked: ok ($(printf '%s\n' "$rows" | wc -l | tr -d ' ') certificates)"
