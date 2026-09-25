#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #5 -- withdrawn.md is the authority; withdrawn/ holds exactly its certificates
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
rows="$(sed -n 's/^| .* | `\([0-9A-F]\{64\}\)` | .*/\1/p' "$R/withdrawn.md")"
[ -n "$rows" ] || fail "withdrawn.md lists no roots"
for s in $rows; do
  f="$R/withdrawn/$s.pem"
  [ -f "$f" ] || fail "withdrawn.md lists $s but withdrawn/$s.pem is missing"
  got="$(openssl x509 -noout -fingerprint -sha256 -in "$f" | sed 's/.*=//' | tr -d :)" || fail "$f does not parse"
  [ "$got" = "$s" ] || fail "withdrawn/$s.pem holds a certificate whose SHA-256 is $got"
done
for f in "$R"/withdrawn/*.pem; do
  s="$(basename "$f" .pem)"
  printf '%s\n' "$rows" | grep -q "^$s\$" || fail "withdrawn/$s.pem has no row in withdrawn.md"
done
echo "withdrawn: ok ($(printf '%s\n' "$rows" | wc -l | tr -d ' ') roots)"
