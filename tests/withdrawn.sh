#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #5 and #7 -- withdrawn.md is the authority; withdrawn/ holds exactly its certificates, none of them Apple's
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

# spec: docs/TRUST-POLICY.md #7 -- a root is Apple's when Apple is its subject's organization: Apple
#       Root CA and its G2 and G3 say "Apple Inc.", the 2005 Apple Root Certificate Authority "Apple Computer, Inc."
apple_roots_in() {  # DIR: each certificate in it whose subject organization is Apple's
  for _f in "$1"/*.pem; do
    [ -f "$_f" ] || continue
    _o="$(openssl x509 -noout -subject -nameopt RFC2253 -in "$_f")" || fail "$_f does not parse"
    case "$_o" in *"O=Apple Inc."*|*"O=Apple Computer\\, Inc."*) basename "$_f" .pem ;; esac
  done
}
T="$(mktemp -d "${TMPDIR:-/tmp}/cawd.XXXXXX")"
trap 'rm -rf "$T"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key" -out "$T/apple.pem" -days 2 \
  -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key" -out "$T/apple2005.pem" -days 2 \
  -subj "/C=US/O=Apple Computer, Inc./OU=Apple Computer Certificate Authority/CN=Apple Root Certificate Authority" >/dev/null 2>&1
[ "$(apple_roots_in "$T" | sort | tr '\n' ' ')" = "apple apple2005 " ] || fail "the check must recognize both of Apple's subject spellings: got '$(apple_roots_in "$T")'"
a="$(apple_roots_in "$R/withdrawn")"
[ -z "$a" ] || fail "withdrawn/ distrusts Apple's own roots, which #7 never does: $a"

echo "withdrawn: ok ($(printf '%s\n' "$rows" | wc -l | tr -d ' ') roots)"
