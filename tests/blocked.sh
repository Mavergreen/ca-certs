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
done
# spec: docs/TRUST-POLICY.md #14 -- a blocked certificate may be self-signed (OneCRL blocks a few roots,
#       two of them roots 10.9 ships), but never one ca-certs trusts. That needs certdata.txt, which this
#       test doesn't download: build/build-bundle.sh dies on it at every build.
for f in "$R"/blocked/*.pem; do
  s="$(basename "$f" .pem)"
  printf '%s\n' "$rows" | grep -q "^$s\$" || fail "blocked/$s.pem has no row in blocked.md"
done
unbugged="$(sed -n 's/^| \(.*\) | `\([0-9A-F]\{64\}\)` | \(.*\) | [0-9]* |$/\2 \3/p' "$R/blocked.md" \
  | grep -v -e ' \[[0-9][0-9]*\](https://bugzilla\.mozilla\.org/show_bug\.cgi?id=[0-9][0-9]*)' \
            -e ' \[OneCRL\](https://firefox\.settings\.services\.mozilla\.com/v1/buckets/security-state/collections/onecrl/records/[0-9a-z-][0-9a-z-]*)' || :)"
[ -z "$unbugged" ] || fail "each blocked.md row must cite the Mozilla bug behind its OneCRL entry, or the entry itself; these don't:
$unbugged"

# spec: build/onecrl.py -- blocked.entries carries each row's SHA-1, issuer and serial for the applier
E="$R/blocked.entries"
[ -f "$E" ] || fail "blocked.entries is missing"
[ "$(grep -v '^#' "$E" | awk '{ print $1 }')" = "$(printf '%s\n' "$rows" | LC_ALL=C sort)" ] \
  || fail "blocked.entries must have exactly one line per blocked.md row, sorted by SHA-256"
bad="$(grep -v '^#' "$E" | awk 'NF != 4 || length($2) != 40')"
[ -z "$bad" ] || fail "blocked.entries has lines that are not 'SHA256 SHA1 ISSUER SERIAL':
$bad"
wrong="$(grep -v '^#' "$E" | while read -r s256 s1 _; do
  got="$(openssl x509 -noout -fingerprint -sha1 -in "$R/blocked/$s256.pem" | sed 's/.*=//' | tr -d :)"
  [ "$got" = "$s1" ] || echo "$s256 has $s1, but its PEM's SHA-1 is $got"
done)"
[ -z "$wrong" ] || fail "blocked.entries gives the wrong SHA-1:
$wrong"

echo "blocked: ok ($(printf '%s\n' "$rows" | wc -l | tr -d ' ') certificates)"
