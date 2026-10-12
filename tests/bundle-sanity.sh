#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #2 and #5 -- the generated data is what the product installs; check it before it ships
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
: "${MAVERICKS_BUILD_ROOT:=${TMPDIR:-/tmp}/mm-build}"
D="$MAVERICKS_BUILD_ROOT/$(basename "$R")/data"
[ -s "$D/ca-certificates.crt" ] || { echo "bundle-sanity: not built (sh build/build-bundle.sh) -- skipping"; exit 77; }
n="$(grep -c 'BEGIN CERTIFICATE' "$D/ca-certificates.crt")"
[ "$n" -ge 100 ] && [ "$n" -le 250 ] || fail "$n roots is outside 100-250; Mozilla trusted 121 in NSS 3.130"
t="$(ls "$D/trusted" | grep -c '\.pem$')"
[ "$t" = "$n" ] || fail "trusted/ has $t files for $n roots in the bundle"
for f in "$D"/trusted/*.pem "$D"/distrust/*.pem; do
  s="$(openssl x509 -noout -fingerprint -sha1 -in "$f" | sed 's/.*=//' | tr -d :)" || fail "$f does not parse"
  [ "$(basename "$f" .pem)" = "$s" ] || fail "$f is named for another certificate (its SHA-1 is $s)"
done
for f in "$D"/distrust/*.pem; do
  [ ! -f "$D/trusted/$(basename "$f")" ] || fail "$(basename "$f") is both trusted and distrusted"
done
[ "$(grep -c '^trusted ' "$D/roots.txt")" = "$n" ] || fail "roots.txt does not list every trusted root"
[ "$(grep -c '^distrusted ' "$D/roots.txt")" = "$(ls "$D/distrust" | grep -c '\.pem$')" ] || fail "roots.txt does not list every distrusted root"
cmp -s "$D/aquatransport-roots.txt" "$R/aquatransport-roots.txt" || fail "the build must carry aquatransport-roots.txt as committed"
echo "bundle-sanity: ok ($n trusted)"
