#!/bin/sh
# platform: host-agnostic
#   usage: build-bundle.sh
#          Writes this release's trust data to $CA_BUILD/data:
#            ca-certificates.crt  every root Mozilla trusts for websites, each after "# label"
#            trusted/SHA1.pem     the same roots, one file each, named by SHA-1 for the applier
#            ca-certificates.sha1 the SHA-1 of each root in ca-certificates.crt, in its order
#            distrust/SHA1.pem    one per withdrawn.md row, from withdrawn/SHA256.pem
#            roots.txt            "trusted|distrusted SHA256 label", sorted, for release notes
#            aquatransport-roots.txt  the roots AquaTransport's root component claims, as committed
# spec: tests/bundle-sanity.sh
set -eu
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
D="${CA_BUILD:?}/data"
rm -rf "$D"
mkdir -p "$D/trusted" "$D/distrust" "$D/split"
sh "$MAVERICKS_ROOT/build/fetch-certdata.sh" "$D"
awk -v now="$(date -u +%Y%m%d%H%M%S)" -f "$MAVERICKS_ROOT/build/certdata-to-pem.awk" \
  "$D/certdata.txt" > "$D/ca-certificates.crt" || build_die "certdata-to-pem failed"
awk -v d="$D/split" '
  /^# / { lab = substr($0, 3) }
  /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%04d.pem", d, n); print lab > (f ".label"); close(f ".label") }
  f { print > f }
  /-----END CERTIFICATE-----/ { close(f); f = "" }
' "$D/ca-certificates.crt"
: > "$D/roots.unsorted"
: > "$D/ca-certificates.sha1"
for c in "$D"/split/*.pem; do
  s1="$(ca_fingerprint sha1 "$c")" || build_die "$c does not parse"
  s256="$(ca_fingerprint sha256 "$c")" || build_die "$c does not parse"
  cp "$c" "$D/trusted/$s1.pem"
  printf '%s\n' "$s1" >> "$D/ca-certificates.sha1"
  printf 'trusted %s %s\n' "$s256" "$(cat "$c.label")" >> "$D/roots.unsorted"
done
sed -n 's/^| \(.*\) | `\([0-9A-F]\{64\}\)` | .*/\2 \1/p' "$MAVERICKS_ROOT/withdrawn.md" > "$D/withdrawn.rows"
[ -s "$D/withdrawn.rows" ] || build_die "withdrawn.md lists no roots"
while read -r s256 name; do
  f="$MAVERICKS_ROOT/withdrawn/$s256.pem"
  [ -f "$f" ] || build_die "withdrawn.md lists $name ($s256) but withdrawn/$s256.pem is missing"
  s1="$(ca_fingerprint sha1 "$f")" || build_die "$f does not parse"
  [ ! -f "$D/trusted/$s1.pem" ] || build_die "$name is trusted by Mozilla and listed in withdrawn.md"
  cp "$f" "$D/distrust/$s1.pem"
  printf 'distrusted %s %s\n' "$s256" "$name" >> "$D/roots.unsorted"
done < "$D/withdrawn.rows"
sort "$D/roots.unsorted" > "$D/roots.txt"
cp "$MAVERICKS_ROOT/aquatransport-roots.txt" "$D/aquatransport-roots.txt"
sh "$MAVERICKS_ROOT/build/aquatransport-conflicts.sh" "$D/aquatransport-roots.txt" "$D/trusted" "$D/distrust" \
  || build_die "AquaTransport's root list disagrees with this release (above)"
rm -rf "$D/split" "$D/roots.unsorted" "$D/withdrawn.rows"
echo "build-bundle: $(grep -c '^trusted ' "$D/roots.txt") trusted, $(grep -c '^distrusted ' "$D/roots.txt") distrusted" >&2
