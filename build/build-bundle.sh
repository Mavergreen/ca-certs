#!/bin/sh
# platform: host-agnostic
#   usage: build-bundle.sh
#          Writes this release's trust data to $CA_BUILD/data:
#            ca-certificates.crt  every root Mozilla trusts for websites, each after "# label"
#            trusted/SHA1.pem     the same roots, one file each, named by SHA-1 for the applier
#            ca-certificates.sha1 the SHA-1 of each root in ca-certificates.crt, in its order
#            distrust/SHA1.pem    one per withdrawn.md row, from withdrawn/SHA256.pem
#            blocked/SHA1.pem     one per blocked.md row, from blocked/SHA256.pem
#            blocked.entries      "SHA1 ISSUER_B64 SERIAL_B64" per blocked certificate, sorted by SHA-1
#            roots.txt            "trusted|distrusted|blocked SHA256 label", sorted, for release notes
#            aquatransport-roots.txt  the roots AquaTransport's root component claims, as committed
# spec: tests/bundle-sanity.sh
set -eu
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
D="${CA_BUILD:?}/data"
rm -rf "$D"
mkdir -p "$D/trusted" "$D/distrust" "$D/blocked" "$D/split"
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
: > "$D/blocked.sha1s"
for c in "$D"/split/*.pem; do
  s1="$(ca_fingerprint sha1 "$c")" || build_die "$c does not parse"
  s256="$(ca_fingerprint sha256 "$c")" || build_die "$c does not parse"
  cp "$c" "$D/trusted/$s1.pem"
  printf '%s\n' "$s1" >> "$D/ca-certificates.sha1"
  printf 'trusted %s %s\n' "$s256" "$(cat "$c.label")" >> "$D/roots.unsorted"
done
# spec: docs/TRUST-POLICY.md #14 -- withdrawn roots are distrusted by the applier; blocked intermediates by issuer and serial. Both
#       are refused if Mozilla trusts them.
for list in withdrawn blocked; do
  sed -n 's/^| \(.*\) | `\([0-9A-F]\{64\}\)` | .*/\2 \1/p' "$MAVERICKS_ROOT/$list.md" > "$D/$list.rows"
  [ -s "$D/$list.rows" ] || build_die "$list.md lists nothing"
  case "$list" in withdrawn) dest=distrust; kind=distrusted;; blocked) dest=blocked; kind=blocked;; esac
  while read -r s256 name; do
    f="$MAVERICKS_ROOT/$list/$s256.pem"
    [ -f "$f" ] || build_die "$list.md lists $name ($s256) but $list/$s256.pem is missing"
    s1="$(ca_fingerprint sha1 "$f")" || build_die "$f does not parse"
    [ ! -f "$D/trusted/$s1.pem" ] || build_die "$name is trusted by Mozilla and listed in $list.md"
    # spec: docs/TRUST-POLICY.md #5 and #14 -- withdrawn roots and blocked intermediates are applied and recorded apart, so one certificate can't be both
    [ "$list" != blocked ] || [ ! -f "$D/distrust/$s1.pem" ] || build_die "$name is listed in both withdrawn.md and blocked.md"
    cp "$f" "$D/$dest/$s1.pem"
    printf '%s %s %s\n' "$kind" "$s256" "$name" >> "$D/roots.unsorted"
    [ "$list" != blocked ] || printf '%s %s\n' "$s256" "$s1" >> "$D/blocked.sha1s"
  done < "$D/$list.rows"
done
# spec: docs/TRUST-POLICY.md #14 -- blocked.entries: SHA1 ISSUER_B64 SERIAL_B64, from the committed SHA256-keyed list
awk 'NR == FNR { sha1[$1] = $2; next }
     /^#/ || NF == 0 { next }
     !($1 in sha1) { print "blocked.entries has no blocked.md row for " $1 > "/dev/stderr"; bad = 1; next }
     { print sha1[$1], $3, $4; seen[$1] = 1 }
     END { for (k in sha1) if (!(k in seen)) { print "blocked.md row " k " has no line in blocked.entries" > "/dev/stderr"; bad = 1 }
           exit bad }' "$D/blocked.sha1s" "$MAVERICKS_ROOT/blocked.entries" > "$D/blocked.unsorted" \
  || build_die "blocked.entries and blocked.md disagree (above)"
sort "$D/blocked.unsorted" > "$D/blocked.entries"
sort "$D/roots.unsorted" > "$D/roots.txt"
cp "$MAVERICKS_ROOT/aquatransport-roots.txt" "$D/aquatransport-roots.txt"
sh "$MAVERICKS_ROOT/build/aquatransport-conflicts.sh" "$D/aquatransport-roots.txt" "$D/trusted" "$D/distrust" "$D/blocked" \
  "$MAVERICKS_ROOT/aquatransport-differences.txt" \
  || build_die "AquaTransport's root list disagrees with this release (above)"
rm -rf "$D/split" "$D/roots.unsorted" "$D/withdrawn.rows" "$D/blocked.rows" "$D/blocked.sha1s" "$D/blocked.unsorted"
echo "build-bundle: $(grep -c '^trusted ' "$D/roots.txt") trusted, $(grep -c '^distrusted ' "$D/roots.txt") distrusted, $(grep -c '^blocked ' "$D/roots.txt") blocked" >&2
