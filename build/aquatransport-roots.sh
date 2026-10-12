#!/bin/sh
# platform: macOS-only -- hdiutil and pkgutil read AquaTransport's DMG, as on the 10.9 box and the CI watcher
#   usage: aquatransport-roots.sh DMG
#          Prints the roots AquaTransport's "Modern Root Certificates" component trusts and
#          distrusts, as aquatransport-roots.txt lists them. Reads the DMG; runs nothing from it.
#          aquatransport-roots.sh --check LIST DMG
#          Exits 1, showing the difference, when the DMG's roots differ from LIST's. Headers are
#          not compared: a new AquaTransport with the same roots is no change.
# spec: tests/aquatransport-roots.sh, docs/TRUST-POLICY.md #12
set -eu
die() { echo "aquatransport-roots: $*" >&2; exit 2; }
ID=Wowfunhappy.AquaTransport.ModernRootCertificates

roots_in() {  # LIST: its trust and distrust lines, sorted
  grep -E '^(trust|distrust) ' "$1" | LC_ALL=C sort || :
}

check=""
if [ "${1:-}" = --check ]; then
  [ $# -eq 3 ] || die "usage: aquatransport-roots.sh --check LIST DMG"
  check="$2"; shift 2
fi
[ $# -eq 1 ] && [ -f "$1" ] || die "usage: aquatransport-roots.sh [--check LIST] DMG"
DMG="$1"

T="$(mktemp -d "${TMPDIR:-/tmp}/atroots.XXXXXX")"
mounted=no
cleanup() {
  if [ "$mounted" = yes ]; then hdiutil detach -quiet "$T/mnt" || hdiutil detach -quiet -force "$T/mnt" || :; fi
  rm -rf "$T"
}
trap cleanup EXIT
hdiutil attach -quiet -readonly -nobrowse -noautoopen -mountpoint "$T/mnt" "$DMG" || die "cannot attach $DMG"
mounted=yes
n=0
for p in "$T/mnt"/*.pkg; do
  [ -f "$p" ] || continue
  n=$((n + 1))
  pkgutil --expand "$p" "$T/x$n" || die "cannot expand $p"
done
[ "$n" -gt 0 ] || die "$DMG holds no .pkg"
comp=""
for info in "$T"/x*/*.pkg/PackageInfo; do
  [ -f "$info" ] || continue
  if grep -q "identifier=\"$ID\"" "$info"; then comp="${info%/PackageInfo}"; fi
done
[ -n "$comp" ] || die "$DMG has no $ID component"
ver="$(sed -n 's/.*<pkg-info[^>]* version="\([^"]*\)".*/\1/p' "$comp/PackageInfo" | head -n 1)"
[ -n "$ver" ] || die "cannot read $ID's version"
[ -d "$comp/Scripts/trust" ] && [ -d "$comp/Scripts/distrust" ] || die "$ID has no Scripts/trust and Scripts/distrust"

{
  for kind in trust distrust; do
    for c in "$comp/Scripts/$kind"/*.pem; do
      [ -f "$c" ] || continue
      sha="$(openssl x509 -noout -fingerprint -sha1 -in "$c" | sed 's/.*=//' | tr -d :)" || die "$c does not parse"
      [ -n "$sha" ] || die "$c does not parse"
      label="$(basename "$c" .pem)"
      printf '%s %s %s\n' "$kind" "$sha" "$label"
    done
  done
} | LC_ALL=C sort > "$T/roots"
[ -s "$T/roots" ] || die "$ID lists no roots"

if [ -n "$check" ]; then
  roots_in "$check" > "$T/listed"
  if diff "$T/listed" "$T/roots"; then exit 0; fi
  echo "aquatransport-roots: $ID $ver differs from $check (> is the DMG); regenerate it with build/aquatransport-roots.sh" >&2
  exit 1
fi
printf '# AquaTransport'"'"'s "Modern Root Certificates" component, %s %s,\n' "$ID" "$ver"
printf '# read from AquaTransport.dmg by build/aquatransport-roots.sh. docs/TRUST-POLICY.md #12 says what ca-certs does with it.\n'
cat "$T/roots"
