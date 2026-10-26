#!/bin/sh
# platform: host-agnostic
#   usage: aquatransport-conflicts.sh LIST TRUSTED_DIR DISTRUST_DIR DIFFERENCES
#          Exits 1, naming each root, unless AquaTransport's choices (LIST, aquatransport-roots.txt)
#          are a subset of ours: every root it trusts is in TRUSTED_DIR and every root it distrusts
#          is in DISTRUST_DIR (files named SHA1.pem, as build-bundle.sh writes them). A root it
#          trusts that we distrust, or the other way round, always fails. Any other root outside
#          our set fails unless DIFFERENCES (aquatransport-differences.txt) has a "trust|distrust
#          SHA1 reason" line for it, and a DIFFERENCES line that excuses nothing fails too.
# spec: tests/aquatransport-roots.sh, docs/TRUST-POLICY.md #12
set -eu
[ $# -eq 4 ] && [ -f "$1" ] && [ -d "$2" ] && [ -d "$3" ] && [ -f "$4" ] \
  || { echo "usage: aquatransport-conflicts.sh LIST TRUSTED_DIR DISTRUST_DIR DIFFERENCES" >&2; exit 2; }
DIFFS="$4"
noreason="$(awk '!/^#/ && NF && NF < 3 { print "  " $0 }' "$DIFFS")"
[ -z "$noreason" ] || { printf 'aquatransport-conflicts: each difference in %s needs a reason:\n%s\n' "$DIFFS" "$noreason" >&2; exit 1; }
declared() { awk -v k="$1" -v s="$2" '!/^#/ && $1 == k && $2 == s { f = 1 } END { exit !f }' "$DIFFS"; }
bad="$(grep -E '^(trust|distrust) ' "$1" | while read -r kind sha label; do
  if [ "$kind" = trust ] && [ -f "$3/$sha.pem" ]; then echo "  AquaTransport trusts $sha ($label), which we distrust"
  elif [ "$kind" = distrust ] && [ -f "$2/$sha.pem" ]; then echo "  AquaTransport distrusts $sha ($label), which we trust"
  elif [ "$kind" = trust ] && [ ! -f "$2/$sha.pem" ] && ! declared trust "$sha"; then echo "  AquaTransport trusts $sha ($label), which we don't: declare it in DIFFERENCES or trust it"
  elif [ "$kind" = distrust ] && [ ! -f "$3/$sha.pem" ] && ! declared distrust "$sha"; then echo "  AquaTransport distrusts $sha ($label), which we don't: declare it in DIFFERENCES or distrust it"
  fi
done)"
stale="$(awk '!/^#/ && NF { print $1, $2 }' "$DIFFS" | while read -r kind sha; do
  dir="$2"; [ "$kind" = distrust ] && dir="$3"
  if [ -f "$dir/$sha.pem" ] || ! grep -q "^$kind $sha " "$1"; then echo "  $kind $sha no longer differs from AquaTransport's list: remove it"; fi
done)"
bad="$bad${bad:+${stale:+
}}$stale"
[ -z "$bad" ] || { printf 'aquatransport-conflicts: AquaTransport'"'"'s choices are not a subset of ours; decide each in docs/TRUST-POLICY.md #12 before shipping:\n%s\n' "$bad" >&2; exit 1; }
