#!/bin/sh
# platform: host-agnostic
#   usage: aquatransport-conflicts.sh LIST TRUSTED_DIR DISTRUST_DIR
#          Exits 1, naming each root, when LIST (aquatransport-roots.txt) trusts a root
#          DISTRUST_DIR holds or distrusts one TRUSTED_DIR holds (files named SHA1.pem, as
#          build-bundle.sh writes them).
# spec: tests/aquatransport-roots.sh, docs/TRUST-POLICY.md #12
set -eu
[ $# -eq 3 ] && [ -f "$1" ] && [ -d "$2" ] && [ -d "$3" ] \
  || { echo "usage: aquatransport-conflicts.sh LIST TRUSTED_DIR DISTRUST_DIR" >&2; exit 2; }
bad="$(grep -E '^(trust|distrust) ' "$1" | while read -r kind sha label; do
  if [ "$kind" = trust ] && [ -f "$3/$sha.pem" ]; then echo "  AquaTransport trusts $sha ($label), which we distrust"; fi
  if [ "$kind" = distrust ] && [ -f "$2/$sha.pem" ]; then echo "  AquaTransport distrusts $sha ($label), which we trust"; fi
done)"
[ -z "$bad" ] || { printf 'aquatransport-conflicts: we and AquaTransport disagree; decide each in docs/TRUST-POLICY.md #12 before shipping:\n%s\n' "$bad" >&2; exit 1; }
