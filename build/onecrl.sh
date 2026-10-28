#!/bin/sh
# platform: CI-only -- python3
#   usage: onecrl.sh [--allow-mass-removal]
#          Downloads OneCRL and CCADB's two intermediate reports, then regenerates blocked.md,
#          blocked/ and blocked.entries from them with onecrl.py, as of today in UTC. Exits 1,
#          having written nothing, when a download fails or a guard trips.
# spec: tests/onecrl.sh, docs/TRUST-POLICY.md #14
set -eu
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/onecrl.XXXXXX")"
trap 'rm -rf "$T"' EXIT
. "$SHIPYARD/mavericks_fetch.sh"
ONECRL=https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records
CCADB=https://ccadb.my.salesforce-sites.com/mozilla
shipyard_curl "$ONECRL" "$T/onecrl.json" || build_die "could not download $ONECRL"
shipyard_curl "$CCADB/PublicIntermediateCertsRevokedWithPEMCSV" "$T/revoked.csv" || build_die "could not download CCADB's revoked intermediates"
shipyard_curl "$CCADB/PublicAllIntermediateCertsWithPEMCSV" "$T/all.csv" || build_die "could not download CCADB's intermediates"
python3 -I "$MAVERICKS_ROOT/build/onecrl.py" --onecrl "$T/onecrl.json" --ccadb "$T/revoked.csv" --ccadb "$T/all.csv" \
  --now "$(date -u +%Y-%m-%d)" --repo "$MAVERICKS_ROOT" "$@"
