#!/bin/sh
# platform: host-agnostic
# spec: INGREDIENTS.md -- Renovate orders NSS_x_y[_z]_RTM tags only with this regex versioning
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
J="$R/.github/renovate.json"
[ -f "$J" ] || fail "no .github/renovate.json"
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys,json; json.load(open(sys.argv[1]))' "$J" || fail "renovate.json is not valid JSON"
fi
grep -q '"github>Mavergreen/shipyard"' "$J" || fail "must extend the shipyard preset"
grep -q '"/^NSS_TAG\$/"' "$J" || fail "must match the NSS_TAG file"
grep -q '"packageNameTemplate": "mozilla/nss"' "$J" || fail "must track mozilla/nss"
grep -q '"datasourceTemplate": "github-tags"' "$J" || fail "must use github-tags"
grep -q 'regex:^NSS_(?<major>' "$J" || fail "must order tags with regex versioning, or NSS_3_126_1_RTM and NSS_3_130_RTM compare as strings"
if grep -q -E '"ignoreTests"|"automerge"' "$J"; then fail "the shipyard preset sets automerge and ignoreTests; restating them is check 4's failure"; fi
echo "renovate: ok"
