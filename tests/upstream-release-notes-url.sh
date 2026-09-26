#!/bin/sh
# platform: host-agnostic
# spec: INGREDIENTS.md "Release notes" -- NSS addresses notes by its own spelling
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
H="$R/build/upstream-release-notes-url.sh"
[ "$(sh "$H" 3.130.0)" = https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_130.html ] \
  || fail "3.130.0 must link nss_3_130.html (verified 200 on 2026-09-25; nss_3_130_0.html is a 404)"
[ "$(sh "$H" 3.126.1)" = https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_126_1.html ] \
  || fail "3.126.1 must link nss_3_126_1.html"
if sh "$H" >/dev/null 2>&1; then fail "no argument must be refused"; fi
echo "upstream-release-notes-url: ok"
