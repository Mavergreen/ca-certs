#!/bin/sh
# platform: host-agnostic
#   usage: upstream-release-notes-url.sh <upstream-version>      (3.130.0, 3.126.1)
#          Prints NSS's release notes page for that version. NSS spells 3.130.0 as 3.130.
# spec: tests/upstream-release-notes-url.sh
set -eu
v="${1:?usage: upstream-release-notes-url.sh <upstream-version>}"
case "$v" in *.*.0) v="${v%.0}" ;; esac
printf 'https://firefox-source-docs.mozilla.org/security/nss/releases/nss_%s.html\n' "$(printf '%s' "$v" | tr . _)"
