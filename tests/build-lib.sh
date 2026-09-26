#!/bin/sh
# platform: host-agnostic
# spec: claude-plugins/mavergreen/skills/mavergreen-conventions/SKILL.md "Build OUT of the source tree" -- keyed by checkout, so two checkouts never share a build directory
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/calib.XXXXXX")"
trap 'rm -rf "$T"' EXIT

build_dir_of() {  # CHECKOUT: the CA_BUILD that build/lib.sh gives a checkout at that path
  mkdir -p "$1/build"
  cp "$R/build/lib.sh" "$R/build/msc.sh" "$1/build/"
  (MAVERICKS_ROOT="$1"; MAVERICKS_BUILD_ROOT="$T/mmb"; . "$1/build/lib.sh"; printf '%s\n' "$CA_BUILD")
}

scenario "two checkouts of ca-certs get two build directories, both under MAVERICKS_BUILD_ROOT"
a="$(build_dir_of "$T/one/mavergreen-ca-certs")"
b="$(build_dir_of "$T/two/ca-certs-review")"
[ "$a" != "$b" ] || fail "both checkouts build in $a: one would overwrite the other's trust data and updater"
case "$a" in "$T/mmb/"?*) ;; *) fail "CA_BUILD is $a, not under MAVERICKS_BUILD_ROOT ($T/mmb)" ;; esac
case "$b" in "$T/mmb/"?*) ;; *) fail "CA_BUILD is $b, not under MAVERICKS_BUILD_ROOT ($T/mmb)" ;; esac

echo "build-lib: ok"
