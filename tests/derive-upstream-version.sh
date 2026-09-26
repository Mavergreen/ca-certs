#!/bin/sh
# platform: host-agnostic
# spec: INGREDIENTS.md -- NSS spells 3.130 but means 3.130.0; three parts keep Sparkle's order
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/cadv.XXXXXX")"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/build"
cp "$R/build/derive-upstream-version.sh" "$T/build/"

good() {
  printf '%s\n' "$1" > "$T/NSS_TAG"
  got="$(sh "$T/build/derive-upstream-version.sh")" || fail "$1 was refused"
  [ "$got" = "$2" ] || fail "$1 printed '$got', want '$2'"
  [ "$(cat "$T/UPSTREAM_VERSION")" = "$2" ] || fail "$1 did not write UPSTREAM_VERSION=$2"
  sp="$(sh "$T/build/derive-upstream-version.sh" --nss-spelling)" || fail "$1 --nss-spelling was refused"
  [ "$sp" = "$3" ] || fail "$1 --nss-spelling printed '$sp', want '$3' (the tarball is named with it)"
}
good NSS_3_130_RTM 3.130.0 3.130
good NSS_3_126_1_RTM 3.126.1 3.126.1
good ' NSS_3_112_2_RTM ' 3.112.2 3.112.2

for bad in NSS_3_130_BETA1 NSS_3_RTM 3.130 NSS_3__1_RTM NSS_3_1_2_3_RTM NSS_3_1a_RTM ''; do
  printf '%s\n' "$bad" > "$T/NSS_TAG"
  rm -f "$T/UPSTREAM_VERSION"
  if sh "$T/build/derive-upstream-version.sh" >/dev/null 2>&1; then
    fail "'$bad' must be refused: it is not NSS_<major>_<minor>[_<patch>]_RTM"
  fi
  [ ! -f "$T/UPSTREAM_VERSION" ] || fail "'$bad' was refused but still wrote UPSTREAM_VERSION"
done
echo "derive-upstream-version: ok"
