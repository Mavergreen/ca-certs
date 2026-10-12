#!/bin/sh
# platform: macOS-only -- pkgutil expands the built pkg
# spec: README.md "For other Mavergreen products" -- the bundle path is a contract; and the hook must be a real file
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
PKG="$(ls "${DIST:-/nonexistent}"/ca-certs-*.pkg 2>/dev/null | head -n 1)"
[ -n "$PKG" ] || { echo "package-pkg: no DIST/ca-certs-*.pkg -- skipping"; exit 77; }
T="$(mktemp -d "${TMPDIR:-/tmp}/capkg.XXXXXX")"
trap 'rm -rf "$T"' EXIT
pkgutil --expand "$PKG" "$T/x" >/dev/null || fail "pkgutil could not expand $PKG"
for c in "$T"/x/*.pkg; do
  [ -f "$c/Payload" ] || continue
  mkdir "$c.root" && (cd "$c.root" && gunzip -c "$c/Payload" | cpio -id 2>/dev/null) || fail "could not unpack $c"
done
tree="$(find "$T/x" -type d -path '*.root/usr/local/mavergreen/ca-certs' | head -n 1)"
post="$(find "$T/x" -type f -path '*/Scripts/postinstall' | head -n 1)"
[ -n "$tree" ] || fail "no usr/local/mavergreen/ca-certs in the payload"
[ -s "$tree/etc/openssl/certs/ca-certificates.crt" ] || fail "the reserved bundle path is empty or missing"
h="$tree/libexec/mavergreen/pre-uninstall"
[ -f "$h" ] && [ ! -h "$h" ] && [ -x "$h" ] || fail "the uninstall hook must be an executable regular file (shipyard refuses a symlink)"
[ -x "$tree/libexec/ca-certs-apply" ] || fail "the applier is missing or not executable"
[ -f "$tree/mavergreen.plist" ] || fail "no manifest"
grep -q 'ca-certs-apply' "$post" || fail "the postinstall does not run the applier"
n="$(grep -c 'BEGIN CERTIFICATE' "$tree/etc/openssl/certs/ca-certificates.crt")"
[ "$(ls "$tree/share/ca-certs/trusted" | grep -c '\.pem$')" = "$n" ] || fail "per-root files and the bundle disagree"
cmp -s "$tree/share/ca-certs/aquatransport-roots.txt" "$R/aquatransport-roots.txt" \
  || fail "the pkg must carry aquatransport-roots.txt as committed: the applier and uninstall read it to leave AquaTransport's roots alone"
cmp -s "$tree/share/ca-certs/ca-certificates.crt" "$tree/etc/openssl/certs/ca-certificates.crt" \
  || fail "the pkg must ship the bundle a second time, in share/, so the applier can rebuild the contract copy from it"
[ "$(wc -l < "$tree/share/ca-certs/ca-certificates.sha1" | tr -d ' ')" = "$n" ] || fail "the pkg must ship ca-certificates.sha1, one SHA-1 per certificate"
echo "package-pkg: ok ($n roots)"
