#!/bin/sh
# platform: macOS-only -- installs a pkg, which on Mac OS X 10.x changes the running system's trust settings
# spec: docs/TRUST-POLICY.md #4, #6, #8, #9, #10, #13
#   usage: CA_CERTS_ONBOX=1 acceptance-onbox.sh PKG [PREVIOUS_PKG]
#          Installs PREVIOUS_PKG when given, then PKG over it, then reinstalls PKG and uninstalls.
#          On Mac OS X 10.x, while each is installed, every root it trusts must verify for TLS,
#          every root it distrusts must not, and every other root must verify as it did before.
#          On macOS 11 and later, every root must verify as it did before, throughout, and the
#          admin trust settings and System keychain must never change. Everywhere: the bundle at
#          its contract path is the shipped one less exactly the roots this Mac's admin trust
#          settings deny for TLS, the updater runs natively, and uninstall restores everything.
#          On failure it uninstalls whatever is installed, so the system is left as it was found.
set -eu
[ "${CA_CERTS_ONBOX:-}" = 1 ] || { echo "acceptance-onbox: set CA_CERTS_ONBOX=1 on a Mac whose trust settings it may change -- skipping"; exit 77; }
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
CA_ROOT="" . "$R/payload/libexec/ca-certs-lib.sh"
PKG="${1:?usage: CA_CERTS_ONBOX=1 acceptance-onbox.sh PKG [PREVIOUS_PKG]}"
PREV="${2:-}"
os="$(sw_vers -productVersion)"
case "$os" in 10.*) mode=trust ;; *) mode=bundle ;; esac
TREE=/usr/local/mavergreen/ca-certs
RECEIPT=/usr/local/mavergreen/var/ca-certs/receipt
UPDATER="/Library/Application Support/Mavergreen/ca-certs-updater.app/Contents/MacOS/ca-certs-updater"
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then hw=arm64; else hw=x86_64; fi
T="$(mktemp -d "${TMPDIR:-/tmp}/caonbox.XXXXXX")"
done=no
cleanup() {
  if [ "$done" = no ] && [ -e "$TREE" ]; then
    echo "acceptance-onbox: failed with ca-certs installed; uninstalling it" >&2
    sudo /usr/local/bin/mavergreen uninstall ca-certs >&2 || echo "acceptance-onbox: that uninstall failed too" >&2
  fi
}
trap cleanup EXIT

probe() { /usr/bin/curl --noproxy '*' -sS -o /dev/null -m 20 -w '%{http_code}' "https://$1/" 2>/dev/null || :; }
snap() {
  security dump-trust-settings -d > "$1.admin" 2>&1 || :
  security find-certificate -a -Z /Library/Keychains/System.keychain | grep '^SHA-1' | sort > "$1.kc"
}
roots_of() {  # PKG NAME: the pkg's trusted/ and distrust/ roots, in $T/NAME/{trusted,distrust}
  pkgutil --expand "$1" "$T/$2.x" >/dev/null || fail "cannot expand $1"
  mkdir -p "$T/$2.p"
  for pl in "$T/$2.x"/*/Payload; do
    ( cd "$T/$2.p" && gzip -dc "$pl" | cpio -id 2>/dev/null ) || fail "cannot unpack $pl"
  done
  s="$T/$2.p$TREE/share/ca-certs"
  [ -d "$s/trusted" ] && [ -d "$s/distrust" ] || fail "$1 carries no share/ca-certs/trusted and distrust"
  mkdir -p "$T/$2"; mv "$s/trusted" "$s/distrust" "$T/$2/"
  cp "$T/$2"/trusted/*.pem "$T/$2"/distrust/*.pem "$T/all/"
}
verdicts() {  # one line per root either release carries: NAME trusted|untrusted, for TLS
  for c in "$T"/all/*.pem; do
    if security verify-cert -c "$c" -p ssl >/dev/null 2>&1; then v=trusted; else v=untrusted; fi
    echo "$(basename "$c") $v"
  done
}
bundle_sha1s() {  # BUNDLE: the SHA-1 of each certificate in it, one per line, sorted
  rm -rf "$T/blk"; mkdir "$T/blk"
  awk -v d="$T/blk" '/-----BEGIN CERTIFICATE-----/ { f = sprintf("%s/%05d.pem", d, ++i) } f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' "$1"
  for c in "$T"/blk/*.pem; do
    [ -f "$c" ] || continue
    openssl x509 -noout -fingerprint -sha1 -in "$c" | sed 's/.*=//' | tr -d :
  done | LC_ALL=C sort
}
check_bundle() {  # LABEL RELEASE: the contract bundle is the shipped one, less exactly what this Mac denies for TLS
  shipped="$T/$2.p$TREE/etc/openssl/certs/ca-certificates.crt"
  idx="$T/$2.p$TREE/share/ca-certs/ca-certificates.sha1"
  sed -n 's/^bundle-omitted //p' "$RECEIPT" | LC_ALL=C sort > "$T/omitted"
  if [ ! -f "$idx" ]; then
    cmp -s "$shipped" "$TREE/etc/openssl/certs/ca-certificates.crt" || fail "after the $1, the bundle is not the one the pkg carries"
    [ ! -s "$T/omitted" ] || fail "after the $1, a release that ships no index left roots out: $(cat "$T/omitted")"
    return 0
  fi
  _x="$(security trust-settings-export -d "$T/admin.plist" >/dev/null 2>&1 && plutil -convert xml1 -o - "$T/admin.plist" || :)"
  printf '%s\n' "$_x" | ca_ssl_denied_in_xml | LC_ALL=C sort > "$T/denied"
  LC_ALL=C sort "$idx" > "$T/idx"
  comm -12 "$T/idx" "$T/denied" > "$T/want-omitted"
  diff "$T/want-omitted" "$T/omitted" >&2 || fail "after the $1, the receipt's bundle-omitted roots are not exactly the bundle's roots this Mac denies for TLS (diff above)"
  comm -23 "$T/idx" "$T/omitted" > "$T/want-in"
  bundle_sha1s "$TREE/etc/openssl/certs/ca-certificates.crt" > "$T/in"
  diff "$T/want-in" "$T/in" >&2 || fail "after the $1, the bundle is not the shipped one less the denied roots (diff above)"
}
expect_installed() {  # LABEL RELEASE: with RELEASE installed, every root's verdict is what it asks for
  verdicts > "$T/$1.v"
  check_bundle "$1" "$2"
  file "$UPDATER" | grep -q "$hw" || fail "after the $1, the updater has no $hw slice for this $hw Mac: $(file "$UPDATER")"
  if [ "$mode" = bundle ]; then
    grep -q '^keychain no ' "$RECEIPT" || fail "after the $1 on macOS $os, the receipt must say the keychain was left alone: $(cat "$RECEIPT")"
    snap "$T/$1"
    diff "$T/before.admin" "$T/$1.admin" >&2 || fail "after the $1 on macOS $os, the admin trust settings changed (diff above); this macOS gets the bundle only"
    cmp -s "$T/before.kc" "$T/$1.kc" || fail "after the $1 on macOS $os, System.keychain changed: $(comm -3 "$T/before.kc" "$T/$1.kc")"
  else
    grep -qx 'keychain yes' "$RECEIPT" || fail "after the $1 on Mac OS X $os, the receipt must say the keychain was changed: $(cat "$RECEIPT")"
  fi
  bad="$(while read -r n v; do
    if [ "$mode" = bundle ]; then
      want="$(awk -v n="$n" '$1 == n { print $2 }' "$T/before.v")"
    elif grep -qx "preexisting ${n%.pem}" "$RECEIPT"; then
      grep -q "<key>${n%.pem}</key>" "$T/before.admin.plist" || echo "  $n is recorded preexisting, but had no admin trust setting before"
      want="$(awk -v n="$n" '$1 == n { print $2 }' "$T/before.v")"
    elif [ -f "$T/$2/trusted/$n" ]; then want=trusted
    elif [ -f "$T/$2/distrust/$n" ]; then want=untrusted
    else want="$(awk -v n="$n" '$1 == n { print $2 }' "$T/before.v")"; fi
    [ "$v" = "$want" ] || echo "  $n verifies $v, want $want"
  done < "$T/$1.v")"
  [ -z "$bad" ] || fail "after the $1, roots verify wrongly for TLS:
$bad"
  echo "acceptance-onbox: after the $1: $(grep -c ' trusted$' "$T/$1.v") of $(wc -l < "$T/$1.v" | tr -d ' ') roots verify, as the release asks on $os ($hw)"
}

mkdir -p "$T/all"
roots_of "$PKG" new
[ -z "$PREV" ] || roots_of "$PREV" prev
snap "$T/before"
: > "$T/before.admin.plist"
security trust-settings-export -d "$T/before.admin.plist" >/dev/null 2>&1 || : > "$T/before.admin.plist"
verdicts > "$T/before.v"
echo "acceptance-onbox: before: $(grep -c ' trusted$' "$T/before.v") of $(wc -l < "$T/before.v" | tr -d ' ') roots verify"

if [ -n "$PREV" ]; then
  sudo installer -pkg "$PREV" -target / || fail "installing the previous release failed"
  expect_installed "previous-release install" prev
fi
sudo installer -pkg "$PKG" -target / || fail "install failed"
label=install; [ -z "$PREV" ] || label=upgrade
expect_installed "$label" new
for h in good.sca1a.amazontrust.com good.sca2a.amazontrust.com good.sca3a.amazontrust.com good.sca4a.amazontrust.com www.google.com www.apple.com github.com; do
  [ "$(probe "$h")" = 200 ] || echo "note: $h does not answer over TLS from here (the network, or this system's TLS)"
done

cp "$RECEIPT" "$T/receipt1"
sudo installer -pkg "$PKG" -target / || fail "reinstall failed"
# spec: payload/libexec/ca-certs-apply -- applied, nss and keychain are all rewritten by
#       ca_receipt_set on every run (its line is deleted, then re-appended at the end), so a
#       clean reinstall relocates all three even when only applied's VALUE is expected to change.
#       nss and keychain must keep their VALUE on a clean reinstall of the same pkg, so only
#       applied's line is dropped; sorting what's left cancels the harmless reorder while still
#       catching a genuine value change anywhere else, nss and keychain included.
grep -v '^applied ' "$T/receipt1" | sort > "$T/receipt1.norm"
grep -v '^applied ' "$RECEIPT" | sort > "$T/receipt2.norm"
diff "$T/receipt1.norm" "$T/receipt2.norm" \
  || fail "a reinstall changed the receipt beyond its applied timestamp (diff above)"
expect_installed reinstall new

sudo /usr/local/bin/mavergreen uninstall ca-certs || fail "uninstall failed"
snap "$T/after"
diff "$T/before.admin" "$T/after.admin" || fail "uninstall did not restore the admin trust settings exactly (diff above)"
cmp -s "$T/before.kc" "$T/after.kc" || fail "uninstall left certificates in System.keychain: $(comm -13 "$T/before.kc" "$T/after.kc")"
verdicts > "$T/after.v"
diff "$T/before.v" "$T/after.v" || fail "after uninstall, roots verify differently than before (diff above)"
[ ! -e "$TREE" ] || fail "uninstall left $TREE"
[ ! -e /usr/local/mavergreen/var/ca-certs ] || fail "uninstall left /usr/local/mavergreen/var/ca-certs"
if pkgutil --pkgs | grep -qx dev.mavergreen.ca-certs; then fail "uninstall left the pkg receipt dev.mavergreen.ca-certs"; fi
done=yes
echo "acceptance-onbox: ok"
