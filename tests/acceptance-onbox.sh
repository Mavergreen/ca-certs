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
timed() {  # LABEL CMD...: run CMD, fail if it fails or takes 120 s or more, print how long it took
  _l="$1"; shift
  _s="$(date +%s)"
  "$@" || fail "$_l failed"
  _d=$(( $(date +%s) - _s ))
  echo "acceptance-onbox: $_l took ${_d}s"
  [ "$_d" -lt 120 ] || fail "$_l took ${_d}s; the bar is under 120s"
}
probe_cert() {  # HOST: fail only when curl cannot verify the certificate (exit 60); any other failure is a note
  _rc=0
  /usr/bin/curl --noproxy '*' -sS -o /dev/null -m 20 "https://$1/" 2>/dev/null || _rc=$?
  [ "$_rc" -ne 60 ] || fail "$1 fails certificate verification (curl exit 60)"
  [ "$_rc" -eq 0 ] || echo "note: $1 does not answer over TLS from here (curl exit $_rc)"
}
snap() {
  # platform: the dump omits admin entries whose certificate is in no keychain (every blocked one), so this reads the export, not dump-trust-settings
  : > "$1.admin.xml"
  if security trust-settings-export -d "$1.admin.plist" >/dev/null 2>&1; then plutil -convert xml1 -o - "$1.admin.plist" | awk '/<key>modDate<\/key>/ { skip = 1; next } skip { skip = 0; next } { print }' > "$1.admin.xml" || : > "$1.admin.xml"; fi  # modDate lines dropped: an import may rewrite dates of entries it carries through
  sed -n 's/.*<key>\([0-9A-F]\{40\}\)<\/key>.*/\1/p' "$1.admin.xml" | LC_ALL=C sort > "$1.admin"
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
check_blocked() {  # LABEL RELEASE: every shipped blocked intermediate is denied for TLS, with a setting, and in a keychain only if the receipt records it imported
  _bd="$TREE/share/ca-certs/blocked"
  if ! ls "$_bd"/*.pem >/dev/null 2>&1; then
    [ "$2" = prev ] && return 0   # an older release ships no blocked set
    fail "after the $1, the release ships no share/ca-certs/blocked/*.pem"
  fi
  for c in "$_bd"/*.pem; do
    openssl x509 -noout -fingerprint -sha1 -in "$c" | sed 's/.*=//' | tr -d :
  done | LC_ALL=C sort > "$T/blocked.sha1"
  [ -s "$T/blocked.sha1" ] || fail "after the $1, openssl read no SHA-1 from any shipped blocked pem"
  sed -n 's/.*<key>\([0-9A-F]\{40\}\)<\/key>.*/\1/p' "$T/$1.admin.xml" | LC_ALL=C sort > "$T/blocked.keys"
  comm -23 "$T/blocked.sha1" "$T/blocked.keys" > "$T/blocked.missing"
  [ ! -s "$T/blocked.missing" ] || fail "after the $1, the admin trust settings export has no key for $(wc -l < "$T/blocked.missing" | tr -d ' ') shipped blocked intermediates, first: $(head -1 "$T/blocked.missing")"
  _first="$(ls "$_bd"/*.pem | head -1)"
  security verify-cert -c "$_first" -p ssl -L > "$T/blocked.verify" 2>&1 || :
  grep -q kSecTrustResultDeny "$T/blocked.verify" || fail "after the $1, $_first does not verify as kSecTrustResultDeny: $(cat "$T/blocked.verify")"
  # spec: docs/TRUST-POLICY.md #14 -- the installer must not import any of them into System.keychain or the login/default keychain
  { security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null || :; security find-certificate -a -Z 2>/dev/null || :; } \
    | sed -n 's/^SHA-1 hash: //p' | LC_ALL=C sort -u > "$T/blocked.kc"
  [ -s "$T/blocked.kc" ] || fail "after the $1, the keychain lookup listed no certificates at all (System.keychain always holds some), so it cannot show the blocked ones are absent"
  comm -12 "$T/blocked.sha1" "$T/blocked.kc" > "$T/blocked.inkc"
  # spec: .superpowers/specs/2026-10-28-onecrl-feed-design.md section 4 "Migrating" -- 3.132.0-mavericks.3 imported the eMudhra ones into System.keychain and recorded them imported; they stay until uninstall, which the before/after keychain check below proves deletes them
  sed -n 's/^imported //p' "$RECEIPT" | LC_ALL=C sort -u > "$T/blocked.receipt-imported"
  comm -12 "$T/blocked.sha1" "$T/blocked.receipt-imported" > "$T/blocked.ours"
  # spec: docs/TRUST-POLICY.md #14 -- only an upgrade from a release that imported them may leave any in a keychain; a fresh install imports none
  [ -n "$PREV" ] || [ ! -s "$T/blocked.ours" ] || fail "after the $1, with no previous release, the receipt records $(wc -l < "$T/blocked.ours" | tr -d ' ') blocked intermediates imported, first: $(head -1 "$T/blocked.ours")"
  comm -23 "$T/blocked.inkc" "$T/blocked.ours" > "$T/blocked.stray"
  [ ! -s "$T/blocked.stray" ] || fail "after the $1, $(wc -l < "$T/blocked.stray" | tr -d ' ') blocked intermediates are in a keychain without an imported line in the receipt, first: $(head -1 "$T/blocked.stray")"
  comm -13 "$T/blocked.inkc" "$T/blocked.ours" > "$T/blocked.gone"
  [ ! -s "$T/blocked.gone" ] || fail "after the $1, the receipt records $(wc -l < "$T/blocked.gone" | tr -d ' ') blocked intermediates imported that no keychain holds, first: $(head -1 "$T/blocked.gone")"
  echo "acceptance-onbox: after the $1: $(wc -l < "$T/blocked.sha1" | tr -d ' ') blocked intermediates denied for TLS, in the admin settings, in a keychain only where the receipt records imported ($(wc -l < "$T/blocked.ours" | tr -d ' '))"
}
expect_installed() {  # LABEL RELEASE: with RELEASE installed, every root's verdict is what it asks for
  verdicts > "$T/$1.v"
  check_bundle "$1" "$2"
  file "$UPDATER" | grep -q "$hw" || fail "after the $1, the updater has no $hw slice for this $hw Mac: $(file "$UPDATER")"
  if [ "$mode" = bundle ]; then
    grep -q '^keychain no ' "$RECEIPT" || fail "after the $1 on macOS $os, the receipt must say the keychain was left alone: $(cat "$RECEIPT")"
    snap "$T/$1"
    diff "$T/before.admin" "$T/$1.admin" >&2 || fail "after the $1 on macOS $os, the admin trust settings changed (diff above); this macOS gets the bundle only"
    diff "$T/before.admin.xml" "$T/$1.admin.xml" >&2 || fail "after the $1 on macOS $os, an admin trust setting's content changed (diff above)"
    cmp -s "$T/before.kc" "$T/$1.kc" || fail "after the $1 on macOS $os, System.keychain changed: $(comm -3 "$T/before.kc" "$T/$1.kc")"
  else
    grep -qx 'keychain yes' "$RECEIPT" || fail "after the $1 on Mac OS X $os, the receipt must say the keychain was changed: $(cat "$RECEIPT")"
    snap "$T/$1"
    check_blocked "$1" "$2"
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
  timed "previous-release install" sudo installer -pkg "$PREV" -target /
  expect_installed "previous-release install" prev
fi
timed "install" sudo installer -pkg "$PKG" -target /
label=install; [ -z "$PREV" ] || label=upgrade
expect_installed "$label" new
for h in good.sca1a.amazontrust.com good.sca2a.amazontrust.com good.sca3a.amazontrust.com good.sca4a.amazontrust.com www.google.com www.apple.com github.com; do
  [ "$(probe "$h")" = 200 ] || echo "note: $h does not answer over TLS from here (the network, or this system's TLS)"
done
# spec: docs/TRUST-POLICY.md #14 -- anchor twins: OneCRL blocks the 10.9-shipped Certum Trusted Network CA 2, but ca-certs trusts a newer copy with the same name and key
for h in www.certum.pl www.identrust.com; do probe_cert "$h"; done

cp "$RECEIPT" "$T/receipt1"
timed "reinstall" sudo installer -pkg "$PKG" -target /
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

timed "uninstall" sudo /usr/local/bin/mavergreen uninstall ca-certs
snap "$T/after"
diff "$T/before.admin" "$T/after.admin" || fail "uninstall did not restore the admin trust settings exactly (diff above)"
diff "$T/before.admin.xml" "$T/after.admin.xml" || fail "uninstall did not restore the admin trust settings' content exactly (diff above)"
cmp -s "$T/before.kc" "$T/after.kc" || fail "uninstall left certificates in System.keychain: $(comm -13 "$T/before.kc" "$T/after.kc")"
verdicts > "$T/after.v"
diff "$T/before.v" "$T/after.v" || fail "after uninstall, roots verify differently than before (diff above)"
[ ! -e "$TREE" ] || fail "uninstall left $TREE"
[ ! -e /usr/local/mavergreen/var/ca-certs ] || fail "uninstall left /usr/local/mavergreen/var/ca-certs"
if pkgutil --pkgs | grep -qx dev.mavergreen.ca-certs; then fail "uninstall left the pkg receipt dev.mavergreen.ca-certs"; fi
done=yes
echo "acceptance-onbox: ok"
