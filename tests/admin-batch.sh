#!/bin/sh
# platform: macOS-only -- ca_admin_batch checks what it writes with plutil, as the 10.9 install does
# spec: docs/TRUST-POLICY.md #8 and #9
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/cabatch.XXXXXX")"
trap 'rm -rf "$T"' EXIT
export SECURITY="$R/tests/fake-security/security"
n=0
mkcert() {
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key" -out "$T/new.pem" -days 2 -subj "/CN=$1" >/dev/null 2>&1
  _s="$(openssl x509 -noout -fingerprint -sha1 -in "$T/new.pem" | sed 's/.*=//' | tr -d :)"
  mv "$T/new.pem" "$2/$_s.pem"
  printf '%s\n' "$_s"
}
fresh() {
  n=$((n + 1)); ROOT="$T/root$n"; SEC="$T/sec$n"
  TREE="$ROOT/usr/local/mavergreen/ca-certs"; BLK="$TREE/share/ca-certs/blocked"
  mkdir -p "$BLK" "$TREE/share/ca-certs/trusted" "$TREE/share/ca-certs/distrust" "$SEC" "$ROOT/Library/Keychains"
  export FAKE_SEC_STATE="$SEC" FAKE_SEC_ROOT="$ROOT" CA_CERTS_BOOTED_ROOT="$ROOT" CA_CERTS_OS_VERSION=10.9.5
  unset FAKE_SEC_FAIL_IMPORT
  : > "$T/entries$n"
}
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- A blocked certificate in share/ca-certs/blocked, and its line in the entries file:
#       made-up issuer and serial base64, unique per certificate, so the import shows where each landed
b64() { printf '%s' "$1" | base64; }
blocked() {
  _b="$(mkcert "$1" "$BLK")"
  printf '%s %s %s\n' "$_b" "$(b64 "issuer-$1")" "$(b64 "serial-$1")" >> "$T/entries$n"
  printf '%s\n' "$_b"
}
batch() { (CA_ROOT="$ROOT"; . "$R/payload/libexec/ca-certs-lib.sh"; ca_admin_batch "$@"); }
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- the same, reading $XML as the admin domain
batchxml() {
  (CA_ROOT="$ROOT"; . "$R/payload/libexec/ca-certs-lib.sh"
   ca_admin_xml() { cat "$XML"; }
   ca_admin_batch "$@")
}
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- a 10.9-shaped export of the given entry bodies: "SHA1 BODY_LINES" per argument, \n-separated
craft() {
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
  printf '<plist version="1.0">\n<dict>\n\t<key>trustList</key>\n\t<dict>\n'
  for _c in "$@"; do printf '\t\t<key>%s</key>\n%b\n' "${_c%% *}" "${_c#* }"; done
  printf '\t</dict>\n\t<key>trustVersion</key>\n\t<integer>1</integer>\n</dict>\n</plist>\n'
}
DENY='\t\t<dict>\n\t\t\t<key>issuerName</key>\n\t\t\t<data>\n\t\t\tZmFrZQ==\n\t\t\t</data>\n\t\t\t<key>modDate</key>\n\t\t\t<date>2026-10-28T12:00:00Z</date>\n\t\t\t<key>serialNumber</key>\n\t\t\t<data>\n\t\t\tAQ==\n\t\t\t</data>\n\t\t\t<key>trustSettings</key>\n\t\t\t<array>\n\t\t\t\t<dict>\n\t\t\t\t\t<key>kSecTrustSettingsPolicy</key>\n\t\t\t\t\t<data>\n\t\t\t\t\tKoZIhvdjZAED\n\t\t\t\t\t</data>\n\t\t\t\t\t<key>kSecTrustSettingsResult</key>\n\t\t\t\t\t<integer>3</integer>\n\t\t\t\t</dict>\n\t\t\t</array>\n\t\t</dict>'
E1=1111111111111111111111111111111111111111
E2=2222222222222222222222222222222222222222
E3=3333333333333333333333333333333333333333
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- the same, reading a real 10.9 export (tabs, base64 wrapped across lines) as the admin domain
batch109() {
  (CA_ROOT="$ROOT"; . "$R/payload/libexec/ca-certs-lib.sh"
   ca_admin_xml() { cat "$R/tests/fixtures/admin-trust-settings-10.9.xml"; }
   ca_admin_batch "$@")
}
denied_ssl() { grep -q "^$1 deny ssl\$" "$SEC/admin" || fail "$1 must be denied for TLS: $(cat "$SEC/admin")"; }
absent() { if grep -q "^$1 " "$SEC/admin"; then fail "$1 must have no admin setting: $(cat "$SEC/admin")"; fi; }
calls() { grep -c "^$1" "$SEC/log" || :; }
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- one certificate's entry -- its key line through its whole nested <dict> -- from a plist in XML
entry() {
  awk -v k="<key>$1</key>" '
    !on && index($0, k) { on = 1; print; next }
    on { print; if ($0 ~ /<dict>/) d++; if ($0 ~ /<\/dict>/ && --d == 0) exit }
  ' "$2"
}
without() {  # a plist in XML, less one certificate's entry
  awk -v k="<key>$1</key>" '
    !on && index($0, k) { on = 1; next }
    on && d == 0 && /<dict\/>/ { on = 0; next }
    on { if ($0 ~ /<dict>/) d++; if ($0 ~ /<\/dict>/ && --d == 0) on = 0; next }
    { print }
  ' "$2"
}
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- one field of the entry in $T/got, whitespace stripped, as "<key>K</key> <data> B64 </data> "
field() { grep -A3 "<key>$1</key>" "$T/got" | tr '\n' ' '; }
preexisting() {  # the user's own: P trusted for every use, Q denied for S/MIME
  P="$(mkcert p "$TREE/share/ca-certs/trusted")"
  Q="$(mkcert q "$TREE/share/ca-certs/distrust")"
  "$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$TREE/share/ca-certs/trusted/$P.pem"
  "$SECURITY" add-trusted-cert -d -r deny -p smime -k kc "$TREE/share/ca-certs/distrust/$Q.pem"
}

scenario "adds every entry in one import"
fresh
X1="$(blocked x1)"; X2="$(blocked x2)"; X3="$(blocked x3)"
: > "$SEC/log"
batch add "$T/entries$n" || fail "adding three entries failed"
denied_ssl "$X1"; denied_ssl "$X2"; denied_ssl "$X3"
[ "$(wc -l < "$SEC/admin" | tr -d ' ')" = 3 ] || fail "want exactly 3 admin settings: $(cat "$SEC/admin")"
[ "$(calls trust-settings-import)" = 1 ] || fail "want exactly one import: $(cat "$SEC/log")"
[ "$(calls add-trusted-cert)" = 1 ] || fail "want exactly one add-trusted-cert, for the template: $(cat "$SEC/log")"
grep -q "^add-trusted-cert -d -r deny -p ssl $BLK/$X1.pem\$" "$SEC/log" || fail "the template must be the first entry, denied for TLS: $(cat "$SEC/log")"
[ ! -s "$SEC/keychain" ] || fail "blocked certificates are never imported into System.keychain: $(cat "$SEC/keychain")"

scenario "keeps every other entry byte for byte"
fresh
preexisting
X1="$(blocked x1)"; X2="$(blocked x2)"; X3="$(blocked x3)"
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- what the batch reads: the export through plutil xml1, which on modern macOS rewraps <data>
"$SECURITY" trust-settings-export -d "$T/export.plist"
plutil -convert xml1 -o "$T/before.xml" "$T/export.plist"
batch add "$T/entries$n" || fail "adding next to the user's settings failed"
denied_ssl "$X1"; denied_ssl "$X2"; denied_ssl "$X3"
grep -q "^$P trustRoot \$" "$SEC/admin" || fail "P's own setting must survive: $(cat "$SEC/admin")"
grep -q "^$Q deny smime\$" "$SEC/admin" || fail "Q's own setting must survive: $(cat "$SEC/admin")"
for k in "$P" "$Q"; do
  entry "$k" "$T/before.xml" > "$T/want"
  entry "$k" "$SEC/imported.plist" > "$T/got"
  [ -s "$T/want" ] || fail "test setup: the export holds no entry for $k"
  diff "$T/want" "$T/got" || fail "$k's entry must be carried through byte for byte (diff above)"
done

scenario "removes only the named keys"
printf '%s\n%s\n' "$X1" "$X3" > "$T/remove"
: > "$SEC/log"
batch remove "$T/remove" || fail "removing two entries failed"
absent "$X1"; absent "$X3"; denied_ssl "$X2"
grep -q "^$P trustRoot \$" "$SEC/admin" && grep -q "^$Q deny smime\$" "$SEC/admin" || fail "the user's settings must survive a removal: $(cat "$SEC/admin")"
[ "$(calls trust-settings-import)" = 1 ] || fail "want exactly one import: $(cat "$SEC/log")"
[ "$(calls remove-trusted-cert)" = 0 ] || fail "removal is by import alone: $(cat "$SEC/log")"
entry "$P" "$T/before.xml" > "$T/want"; entry "$P" "$SEC/imported.plist" > "$T/got"
diff "$T/want" "$T/got" || fail "P's entry must be carried through a removal byte for byte (diff above)"

scenario "batch into an empty admin domain"
fresh
X1="$(blocked x1)"; X2="$(blocked x2)"
[ ! -s "$SEC/admin" ] && [ ! -f "$ROOT/Library/Security/Trust Settings/Admin.plist" ] || fail "test setup: the admin domain must start empty"
batch add "$T/entries$n" || fail "adding into an empty admin domain failed"
denied_ssl "$X1"; denied_ssl "$X2"
[ "$(wc -l < "$SEC/admin" | tr -d ' ')" = 2 ] || fail "want exactly 2 admin settings: $(cat "$SEC/admin")"

scenario "refuses a failed import"
fresh
preexisting
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- the user's own TLS denial of U is a template already, so no add-trusted-cert comes first
U="$(mkcert u "$TREE/share/ca-certs/distrust")"
"$SECURITY" add-trusted-cert -d -r deny -p ssl -k kc "$TREE/share/ca-certs/distrust/$U.pem"
X1="$(blocked x1)"; X2="$(blocked x2)"
cp "$SEC/admin" "$T/admin-before"
: > "$SEC/log"
if FAKE_SEC_FAIL_IMPORT=1 batch add "$T/entries$n" 2>"$T/err"; then fail "a failed import must fail the batch"; fi
grep -q "import" "$T/err" || fail "the failure must name the import: $(cat "$T/err")"
[ "$(calls add-trusted-cert)" = 0 ] || fail "an existing TLS denial is the template; nothing may be added: $(cat "$SEC/log")"
cmp -s "$T/admin-before" "$SEC/admin" || fail "a failed import must change nothing: $(cat "$SEC/admin")"
printf '%s\n' "$U" > "$T/remove"
if FAKE_SEC_FAIL_IMPORT=1 batch remove "$T/remove" 2>"$T/err"; then fail "a failed import must fail the removal"; fi
grep -q "import" "$T/err" || fail "the failure must name the import: $(cat "$T/err")"
cmp -s "$T/admin-before" "$SEC/admin" || fail "a failed import must change nothing: $(cat "$SEC/admin")"

scenario "writes the exact issuer and serial"
fresh
X1="$(blocked x1)"; X2="$(blocked x2)"; X3="$(blocked x3)"
batch add "$T/entries$n" || fail "adding three entries failed"
for x in "x2 $X2" "x3 $X3"; do
  set -- $x
  entry "$2" "$SEC/imported.plist" | tr -d ' \t' > "$T/got"
  [ "$(field issuerName)" = "<key>issuerName</key> <data> $(b64 "issuer-$1") </data> " ] || fail "$2's issuerName must be the given base64: $(cat "$T/got")"
  [ "$(field serialNumber)" = "<key>serialNumber</key> <data> $(b64 "serial-$1") </data> " ] || fail "$2's serialNumber must be the given base64: $(cat "$T/got")"
done

scenario "edits a real 10.9 export: copies its TLS denial, and the rest stays byte for byte"
fresh
X1="$(blocked x1)"; X2="$(blocked x2)"
: > "$SEC/log"
batch109 add "$T/entries$n" || fail "adding to a real 10.9 export failed"
[ "$(calls add-trusted-cert)" = 0 ] || fail "the export holds TLS denials to copy; nothing may be added: $(cat "$SEC/log")"
denied_ssl "$X1"; denied_ssl "$X2"
for k in "$X1" "$X2"; do
  entry "$k" "$SEC/imported.plist" > "$T/new-$k"
  grep -q 'KoZIhvdjZAED' "$T/new-$k" || fail "$k must be a copy of a TLS denial: $(cat "$T/new-$k")"
done
F109="$R/tests/fixtures/admin-trust-settings-10.9.xml"
without "$X1" "$SEC/imported.plist" > "$T/rest1"; without "$X2" "$T/rest1" > "$T/rest"
diff "$F109" "$T/rest" || fail "the 10.9 export must be carried through byte for byte (diff above)"
[ "$(grep -c '<key>[0-9A-F]\{40\}</key>' "$SEC/imported.plist")" = "$(( $(grep -c '<key>[0-9A-F]\{40\}</key>' "$F109") + 2 ))" ] || fail "want the export's entries plus 2"
for pair in "x1 $X1" "x2 $X2"; do
  set -- $pair
  tr -d ' \t' < "$T/new-$2" > "$T/got"
  [ "$(field issuerName)" = "<key>issuerName</key> <data> $(b64 "issuer-$1") </data> " ] || fail "$2's issuerName must be the given base64: $(cat "$T/got")"
  [ "$(field serialNumber)" = "<key>serialNumber</key> <data> $(b64 "serial-$1") </data> " ] || fail "$2's serialNumber must be the given base64: $(cat "$T/got")"
done
G="$(sed -n 's/.*<key>\([0-9A-F]\{40\}\)<\/key>.*/\1/p' "$F109" | sed -n 3p)"
printf '%s\n' "$G" > "$T/remove"
batch109 remove "$T/remove" || fail "removing from a real 10.9 export failed"
entry "$G" "$F109" > "$T/gone"
[ "$(wc -l < "$T/gone" | tr -d ' ')" -gt 3 ] || fail "test setup: no entry for $G"
without "$G" "$F109" > "$T/want"
diff "$T/want" "$SEC/imported.plist" || fail "removing $G must drop exactly its entry (diff above)"

scenario "removes a key whose value is <dict/>, and not the entry after it"
fresh
XML="$T/crafted.xml"
craft "$E1 \t\t<dict/>" "$E2 $DENY" "$E3 $DENY" > "$XML"
printf '%s\n' "$E1" > "$T/remove"
batchxml remove "$T/remove" || fail "removing an entry whose value is <dict/> failed"
without "$E1" "$XML" > "$T/want"
diff "$T/want" "$SEC/imported.plist" || fail "removing $E1 must drop exactly its entry (diff above)"

scenario "refuses an edit whose key count doesn't add up"
fresh
XML="$T/crafted.xml"
# spec: payload/libexec/ca-certs-lib.sh ca_admin_batch -- E1's entry hides a 40-hex key inside it: dropping one entry would drop two keys
craft "$E1 \t\t<dict>\n\t\t\t<key>$E3</key>\n\t\t\t<string>x</string>\n\t\t</dict>" "$E2 $DENY" > "$XML"
printf '%s\n' "$E1" > "$T/remove"
: > "$SEC/log"
if batchxml remove "$T/remove" 2>"$T/err"; then fail "a mis-counted edit must be refused"; fi
grep -q "count" "$T/err" || fail "the refusal must name the key count check: $(cat "$T/err")"
[ "$(calls trust-settings-import)" = 0 ] || fail "nothing may be imported: $(cat "$SEC/log")"

scenario "refuses a malformed entries line before any security call"
fresh
preexisting
X1="$(blocked x1)"
printf '%s not*base64 AQ==\n' "$X1" >> "$T/entries$n"
: > "$SEC/log"
if batch add "$T/entries$n" 2>"$T/err"; then fail "a malformed entries line must be refused"; fi
grep -q "malformed" "$T/err" || fail "the refusal must say the line is malformed: $(cat "$T/err")"
[ ! -s "$SEC/log" ] || fail "no security call may come before the entries are checked: $(cat "$SEC/log")"

scenario "refuses when it cannot make a temporary file"
fresh
X1="$(blocked x1)"
: > "$SEC/log"
if TMPDIR="$T/nonexistent" batch add "$T/entries$n" 2>"$T/err"; then fail "a failed mktemp must fail the batch"; fi
grep -q "temporary file" "$T/err" || fail "the failure must name the temporary file: $(cat "$T/err")"
[ ! -s "$SEC/log" ] || fail "nothing may change without the temporary file: $(cat "$SEC/log")"
