#!/bin/sh
# platform: macOS-only -- sources ca-certs-lib.sh, the applier's library, which only runs on macOS
# spec: docs/TRUST-POLICY.md #13
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/cadenies.XXXXXX")"
trap 'rm -rf "$T"' EXIT
CA_ROOT="$T/root"
. "$R/payload/libexec/ca-certs-lib.sh"

scenario "a real 10.9 export: the 25 withdrawn roots are denied for TLS, and nothing else is"
for f in "$R"/withdrawn/*.pem; do openssl x509 -noout -fingerprint -sha1 -in "$f" | sed 's/.*=//' | tr -d :; done | sort > "$T/want"
ca_ssl_denied_in_xml < "$R/tests/fixtures/admin-trust-settings-10.9.xml" | sort > "$T/got"
diff "$T/want" "$T/got" || fail "the fixture holds ca-certs' 18 TLS-only denials and AquaTransport's 7 for every use; want exactly the 25 withdrawn roots (diff above)"

xml() {  # one certificate's trustSettings array, as real exports write it
  printf '<plist version="1.0">\n<dict>\n<key>trustList</key>\n<dict>\n<key>%s</key>\n<dict>\n<key>issuerName</key>\n<data>\nZmFrZQ==\n</data>\n%s</dict>\n</dict>\n</dict>\n</plist>\n' \
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "$1"
}
setting() {  # POLICY_DATA|"" POLICY_STRING|"" RESULT|""
  printf '<dict>\n'
  [ -z "$1" ] || printf '<key>kSecTrustSettingsPolicy</key>\n<data>\n%s\n</data>\n' "$1"
  [ -z "$2" ] || printf '<key>kSecTrustSettingsPolicyString</key>\n<string>%s</string>\n' "$2"
  [ -z "$3" ] || printf '<key>kSecTrustSettingsResult</key>\n<integer>%s</integer>\n' "$3"
  printf '</dict>\n'
}
SSL=KoZIhvdjZAED; SMIME=KoZIhvdjZAEI
denied() {  # LABEL WANT(yes|no) SETTINGS...
  label="$1"; want="$2"; shift 2
  body="<key>trustSettings</key>
<array>
$*
</array>
"
  got=no; [ -z "$(xml "$body" | ca_ssl_denied_in_xml)" ] || got=yes
  [ "$got" = "$want" ] || fail "$label: want denied=$want, got $got"
}
scenario "settings apply in order, as Apple's and Go's evaluation do: the first one that decides TLS wins"
denied "a deny for every use" yes "$(setting '' '' 3)"
denied "a deny for TLS" yes "$(setting "$SSL" '' 3)"
denied "a deny for email only" no "$(setting "$SMIME" '' 3)"
denied "a deny for one hostname" no "$(setting "$SSL" www.example.com 3)"
denied "trust for TLS, then a deny for every use" no "$(setting "$SSL" '' 1)
$(setting '' '' 3)"
denied "unspecified for TLS, then a deny for every use" yes "$(setting "$SSL" '' 4)
$(setting '' '' 3)"
denied "a deny for email, then a deny for every use" yes "$(setting "$SMIME" '' 3)
$(setting '' '' 3)"
denied "a setting with no result is trust" no "$(setting "$SSL" '' '')"
[ -z "$(xml '' | ca_ssl_denied_in_xml)" ] || fail "a certificate with no trustSettings is trusted for every use, not denied"

echo "admin-denies: ok"
