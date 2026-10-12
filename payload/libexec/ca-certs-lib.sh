# platform: macOS-only -- security, plutil, sw_vers and BSD stat read the trust store
#   usage: CA_ROOT=/Volumes/X . ca-certs-lib.sh      (CA_ROOT empty for /)
#          Paths, the receipt, and the questions ca-certs-apply and pre-uninstall ask the trust
#          store. Every answer that feeds a decision is checked, never piped through unchecked.
: "${SECURITY:=/usr/bin/security}"
: "${CA_CERTS_BOOTED_ROOT:=/}"
CA_TREE="$CA_ROOT/usr/local/mavergreen/ca-certs"
CA_VAR="$CA_ROOT/usr/local/mavergreen/var/ca-certs"
CA_RECEIPT="$CA_VAR/receipt"
CA_KC="$CA_ROOT/Library/Keychains/System.keychain"
# platform: the admin trust domain lives in this one file (spike 5 hashed it); absent means no settings
CA_ADMIN_FILE="$CA_ROOT/Library/Security/Trust Settings/Admin.plist"

ca_die() { echo "ca-certs: $*" >&2; exit 1; }

# platform: security's -d writes go through securityd to the running system, never to a file under a root
ca_is_booted_root() { [ "$(stat -f %d:%i "$CA_ROOT/")" = "$(stat -f %d:%i "$CA_CERTS_BOOTED_ROOT")" ]; }

# spec: docs/TRUST-POLICY.md #10 -- from macOS 11 an unattended admin trust change needs a password
ca_os_allows_keychain() {
  _v="${CA_CERTS_OS_VERSION:-$(sw_vers -productVersion)}"
  case "$_v" in 10.*) return 0 ;; esac
  return 1
}

# platform: this exact text is what security trust-settings-export prints on stderr when the
#           admin trust domain has no settings, e.g. right after removing the last one -- a real
#           10.9 may also leave Admin.plist behind, empty, in that state
CA_NO_ADMIN_SETTINGS_MSG='No Trust Settings were found'

ca_admin_keys() {
  _x="$(ca_admin_xml)"
  printf '%s\n' "$_x" | sed -n 's/.*<key>\([0-9A-F]\{40\}\)<\/key>.*/\1/p'
}
ca_admin_xml() {
  [ -f "$CA_ADMIN_FILE" ] || return 0
  _t="$(mktemp "${TMPDIR:-/tmp}/ca-certs-admin.XXXXXX")"
  _e="$(mktemp "${TMPDIR:-/tmp}/ca-certs-admin-err.XXXXXX")"
  if ! "$SECURITY" trust-settings-export -d "$_t" >/dev/null 2>"$_e"; then
    if grep -q "$CA_NO_ADMIN_SETTINGS_MSG" "$_e"; then rm -f "$_t" "$_e"; return 0; fi
    _m="$(cat "$_e")" || _m="(its error output is unreadable)"
    rm -f "$_t" "$_e"
    ca_die "could not read the admin trust settings: $_m"
  fi
  rm -f "$_e"
  _x="$(plutil -convert xml1 -o - "$_t")" || { rm -f "$_t"; ca_die "could not read the exported admin trust settings"; }
  rm -f "$_t"
  printf '%s\n' "$_x"
}

ca_kc_keys() {
  _l="$("$SECURITY" find-certificate -a -Z "$CA_KC")" || ca_die "could not list $CA_KC"
  printf '%s\n' "$_l" | sed -n 's/^SHA-1 hash: \([0-9A-F]\{40\}\)$/\1/p'
}

ca_in() { printf '%s\n' "$2" | grep -q "^$1\$"; }

# spec: docs/TRUST-POLICY.md #9 -- every receipt read and rewrite is checked. A receipt
#       that exists but cannot be read dies, never reads as "nothing recorded". Callers read
#       ca_receipt_list and ca_receipt_value with a plain assignment, so a failure stops them
ca_receipt_has() {
  [ -f "$CA_RECEIPT" ] || return 1
  _s=0; grep -q "^$1 $2\$" "$CA_RECEIPT" || _s=$?
  [ "$_s" -le 1 ] || ca_die "could not read $CA_RECEIPT"
  return "$_s"
}
# spec: docs/TRUST-POLICY.md #9 -- the receipt is only ever replaced, by rename, with
#       a .tmp that was written whole. Every change is written into .tmp by sed and printf, which
#       exit non-zero when a write fails; 10.9's grep exits 0 then (a full disk), so it never writes
#       one. Even an add rewrites, so a failed append cannot leave a partial line in the receipt
ca_receipt_abandon() { rm -f "$CA_RECEIPT.tmp"; ca_die "could not rewrite $CA_RECEIPT"; }
ca_receipt_without() {
  rm -f "$CA_RECEIPT.tmp"
  [ -f "$CA_RECEIPT" ] || return 0
  sed "/$1/d" "$CA_RECEIPT" > "$CA_RECEIPT.tmp" || ca_receipt_abandon
}
ca_receipt_with() { printf '%s\n' "$*" >> "$CA_RECEIPT.tmp" || ca_receipt_abandon; }
ca_receipt_replace() { mv -f "$CA_RECEIPT.tmp" "$CA_RECEIPT" || ca_receipt_abandon; }
ca_receipt_add() {
  ca_receipt_without "^$1 $2\$"
  ca_receipt_with "$1 $2"
  ca_receipt_replace
}
ca_receipt_drop() {
  [ -f "$CA_RECEIPT" ] || return 0
  ca_receipt_without "^$1 $2\$"
  ca_receipt_replace
}
ca_receipt_set() {
  _k="$1"; shift
  ca_receipt_without "^$_k "
  ca_receipt_with "$_k $*"
  ca_receipt_replace
}
ca_receipt_list() {
  [ -f "$CA_RECEIPT" ] || return 0
  _l="$(sed -n "s/^$1 \([0-9A-F]\{40\}\)\$/\1/p" "$CA_RECEIPT")" || ca_die "could not read $CA_RECEIPT"
  [ -z "$_l" ] || printf '%s\n' "$_l"
}
ca_receipt_value() {
  [ -f "$CA_RECEIPT" ] || return 0
  _v="$(sed -n "s/^$1 //p" "$CA_RECEIPT")" || ca_die "could not read $CA_RECEIPT"
  [ -z "$_v" ] || printf '%s\n' "$_v"
}
ca_receipt_changes() {
  _c="$(ca_receipt_list trusted)" || exit 1
  _d="$(ca_receipt_list denied)" || exit 1
  _i="$(ca_receipt_list imported)" || exit 1
  [ -n "$_c$_d$_i" ]
}

# spec: docs/TRUST-POLICY.md #8 -- a trust setting that already exists (here: already gone) is never
#       touched, so an admin setting the user removed by hand is skipped, not re-removed or died on
ca_undo_setting() {
  _admin="$(ca_admin_keys)"
  ca_in "$1" "$_admin" || return 0
  "$SECURITY" remove-trusted-cert -d "$CA_VAR/certs/$1.pem" || ca_die "could not remove the admin trust setting for $1"
  _admin="$(ca_admin_keys)"
  if ca_in "$1" "$_admin"; then ca_die "security reported removing $1 but its admin setting remains"; fi
}
ca_undo_import() {
  _kc="$(ca_kc_keys)"
  ca_in "$1" "$_kc" || return 0
  "$SECURITY" delete-certificate -Z "$1" "$CA_KC" >/dev/null || ca_die "could not delete $1 from $CA_KC"
  _kc="$(ca_kc_keys)"
  if ca_in "$1" "$_kc"; then ca_die "security reported deleting $1 but it is still in $CA_KC"; fi
}

# spec: docs/TRUST-POLICY.md #12 -- AquaTransport's "Modern Root Certificates" component never undoes
#       its trust settings and skips a root already in System.keychain, so when its receipt has
#       changed since our last run, it ran after us, and a root its list names that has an admin
#       setting is its, not ours: dropping our lines for it means no run and no uninstall ever
#       undoes it, and the next run records it preexisting as it does any setting it finds. A
#       setting we made with its receipt already in place is one it chose not to make, so it stays ours.
CA_AT_RECEIPT="$CA_ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
CA_AT_ROOTS="$CA_TREE/share/ca-certs/aquatransport-roots.txt"
ca_at_stamp() {
  [ -f "$CA_AT_RECEIPT" ] || return 0
  _st="$(cksum < "$CA_AT_RECEIPT")" || ca_die "could not read $CA_AT_RECEIPT"
  printf '%s\n' "$_st" | awk '{ print $1 "-" $2 }'
}
ca_note_aquatransport() {
  _st="$(ca_at_stamp)"
  [ -z "$_st" ] || ca_receipt_set aquatransport "$_st"
}
ca_cede_to_aquatransport() {
  [ -f "$CA_AT_RECEIPT" ] && [ -f "$CA_AT_ROOTS" ] || return 0
  [ "$(ca_at_stamp)" != "$(ca_receipt_value aquatransport)" ] || return 0
  _claimed="$(awk '($1 == "trust" || $1 == "distrust") && $2 ~ /^[0-9A-F]+$/ && length($2) == 40 { print $2 }' "$CA_AT_ROOTS")" \
    || ca_die "could not read $CA_AT_ROOTS"
  [ -n "$_claimed" ] || return 0
  _admin="$(ca_admin_keys)"
  for _at in $_claimed; do
    ca_in "$_at" "$_admin" || continue
    for _atk in trusted denied imported; do
      if ca_receipt_has "$_atk" "$_at"; then ca_receipt_drop "$_atk" "$_at"; fi
    done
  done
}

# spec: docs/TRUST-POLICY.md #13 -- reads trust-settings-export's XML (plutil xml1) on stdin and
#       prints each certificate whose admin settings deny it for TLS. Settings apply in order and the
#       first that decides TLS wins: one restricted to another policy or to a policy string (a
#       hostname) doesn't apply, an absent result is TrustRoot, and Unspecified (4) decides nothing.
#       No trustSettings at all means TrustRoot for every use.
ca_ssl_denied_in_xml() {
  awk '
    function decide() {
      if (done || pstr) return
      if (pol != "" && pol != "KoZIhvdjZAED") return
      r = (res == "") ? 1 : res
      if (r == 4) return
      done = 1
      if (r == 3) print sha
    }
    /<key>[0-9A-F]*<\/key>/ && !insets {
      k = $0; sub(/.*<key>/, "", k); sub(/<\/key>.*/, "", k)
      if (length(k) == 40) { sha = k; done = 0 }
      next
    }
    /<key>trustSettings<\/key>/ { insets = 1; next }
    insets && /<\/array>/ { insets = 0; next }
    insets && /<dict>/ { pol = ""; pstr = 0; res = ""; want = ""; next }
    insets && /<\/dict>/ { decide(); next }
    insets && /<key>kSecTrustSettingsPolicy<\/key>/ { want = "pol"; next }
    insets && /<key>kSecTrustSettingsPolicyString<\/key>/ { pstr = 1; want = ""; next }
    insets && /<key>kSecTrustSettingsResult<\/key>/ { want = "res"; next }
    insets && /<key>/ { want = ""; next }
    insets && want == "pol" && !/<\/?data>/ { v = $0; gsub(/[ \t]/, "", v); pol = pol v; next }
    insets && want == "pol" && /<\/data>/ { want = ""; next }
    insets && want == "res" && /<integer>/ { v = $0; gsub(/[^0-9]/, "", v); res = v; want = ""; next }
  '
}

CA_BUNDLE="$CA_TREE/etc/openssl/certs/ca-certificates.crt"
CA_BUNDLE_SHIPPED="$CA_TREE/share/ca-certs/ca-certificates.crt"
CA_BUNDLE_INDEX="$CA_TREE/share/ca-certs/ca-certificates.sha1"
# spec: docs/TRUST-POLICY.md #13 -- the bundle is rebuilt from the shipped copy on every run,
#       leaving out each root the running system's admin trust settings deny for TLS, and the
#       receipt lists what was left out. Replaced only whole, by rename, never partly written.
ca_filter_bundle() {
  [ -f "$CA_BUNDLE_SHIPPED" ] && [ -f "$CA_BUNDLE_INDEX" ] || return 0
  _xml="$(ca_admin_xml)"
  _den="$(printf '%s\n' "$_xml" | ca_ssl_denied_in_xml)" || ca_die "could not read which roots the admin trust settings deny"
  _fd="$(mktemp "${TMPDIR:-/tmp}/ca-certs-denied.XXXXXX")"
  printf '%s\n' "$_den" > "$_fd" || { rm -f "$_fd"; ca_die "could not write the list of denied roots"; }
  _fb="$CA_BUNDLE.tmp"
  rm -f "$_fb"
  _out="$(awk -v idx="$CA_BUNDLE_INDEX" -v den="$_fd" -v out="$_fb" '
    BEGIN {
      while ((getline l < idx) > 0) sha[++n] = l
      while ((getline l < den) > 0) if (l != "") deny[l] = 1
    }
    { buf = buf $0 "\n" }
    /-----END CERTIFICATE-----/ {
      i++
      if (i > n) { bad = 1; exit }
      if (sha[i] in deny) print sha[i]; else printf "%s", buf > out
      buf = ""
    }
    END { if (bad || i != n || buf != "") exit 1; close(out) }
  ' "$CA_BUNDLE_SHIPPED")" || { rm -f "$_fd" "$_fb"; ca_die "the shipped bundle and its index disagree; left the bundle as it was"; }
  rm -f "$_fd"
  [ -s "$_fb" ] || { rm -f "$_fb"; ca_die "every root in the bundle is denied; left the bundle as it was"; }
  chmod 644 "$_fb" && mv -f "$_fb" "$CA_BUNDLE" || { rm -f "$_fb"; ca_die "could not replace $CA_BUNDLE"; }
  _was="$(ca_receipt_list bundle-omitted)"
  for _bo in $_was; do ca_in "$_bo" "$_out" || ca_receipt_drop bundle-omitted "$_bo"; done
  for _bo in $_out; do ca_receipt_has bundle-omitted "$_bo" || ca_receipt_add bundle-omitted "$_bo"; done
}
