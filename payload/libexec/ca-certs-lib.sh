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
  printf '%s\n' "$_x" | sed -n 's/.*<key>\([0-9A-F]\{40\}\)<\/key>.*/\1/p'
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
