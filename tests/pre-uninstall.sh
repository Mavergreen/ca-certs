#!/bin/sh
# platform: macOS-only -- the hook uses BSD stat and plutil, as the 10.9 uninstall does
# spec: docs/TRUST-POLICY.md #8 and #9
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/caunin.XXXXXX")"
trap 'rm -rf "$T"' EXIT
export SECURITY="$R/tests/fake-security/security"
n=0
mkcert() {
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key" -out "$T/new.pem" -days 2 -subj "/CN=$1" >/dev/null 2>&1
  _s="$(openssl x509 -noout -fingerprint -sha1 -in "$T/new.pem" | sed 's/.*=//' | tr -d :)"
  mv "$T/new.pem" "$2/$_s.pem"
  printf '%s\n' "$_s"
}
setup_applied() {  # [at-first]: AquaTransport's root component was installed before us, claiming A
  n=$((n + 1)); ROOT="$T/root$n"; SEC="$T/sec$n"
  TREE="$ROOT/usr/local/mavergreen/ca-certs"; VAR="$ROOT/usr/local/mavergreen/var/ca-certs"
  mkdir -p "$TREE/libexec/mavergreen" "$TREE/share/ca-certs/trusted" "$TREE/share/ca-certs/distrust" "$SEC"
  cp "$R/payload/libexec/ca-certs-apply" "$R/payload/libexec/ca-certs-lib.sh" "$TREE/libexec/"
  cp "$R/payload/libexec/mavergreen/pre-uninstall" "$TREE/libexec/mavergreen/"
  echo 3.130.0 > "$TREE/share/ca-certs/nss-version"
  export FAKE_SEC_STATE="$SEC" FAKE_SEC_ROOT="$ROOT" CA_CERTS_BOOTED_ROOT="$ROOT" CA_CERTS_OS_VERSION=10.9.5
  unset FAKE_SEC_SILENT_ADD FAKE_SEC_FAIL_REMOVE
  A="$(mkcert a "$TREE/share/ca-certs/trusted")"
  B="$(mkcert b "$TREE/share/ca-certs/trusted")"
  D="$(mkcert d "$TREE/share/ca-certs/distrust")"
  "$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$TREE/share/ca-certs/trusted/$B.pem"
  if [ "${1:-}" = at-first ]; then
    mkdir -p "$ROOT/private/var/db/receipts"
    : > "$ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
    printf '# fixture\ntrust %s a\n' "$A" > "$TREE/share/ca-certs/aquatransport-roots.txt"
  fi
  sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "setup apply failed"
  : > "$SEC/log"
}
hook() { env "$@" MAVERGREEN_ROOT="$ROOT/" MAVERGREEN_PRODUCT=ca-certs sh "$TREE/libexec/mavergreen/pre-uninstall"; }

scenario "full undo: ours goes, the user's B stays"
setup_applied
hook || fail "the hook failed on a clean undo"
[ "$(cat "$SEC/admin")" = "$B trustRoot " ] || fail "only the user's own setting may remain: $(cat "$SEC/admin")"
[ "$(cat "$SEC/keychain")" = "$B" ] || fail "only certificates we imported may be deleted: $(cat "$SEC/keychain")"
if grep -q -E '^(trusted|denied|imported) ' "$VAR/receipt"; then fail "undone entries must leave the receipt"; fi

scenario "partial: the distrust cannot be removed; the retry resumes"
setup_applied
if hook FAKE_SEC_FAIL_REMOVE="$D" 2>/dev/null; then fail "a failed removal must fail the hook, so nothing is removed"; fi
grep -q "^denied $D\$" "$VAR/receipt" || fail "the entry that failed must stay for the retry"
if grep -q "^trusted $A\$" "$VAR/receipt"; then fail "the entries already undone must leave the receipt"; fi
hook || fail "the retry must finish the undo"
if grep -q -E '^(trusted|denied|imported) ' "$VAR/receipt"; then fail "the retry must leave nothing recorded"; fi

scenario "not the running system: refuse, touch nothing"
setup_applied
cp "$VAR/receipt" "$T/before"
if hook CA_CERTS_BOOTED_ROOT=/ 2>"$T/err"; then fail "changes made to another system must not be reported undone"; fi
grep -q 'boot from' "$T/err" || fail "the refusal must say how to finish: $(cat "$T/err")"
cmp -s "$T/before" "$VAR/receipt" || fail "a refusal must leave the receipt exactly as it was"
[ ! -s "$SEC/log" ] || fail "a refusal must not call security: $(cat "$SEC/log")"

scenario "nothing recorded: exit 0, no calls"
setup_applied
hook
: > "$SEC/log"
hook || fail "a second uninstall attempt with nothing left must succeed"
[ ! -s "$SEC/log" ] || fail "nothing recorded means nothing to do"
rm -f "$VAR/receipt"
hook || fail "no receipt at all must succeed"

scenario "junk receipt: nothing that is not a SHA-1 reaches security"
setup_applied
hook
printf 'trusted ../../etc/passwd\ndenied abc\nimported -rf\n' >> "$VAR/receipt"
: > "$SEC/log"
hook || fail "junk lines must be ignored, not fatal"
[ ! -s "$SEC/log" ] || fail "junk reached security: $(cat "$SEC/log")"

scenario "imported with no trusted/denied line: delete if present in the keychain, leave alone if absent"
setup_applied
hook || fail "clearing the setup's receipt failed"
X="$(mkcert x "$T")"
Y="$(mkcert y "$T")"
printf '%s\n' "$X" >> "$SEC/keychain"
printf 'imported %s\nimported %s\n' "$X" "$Y" >> "$VAR/receipt"
: > "$SEC/log"
hook || fail "an orphaned imported entry (no trusted/denied line) must not fail the hook"
if grep -q "^$X\$" "$SEC/keychain"; then fail "an orphaned imported cert present in the keychain must be deleted: $(cat "$SEC/keychain")"; fi
grep -q "delete-certificate -Z $X " "$SEC/log" || fail "the present orphan must reach security: $(cat "$SEC/log")"
if grep -q "$Y" "$SEC/log"; then fail "an orphaned imported cert absent from the keychain must not reach security: $(cat "$SEC/log")"; fi
if grep -q -E '^(trusted|denied|imported) ' "$VAR/receipt"; then fail "both orphaned entries must leave the receipt once undone"; fi

# spec: docs/TRUST-POLICY.md #9 -- a receipt that exists but cannot be read is not
#       "nothing recorded"; exiting 0 would let the uninstall delete the only record of our changes
scenario "an unreadable receipt: fail, remove nothing"
setup_applied
cp "$VAR/receipt" "$T/before"
chmod 000 "$VAR/receipt"
if [ -r "$VAR/receipt" ]; then
  chmod 644 "$VAR/receipt"
  scenario "  (skipped: this user can read a mode-000 file)"
else
  if hook 2>"$T/err"; then chmod 644 "$VAR/receipt"; fail "an unreadable receipt must fail the hook, so nothing is removed"; fi
  chmod 644 "$VAR/receipt"
  grep -q "could not read" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
  cmp -s "$T/before" "$VAR/receipt" || fail "an unreadable receipt must be left exactly as it was"
  [ ! -s "$SEC/log" ] || fail "an unreadable receipt must not reach security: $(cat "$SEC/log")"
fi

scenario "a receipt rewrite that fails stops the hook; the retry resumes"
setup_applied
cp "$VAR/receipt" "$T/before"
# spec: docs/TRUST-POLICY.md #9 -- a full disk: 10.9's grep exits 0 having written nothing (tests/full-disk)
if hook PATH="$R/tests/full-disk:$PATH" FULL_DISK_ON="^trusted " 2>"$T/err"; then fail "a failed receipt rewrite must fail the hook, so nothing is removed"; fi
grep -q "could not rewrite" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
cmp -s "$T/before" "$VAR/receipt" || fail "a failed rewrite must leave the receipt exactly as it was: $(cat "$VAR/receipt")"
grep -q "^trusted $A\$" "$VAR/receipt" || fail "the entry whose drop failed must stay for the retry: $(cat "$VAR/receipt")"
grep -q "^imported $A\$" "$VAR/receipt" || fail "entries not yet undone must stay for the retry: $(cat "$VAR/receipt")"
hook 2>/dev/null || fail "the retry must finish the undo"
if grep -q -E '^(trusted|denied|imported) ' "$VAR/receipt"; then fail "the retry must leave nothing recorded"; fi
[ "$(cat "$SEC/keychain")" = "$B" ] || fail "the retry must delete what we imported: $(cat "$SEC/keychain")"

scenario "AquaTransport's root component ran after us: the roots it claims outlive our uninstall, ours go"
setup_applied
C="$(mkcert c "$TREE/share/ca-certs/trusted")"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "applying C failed"
mkdir -p "$ROOT/private/var/db/receipts"
: > "$ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
printf '# fixture\ntrust %s a\ndistrust %s d\n' "$A" "$D" > "$TREE/share/ca-certs/aquatransport-roots.txt"
"$SECURITY" add-trusted-cert -d -r deny -k kc "$TREE/share/ca-certs/distrust/$D.pem"
: > "$SEC/log"
hook 2>/dev/null || fail "the hook failed"
grep -q "^$A trustRoot " "$SEC/admin" || fail "AquaTransport's root component also trusts A, and never undoes that: our uninstall must leave A trusted: $(cat "$SEC/admin")"
grep -q "^$D deny \$" "$SEC/admin" || fail "AquaTransport's root component denies D for every use: our uninstall must leave that: $(cat "$SEC/admin")"
grep -qx "$A" "$SEC/keychain" && grep -qx "$D" "$SEC/keychain" \
  || fail "A and D must stay in System.keychain, where AquaTransport's settings need them: $(cat "$SEC/keychain")"
if grep -q "^$C " "$SEC/admin"; then fail "C is ours alone: its trust must go"; fi
if grep -qx "$C" "$SEC/keychain"; then fail "C is ours alone: the certificate we imported must go"; fi

scenario "the same claims without AquaTransport's receipt: everything we recorded is undone"
setup_applied
printf '# fixture\ntrust %s a\ndistrust %s d\n' "$A" "$D" > "$TREE/share/ca-certs/aquatransport-roots.txt"
hook 2>/dev/null || fail "the hook failed"
[ "$(cat "$SEC/admin")" = "$B trustRoot " ] || fail "with no AquaTransport receipt, its list claims nothing: $(cat "$SEC/admin")"
[ "$(cat "$SEC/keychain")" = "$B" ] || fail "with no AquaTransport receipt, everything we imported goes: $(cat "$SEC/keychain")"

scenario "a claimed root whose setting someone removed by hand: we still delete the certificate we imported"
setup_applied
mkdir -p "$ROOT/private/var/db/receipts"
: > "$ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
printf '# fixture\ntrust %s a\n' "$A" > "$TREE/share/ca-certs/aquatransport-roots.txt"
"$SECURITY" remove-trusted-cert -d "$VAR/certs/$A.pem"
hook 2>/dev/null || fail "the hook failed"
if grep -qx "$A" "$SEC/keychain"; then fail "A has no admin setting, so AquaTransport's root component did not set it: the certificate we imported must go: $(cat "$SEC/keychain")"; fi

scenario "a claimed root we set with AquaTransport already installed: it never set it, so our uninstall undoes it"
setup_applied at-first
hook 2>/dev/null || fail "the hook failed"
[ "$(cat "$SEC/admin")" = "$B trustRoot " ] || fail "A's setting is ours, made after AquaTransport's root component ran: it must go: $(cat "$SEC/admin")"
[ "$(cat "$SEC/keychain")" = "$B" ] || fail "A's certificate is one we imported: it must go: $(cat "$SEC/keychain")"

# spec: docs/TRUST-POLICY.md #8, #9 and #14 -- blocked intermediates, as the pkg ships them, are
#       removed from the admin domain in one import, and a key still there keeps the receipt
mkblocked() {
  mkdir -p "$TREE/share/ca-certs/blocked"
  _m="$(mkcert "$1" "$TREE/share/ca-certs/blocked")"
  printf '%s %s %s\n' "$_m" "$(printf 'issuer-%s' "$_m" | base64)" "$(printf 'serial-%s' "$_m" | base64)" >> "$TREE/share/ca-certs/blocked.entries"
  printf '%s\n' "$_m"
}
calls() { grep -c "^$1" "$SEC/log" || :; }

scenario "removes every blocked entry in one import"
setup_applied
BA="$(mkblocked ba)"; BB="$(mkblocked bb)"; BC="$(mkblocked bc)"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "applying the blocked intermediates failed"
grep -q "^blocked $BA\$" "$VAR/receipt" || fail "setup must record the blocked intermediates: $(cat "$VAR/receipt")"
: > "$SEC/log"
hook || fail "the hook failed"
for b in $BA $BB $BC; do
  if grep -q "^$b " "$SEC/admin"; then fail "$b must have no admin setting: $(cat "$SEC/admin")"; fi
done
[ "$(calls trust-settings-import)" = 1 ] || fail "every blocked entry must go in one import: $(cat "$SEC/log")"
if grep -q -E '^(trusted|denied|imported|blocked) ' "$VAR/receipt"; then fail "undone entries must leave the receipt: $(cat "$VAR/receipt")"; fi
[ "$(cat "$SEC/admin")" = "$B trustRoot " ] || fail "only the user's own setting may remain: $(cat "$SEC/admin")"

scenario "uninstall leaves a user's entry alone"
setup_applied
BA="$(mkblocked ba)"; BU="$(mkblocked bu)"
"$SECURITY" add-trusted-cert -d -r deny "$TREE/share/ca-certs/blocked/$BU.pem"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "applying the blocked intermediates failed"
grep -q "^preexisting $BU\$" "$VAR/receipt" || fail "the user's entry must be preexisting: $(cat "$VAR/receipt")"
hook || fail "the hook failed"
grep -q "^$BU deny " "$SEC/admin" || fail "the user's own entry must survive: $(cat "$SEC/admin")"
if grep -q "^$BA " "$SEC/admin"; then fail "our entry must go: $(cat "$SEC/admin")"; fi

scenario "a failed import keeps the receipt"
setup_applied
BA="$(mkblocked ba)"; BB="$(mkblocked bb)"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "applying the blocked intermediates failed"
if hook FAKE_SEC_FAIL_IMPORT=1 2>"$T/err"; then fail "a failed import must fail the hook, so nothing is removed"; fi
grep -q "^blocked $BA\$" "$VAR/receipt" && grep -q "^blocked $BB\$" "$VAR/receipt" \
  || fail "blocked entries still set must stay for the retry: $(cat "$VAR/receipt")"
grep -q "^$BA deny ssl\$" "$SEC/admin" || fail "the failed import must change nothing: $(cat "$SEC/admin")"
hook || fail "the retry must finish the undo"
if grep -q -E '^(trusted|denied|imported|blocked) ' "$VAR/receipt"; then fail "the retry must leave nothing recorded: $(cat "$VAR/receipt")"; fi

scenario "a blocked setting the user already removed is just forgotten"
setup_applied
BA="$(mkblocked ba)"; BB="$(mkblocked bb)"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "applying the blocked intermediates failed"
"$SECURITY" remove-trusted-cert -d "$TREE/share/ca-certs/blocked/$BA.pem"
hook || fail "the hook failed"
if grep -q -E '^(trusted|denied|imported|blocked) ' "$VAR/receipt"; then fail "both entries must leave the receipt: $(cat "$VAR/receipt")"; fi
if grep -q "^$BB " "$SEC/admin"; then fail "BB must go: $(cat "$SEC/admin")"; fi

scenario "uninstall after a .3 upgrade deletes the keychain copy"
setup_applied
hook || fail "clearing the setup's receipt failed"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "re-applying failed"
BE="$(mkcert be "$TREE/share/ca-certs/distrust")"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "the .3-shaped apply failed"
grep -q "^denied $BE\$" "$VAR/receipt" || fail "setup must record BE as denied: $(cat "$VAR/receipt")"
mv "$TREE/share/ca-certs/distrust/$BE.pem" "$TREE/share/ca-certs/blocked/" 2>/dev/null || { mkdir -p "$TREE/share/ca-certs/blocked"; mv "$TREE/share/ca-certs/distrust/$BE.pem" "$TREE/share/ca-certs/blocked/"; }
printf '%s %s %s\n' "$BE" "$(printf 'issuer-%s' "$BE" | base64)" "$(printf 'serial-%s' "$BE" | base64)" >> "$TREE/share/ca-certs/blocked.entries"
sh "$TREE/libexec/ca-certs-apply" --root "$ROOT" 2>/dev/null || fail "the upgrading apply failed"
grep -q "^blocked $BE\$" "$VAR/receipt" && grep -q "^imported $BE\$" "$VAR/receipt" || fail "setup must be migrated: $(cat "$VAR/receipt")"
hook || fail "the hook failed"
if grep -q "^$BE " "$SEC/admin"; then fail "BE's admin setting must go: $(cat "$SEC/admin")"; fi
if grep -qx "$BE" "$SEC/keychain"; then fail "BE's keychain copy must go: $(cat "$SEC/keychain")"; fi

echo "pre-uninstall: ok"
