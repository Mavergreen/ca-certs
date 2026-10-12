#!/bin/sh
# platform: macOS-only -- the applier uses BSD stat and plutil, as the 10.9 install does
# spec: docs/TRUST-POLICY.md #4, #6, #7, #8 and #9
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/caapply.XXXXXX")"
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
  TREE="$ROOT/usr/local/mavergreen/ca-certs"; VAR="$ROOT/usr/local/mavergreen/var/ca-certs"
  mkdir -p "$TREE/libexec/mavergreen" "$TREE/share/ca-certs/trusted" "$TREE/share/ca-certs/distrust" "$SEC" "$ROOT/Library/Keychains"
  cp "$R/payload/libexec/ca-certs-apply" "$R/payload/libexec/ca-certs-lib.sh" "$TREE/libexec/"
  cp "$R/payload/libexec/mavergreen/pre-uninstall" "$TREE/libexec/mavergreen/" 2>/dev/null || :
  echo 3.130.0 > "$TREE/share/ca-certs/nss-version"
  export FAKE_SEC_STATE="$SEC" FAKE_SEC_ROOT="$ROOT" CA_CERTS_BOOTED_ROOT="$ROOT" CA_CERTS_OS_VERSION=10.9.5
  unset FAKE_SEC_SILENT_ADD FAKE_SEC_FAIL_REMOVE
}
apply() { env "$@" sh "$TREE/libexec/ca-certs-apply" --root "$ROOT"; }
has() { grep -q "^$1\$" "$VAR/receipt" || fail "receipt lacks '$1':
$(cat "$VAR/receipt")"; }
lacks() { if grep -q "^$1\$" "$VAR/receipt"; then fail "receipt has '$1' but should not"; fi; }

scenario "preexisting: the user already trusts B; A is new; D is withdrawn"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"
B="$(mkcert b "$TREE/share/ca-certs/trusted")"
D="$(mkcert d "$TREE/share/ca-certs/distrust")"
"$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$TREE/share/ca-certs/trusted/$B.pem"
: > "$SEC/log"
apply || fail "first apply failed"
grep -q "^$A trustRoot \$" "$SEC/admin" || fail "A must be trusted for all policies (no -p)"
[ "$(grep -c "^$B " "$SEC/admin")" = 1 ] && grep -q "^$B trustRoot \$" "$SEC/admin" || fail "B's own setting must be untouched"
if grep -q "trusted/$B.pem" "$SEC/log"; then fail "B already had an admin setting; re-adding it would replace the user's"; fi
grep -q "^$D deny ssl\$" "$SEC/admin" || fail "D must be denied for TLS only"
has "trusted $A"; has "imported $A"; has "preexisting $B"; has "denied $D"; has "imported $D"
lacks "trusted $B"; has "backup yes"; has "keychain yes"; has "nss 3.130.0"
[ -s "$VAR/trust-settings-backup.plist" ] || fail "admin settings existed, so they must be backed up first"
[ -f "$VAR/certs/$A.pem" ] && [ -f "$VAR/certs/$D.pem" ] || fail "every touched certificate must be kept in var/ for later undo"

scenario "idempotent: a second run changes nothing"
: > "$SEC/log"
apply || fail "second apply failed"
if grep -q -E '^(add-trusted-cert|remove-trusted-cert|delete-certificate)' "$SEC/log"; then fail "a re-run must change nothing: $(cat "$SEC/log")"; fi

scenario "converge: the next release drops A and adds C; A's file is gone from the tree"
rm "$TREE/share/ca-certs/trusted/$A.pem"
C="$(mkcert c "$TREE/share/ca-certs/trusted")"
apply || fail "converging apply failed"
if grep -q "^$A " "$SEC/admin"; then fail "a root the release dropped must lose the trust we gave it"; fi
if grep -q "^$A\$" "$SEC/keychain"; then fail "a certificate we imported for a dropped root must be deleted"; fi
lacks "trusted $A"; lacks "imported $A"; has "trusted $C"

scenario "silent add: security says yes and does nothing"
E="$(mkcert e "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_SILENT_ADD="$E" 2>"$T/err"; then fail "a silent failure to trust E must fail the apply"; fi
grep -q "$E" "$T/err" || fail "the failure must name E: $(cat "$T/err")"
lacks "trusted $E"

scenario "not the running system: files only, no security calls"
fresh
mkcert f "$TREE/share/ca-certs/trusted" >/dev/null
apply CA_CERTS_BOOTED_ROOT=/ || fail "a non-boot volume must install, not fail"
[ ! -s "$SEC/log" ] || fail "a non-boot volume must not be touched through securityd: $(cat "$SEC/log")"
grep -q '^keychain no ' "$VAR/receipt" || fail "the receipt must say the keychain was not changed"

scenario "macOS 11 and later: files only"
fresh
mkcert g "$TREE/share/ca-certs/trusted" >/dev/null
apply CA_CERTS_OS_VERSION=11.7.10 || fail "macOS 11 must install, not fail"
[ ! -s "$SEC/log" ] || fail "macOS 11 must not be asked for admin trust changes"

scenario "no admin settings at start: nothing to back up, and the receipt says so"
fresh
mkcert h "$TREE/share/ca-certs/trusted" >/dev/null
apply || fail "apply with no prior admin settings failed"
has "backup none"
[ ! -f "$VAR/trust-settings-backup.plist" ] || fail "there was nothing to back up"

scenario "changes recorded, then the OS moved to 11: keep the record, change nothing"
cp "$VAR/receipt" "$T/before"
apply CA_CERTS_OS_VERSION=11.7.10 || fail "apply on 11 with an old record must not fail"
cmp -s "$T/before" "$VAR/receipt" || fail "the record of earlier changes must survive untouched"

# spec: docs/TRUST-POLICY.md #9 -- a query used inline as another command's argument loses
#       a failing exit status to command substitution; assigning it to a variable first restores it
scenario "swallowed query failures: a one-shot find-certificate failure must fail the apply, not proceed on empty output"
fresh
I="$(mkcert i "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_ONCE=find-certificate 2>"$T/err"; then fail "a failed keychain query must fail the apply"; fi
grep -q "could not list" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
lacks "trusted $I"; lacks "imported $I"
if grep -q "^$I " "$SEC/admin"; then fail "a query failure must stop before any admin trust change: $(cat "$SEC/admin")"; fi

scenario "add-trusted-cert imports into the keychain but then fails: the intent is reconciled immediately"
fresh
J="$(mkcert j "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_AFTER_IMPORT="$J" 2>"$T/err"; then fail "a failed add-trusted-cert must fail the apply"; fi
grep -q "$J" "$T/err" || fail "the failure must name J: $(cat "$T/err")"
# spec: docs/TRUST-POLICY.md #9 -- intent is recorded BEFORE the add, then reconciled with a checked
#       listing right after a failed add: the import really happened (kept), the trust setting
#       never did (dropped), told apart by that listing rather than guessed
has "imported $J"; lacks "trusted $J"

scenario "undo of an already-removed setting: the admin entry is gone but the receipt still says trusted"
fresh
K="$(mkcert k "$TREE/share/ca-certs/trusted")"
apply || fail "seed apply for K failed"
has "trusted $K"
"$SECURITY" remove-trusted-cert -d "$TREE/share/ca-certs/trusted/$K.pem" || fail "could not simulate the user removing K's admin setting"
rm "$TREE/share/ca-certs/trusted/$K.pem"
: > "$SEC/log"
apply || fail "converging past an already-removed admin setting must not fail"
lacks "trusted $K"
if grep -q '^remove-trusted-cert' "$SEC/log"; then fail "an already-removed admin setting must not be removed again: $(cat "$SEC/log")"; fi

scenario "already in the keychain without an admin setting: adding trust must not claim we imported it"
fresh
L="$(mkcert l "$TREE/share/ca-certs/trusted")"
printf '%s\n' "$L" >> "$SEC/keychain"
apply || fail "apply with a pre-existing keychain entry failed"
has "trusted $L"
lacks "imported $L"

scenario "converge: security fails to remove a dropped root's admin trust; the receipt keeps the entry"
fresh
M="$(mkcert m "$TREE/share/ca-certs/trusted")"
apply || fail "adding M failed"
has "trusted $M"
rm "$TREE/share/ca-certs/trusted/$M.pem"
if apply FAKE_SEC_FAIL_REMOVE="$M" 2>"$T/err"; then fail "a failed removal must fail the apply"; fi
grep -q "$M" "$T/err" || fail "the failure must name M: $(cat "$T/err")"
has "trusted $M"

scenario "converge: security fails to delete an imported certificate from the keychain"
fresh
N="$(mkcert n "$TREE/share/ca-certs/trusted")"
apply || fail "adding N failed"
has "trusted $N"; has "imported $N"
rm "$TREE/share/ca-certs/trusted/$N.pem"
if apply FAKE_SEC_FAIL_DELETE="$N" 2>"$T/err"; then fail "a failed keychain delete must fail the apply"; fi
grep -q "$N" "$T/err" || fail "the failure must name N: $(cat "$T/err")"

scenario "converge: a distrusted (denied) root is dropped by a later release"
fresh
O="$(mkcert o "$TREE/share/ca-certs/distrust")"
apply || fail "adding the denied root O failed"
has "denied $O"
rm "$TREE/share/ca-certs/distrust/$O.pem"
apply || fail "dropping a denied root failed"
lacks "denied $O"
if grep -q "^$O " "$SEC/admin"; then fail "a dropped denied root must lose its deny setting: $(cat "$SEC/admin")"; fi

scenario "Admin.plist already exists but is empty at the very start: nothing to back up"
fresh
mkdir -p "$ROOT/Library/Security/Trust Settings"
: > "$ROOT/Library/Security/Trust Settings/Admin.plist"
P="$(mkcert p "$TREE/share/ca-certs/trusted")"
apply || fail "apply with a pre-existing empty Admin.plist failed"
has "backup none"
has "trusted $P"
[ ! -f "$VAR/trust-settings-backup.plist" ] || fail "there was nothing to back up"

scenario "an emptied Admin.plist may survive removal (real 10.9 uncertain behavior): later runs still work"
fresh
Q="$(mkcert q "$TREE/share/ca-certs/trusted")"
apply || fail "seed apply for Q failed"
has "trusted $Q"
rm "$TREE/share/ca-certs/trusted/$Q.pem"
apply FAKE_SEC_KEEP_EMPTY_ADMIN_FILE=1 || fail "converging past Q, with the fake leaving an empty Admin.plist behind, must not fail"
[ -f "$ROOT/Library/Security/Trust Settings/Admin.plist" ] || fail "the fake did not leave an empty Admin.plist, as FAKE_SEC_KEEP_EMPTY_ADMIN_FILE requires"
[ ! -s "$ROOT/Library/Security/Trust Settings/Admin.plist" ] || fail "the fake's lingering Admin.plist should be empty"
lacks "trusted $Q"
W="$(mkcert w "$TREE/share/ca-certs/trusted")"
apply || fail "a later apply must treat the lingering empty Admin.plist as no settings, not die"
has "trusted $W"

# spec: docs/TRUST-POLICY.md #9 -- a listing taken right AFTER a successful add must not
#       be able to make our own change look untracked or, on the next run, "preexisting"
scenario "a keychain listing fails right after a successful add: the change must not look untracked"
fresh
S="$(mkcert s "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_ONCE=find-certificate:3 2>"$T/err"; then fail "a failed post-add keychain listing must fail the apply"; fi
grep -q "could not list" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
has "trusted $S"; has "imported $S"
grep -q "^$S trustRoot \$" "$SEC/admin" || fail "S must actually be trusted despite the listing failure: $(cat "$SEC/admin")"
: > "$SEC/log"
apply || fail "a second run after the listing failure must converge cleanly"
if grep -q '^add-trusted-cert' "$SEC/log"; then fail "a second run must not re-add S: $(cat "$SEC/log")"; fi
lacks "preexisting $S"

scenario "an admin listing fails right after a successful add: the change must not look untracked"
fresh
U="$(mkcert u "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_ONCE=trust-settings-export 2>"$T/err"; then fail "a failed post-add admin listing must fail the apply"; fi
grep -q "could not read the admin trust settings" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
grep -q "FAKE_SEC_FAIL_ONCE" "$T/err" || fail "the failure must carry security's own reason, for install.log: $(cat "$T/err")"
has "trusted $U"; has "imported $U"
grep -q "^$U trustRoot \$" "$SEC/admin" || fail "U must actually be trusted despite the listing failure: $(cat "$SEC/admin")"
: > "$SEC/log"
apply || fail "a second run after the listing failure must converge cleanly"
if grep -q '^add-trusted-cert' "$SEC/log"; then fail "a second run must not re-add U: $(cat "$SEC/log")"; fi
lacks "preexisting $U"

scenario "a genuinely user-owned setting is still left alone, unaffected by pre-recording intent"
fresh
V="$(mkcert v "$TREE/share/ca-certs/trusted")"
"$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$TREE/share/ca-certs/trusted/$V.pem"
: > "$SEC/log"
apply || fail "apply over a user-owned setting failed"
has "preexisting $V"
lacks "trusted $V"; lacks "imported $V"
if grep -q "trusted/$V.pem" "$SEC/log"; then fail "V already had an admin setting; it must never be re-added: $(cat "$SEC/log")"; fi
: > "$SEC/log"
apply || fail "a re-run over a still-present user-owned setting failed"
has "preexisting $V"
if grep -q "trusted/$V.pem" "$SEC/log"; then fail "V's setting is still there; a re-run must leave it alone: $(cat "$SEC/log")"; fi

# spec: docs/TRUST-POLICY.md #9 -- a preexisting line is only as good as the admin
#       listing that still shows its setting; once the setting is gone the root is ours to trust
scenario "a preexisting setting that later disappears is trusted on the next run, and recorded as ours"
"$SECURITY" remove-trusted-cert -d "$TREE/share/ca-certs/trusted/$V.pem" || fail "could not simulate the user removing V's own setting"
: > "$SEC/log"
apply || fail "apply after the user's own setting went away failed"
grep -q "^$V trustRoot \$" "$SEC/admin" || fail "V must be trusted once its preexisting setting is gone: $(cat "$SEC/admin")"
lacks "preexisting $V"; has "trusted $V"
lacks "imported $V"

# spec: docs/TRUST-POLICY.md #9 -- every run reconciles the receipt against checked
#       listings, so a recorded change that never took hold is re-applied, not skipped forever
scenario "a recorded trust setting that never took hold is re-applied, not skipped forever"
fresh
Y1="$(mkcert y1 "$TREE/share/ca-certs/trusted")"
apply || fail "seed apply for Y1 failed"
has "trusted $Y1"
"$SECURITY" remove-trusted-cert -d "$TREE/share/ca-certs/trusted/$Y1.pem" || fail "could not simulate the missing admin setting"
: > "$SEC/log"
apply || fail "re-applying a recorded-but-missing trust setting must not be skipped"
grep -q '^add-trusted-cert' "$SEC/log" || fail "Y1 must actually be re-added, not skipped: $(cat "$SEC/log")"
grep -q "^$Y1 trustRoot \$" "$SEC/admin" || fail "Y1 must really be re-trusted: $(cat "$SEC/admin")"
has "trusted $Y1"

scenario "add-trusted-cert imports then fails; a clean second run finishes the job"
fresh
Z="$(mkcert z "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_AFTER_IMPORT="$Z" 2>"$T/err"; then fail "a failed add-trusted-cert must fail the apply"; fi
grep -q "$Z" "$T/err" || fail "the failure must name Z: $(cat "$T/err")"
: > "$SEC/log"
apply || fail "the second, clean run must finish trusting Z"
has "trusted $Z"; has "imported $Z"
grep -q "^$Z trustRoot \$" "$SEC/admin" || fail "Z must really be trusted: $(cat "$SEC/admin")"
grep -q "^$Z\$" "$SEC/keychain" || fail "Z must really be in the keychain: $(cat "$SEC/keychain")"

scenario "a clean add-trusted-cert failure (nothing changed) is retried and finished cleanly"
fresh
X="$(mkcert x "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_ADD="$X" 2>"$T/err"; then fail "a clean add failure must fail the apply"; fi
grep -q "$X" "$T/err" || fail "the failure must name X: $(cat "$T/err")"
lacks "trusted $X"; lacks "imported $X"
if grep -q "^$X " "$SEC/admin"; then fail "X must not actually be trusted after a clean add failure: $(cat "$SEC/admin")"; fi
if grep -q "^$X\$" "$SEC/keychain"; then fail "X must not actually be in the keychain after a clean add failure: $(cat "$SEC/keychain")"; fi
: > "$SEC/log"
apply || fail "the second run must add X cleanly"
has "trusted $X"; has "imported $X"
grep -q "^$X trustRoot \$" "$SEC/admin" || fail "X must really be trusted: $(cat "$SEC/admin")"
grep -q "^$X\$" "$SEC/keychain" || fail "X must really be in the keychain: $(cat "$SEC/keychain")"

scenario "a stale import record must not survive to claim a cert the user imported themselves"
fresh
Y="$(mkcert y "$TREE/share/ca-certs/trusted")"
if apply FAKE_SEC_FAIL_ADD="$Y" 2>"$T/err"; then fail "a clean add failure must fail the apply"; fi
lacks "trusted $Y"; lacks "imported $Y"
printf '%s\n' "$Y" >> "$SEC/keychain"
: > "$SEC/log"
apply || fail "a later apply must succeed once the user has imported Y themselves"
has "trusted $Y"
lacks "imported $Y"
grep -q "^$Y trustRoot \$" "$SEC/admin" || fail "Y must really be trusted: $(cat "$SEC/admin")"

# spec: docs/TRUST-POLICY.md #9 -- a receipt read or rewrite that fails must stop the
#       run with the record intact. A read error is grep's status 2 (tests/fake-grep); a write that
#       fails is a full disk (tests/full-disk), where 10.9's grep still exits 0 with a short file
grep_fails_on() { _on="$1"; shift; touch "$T/arm"; apply PATH="$R/tests/fake-grep:$PATH" FAKE_GREP_ARM="$T/arm" FAKE_GREP_FAIL_ON="$_on" "$@"; }
disk_full_on() { _on="$1"; shift; apply PATH="$R/tests/full-disk:$PATH" FULL_DISK_ON="$_on" "$@"; }
no_writes() { if grep -q -E '^(add-trusted-cert|remove-trusted-cert|delete-certificate|trust-settings-export)' "$SEC/log"; then fail "$1: $(cat "$SEC/log")"; fi; }

scenario "a receipt rewrite that fails stops the apply, and the receipt survives whole"
fresh
AA="$(mkcert aa "$TREE/share/ca-certs/trusted")"
apply 2>/dev/null || fail "seed apply for AA failed"
cp "$VAR/receipt" "$T/before"
: > "$SEC/log"
if disk_full_on "^nss " 2>"$T/err"; then fail "a failed receipt rewrite must fail the apply"; fi
grep -q "could not rewrite" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
cmp -s "$T/before" "$VAR/receipt" || fail "a failed rewrite must leave the receipt exactly as it was: $(cat "$VAR/receipt")"
no_writes "a failed receipt rewrite must stop before any trust change"

scenario "a failed rewrite while undoing a dropped root keeps its entries for the next run"
rm "$TREE/share/ca-certs/trusted/$AA.pem"
if disk_full_on "^trusted " 2>"$T/err"; then fail "a failed receipt rewrite must fail the apply"; fi
has "trusted $AA"; has "imported $AA"
apply 2>/dev/null || fail "the next clean run must finish undoing AA"
lacks "trusted $AA"; lacks "imported $AA"
if grep -q "^$AA\$" "$SEC/keychain"; then fail "the certificate we imported for AA must be deleted: $(cat "$SEC/keychain")"; fi

scenario "a new record that cannot be written stops the apply before the trust change"
fresh
AI="$(mkcert ai "$TREE/share/ca-certs/trusted")"
apply 2>/dev/null || fail "seed apply failed"
AJ="$(mkcert aj "$TREE/share/ca-certs/trusted")"
cp "$VAR/receipt" "$T/before"
: > "$SEC/log"
if disk_full_on "^trusted $AJ" 2>"$T/err"; then fail "a receipt add that cannot be written must fail the apply"; fi
grep -q "could not rewrite" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
[ "$(sort "$T/before")" = "$(sort "$VAR/receipt")" ] || fail "a failed add must leave every receipt line as it was: $(cat "$VAR/receipt")"
if grep -q "trusted/$AJ.pem" "$SEC/log"; then fail "AJ must not be trusted before its record is written: $(cat "$SEC/log")"; fi
apply 2>/dev/null || fail "the next clean run must add AJ"
has "trusted $AJ"

scenario "a receipt lookup that fails stops the apply instead of reading as not recorded"
fresh
AB="$(mkcert ab "$TREE/share/ca-certs/trusted")"
apply 2>/dev/null || fail "seed apply for AB failed"
cp "$VAR/receipt" "$T/before"
if grep_fails_on "-q ^trusted " 2>"$T/err"; then fail "a failed receipt lookup must fail the apply"; fi
lacks "preexisting $AB"
[ "$(sort "$T/before")" = "$(sort "$VAR/receipt")" ] || fail "a failed lookup must leave every receipt line as it was: $(cat "$VAR/receipt")"

scenario "an unreadable receipt stops the apply before anything, and the backup is never re-exported"
fresh
AC="$(mkcert ac "$TREE/share/ca-certs/trusted")"
AD="$(mkcert ad "$T")"
"$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$T/$AD.pem"
apply 2>/dev/null || fail "seed apply for AC failed"
has "backup yes"
cp "$VAR/trust-settings-backup.plist" "$T/backup-before"; cp "$VAR/receipt" "$T/before"
AE="$(mkcert ae "$T")"
"$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$T/$AE.pem"
chmod 000 "$VAR/receipt"
if [ -r "$VAR/receipt" ]; then
  chmod 644 "$VAR/receipt"
  scenario "  (skipped: this user can read a mode-000 file)"
else
  : > "$SEC/log"
  if apply 2>"$T/err"; then chmod 644 "$VAR/receipt"; fail "an unreadable receipt must fail the apply"; fi
  chmod 644 "$VAR/receipt"
  grep -q "could not read" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
  cmp -s "$T/before" "$VAR/receipt" || fail "an unreadable receipt must be left exactly as it was: $(cat "$VAR/receipt")"
  cmp -s "$T/backup-before" "$VAR/trust-settings-backup.plist" || fail "the saved backup must never be re-exported over"
  no_writes "an unreadable receipt must stop before anything"
fi

scenario "a receipt that lost its backup line never re-exports over the saved backup"
grep -v '^backup ' "$T/before" > "$VAR/receipt"
apply 2>/dev/null || fail "apply with the backup line missing failed"
cmp -s "$T/backup-before" "$VAR/trust-settings-backup.plist" || fail "the saved backup must never be re-exported over"
has "backup yes"

scenario "security exports an empty backup: stop before any change, never record backup yes"
fresh
AF="$(mkcert af "$TREE/share/ca-certs/trusted")"
AG="$(mkcert ag "$T")"
"$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$T/$AG.pem"
: > "$SEC/log"
if apply FAKE_SEC_EMPTY_EXPORT=1 2>"$T/err"; then fail "an empty backup must fail the apply"; fi
grep -q "empty" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
[ ! -f "$VAR/receipt" ] || lacks "backup yes"
[ ! -f "$VAR/trust-settings-backup.plist" ] || fail "an empty export must not be kept as the backup"
if grep -q '^add-trusted-cert' "$SEC/log"; then fail "no trust change may follow a failed backup: $(cat "$SEC/log")"; fi

scenario "a backup that security cannot write says why, for install.log"
fresh
AH="$(mkcert ah "$T")"
"$SECURITY" add-trusted-cert -d -r trustRoot -k kc "$T/$AH.pem"
if apply FAKE_SEC_FAIL_ONCE=trust-settings-export 2>"$T/err"; then fail "a failed backup must fail the apply"; fi
grep -q "could not back up" "$T/err" || fail "the failure must explain what happened: $(cat "$T/err")"
grep -q "FAKE_SEC_FAIL_ONCE" "$T/err" || fail "the failure must carry security's own reason: $(cat "$T/err")"

scenario "AquaTransport's root component ran after us: the next run hands the roots it claims over"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"
C="$(mkcert c "$TREE/share/ca-certs/trusted")"
D="$(mkcert d "$TREE/share/ca-certs/distrust")"
apply 2>/dev/null || fail "first apply failed"
mkdir -p "$ROOT/private/var/db/receipts"
: > "$ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
printf '# fixture\ntrust %s a\ndistrust %s d\n' "$A" "$D" > "$TREE/share/ca-certs/aquatransport-roots.txt"
"$SECURITY" add-trusted-cert -d -r deny -k kc "$TREE/share/ca-certs/distrust/$D.pem"
: > "$SEC/log"
apply 2>/dev/null || fail "the run after AquaTransport's failed"
lacks "trusted $A"; lacks "imported $A"; has "preexisting $A"
lacks "denied $D"; lacks "imported $D"; has "preexisting $D"
has "trusted $C"; has "imported $C"
grep -q "^$D deny \$" "$SEC/admin" || fail "AquaTransport's deny for every use must stand, not be replaced by our TLS-only one: $(cat "$SEC/admin")"
if grep -q -E '^(add-trusted-cert|remove-trusted-cert|delete-certificate)' "$SEC/log"; then fail "handing roots over changes no setting: $(cat "$SEC/log")"; fi

scenario "a claimed root with no admin setting stays ours, on this run and the next: AquaTransport's root component never set it"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"
mkdir -p "$ROOT/private/var/db/receipts"
: > "$ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
printf '# fixture\ntrust %s a\n' "$A" > "$TREE/share/ca-certs/aquatransport-roots.txt"
apply 2>/dev/null || fail "apply failed"
has "trusted $A"; has "imported $A"; lacks "preexisting $A"
apply 2>/dev/null || fail "the second apply failed"
has "trusted $A"; has "imported $A"; lacks "preexisting $A"

scenario "AquaTransport's root component ran again after us: the next run hands A over"
echo reinstalled > "$ROOT/private/var/db/receipts/Wowfunhappy.AquaTransport.ModernRootCertificates.plist"
: > "$SEC/log"
apply 2>/dev/null || fail "the run after AquaTransport's reinstall failed"
lacks "trusted $A"; lacks "imported $A"; has "preexisting $A"
if grep -q -E '^(add-trusted-cert|remove-trusted-cert|delete-certificate)' "$SEC/log"; then fail "handing roots over changes no setting: $(cat "$SEC/log")"; fi

mkbundle() {  # the bundle the pkg ships: share/ca-certs/ca-certificates.crt, its .sha1 index, and the contract copy
  _b="$TREE/share/ca-certs/ca-certificates.crt"; : > "$_b"; : > "$TREE/share/ca-certs/ca-certificates.sha1"
  for _f in "$TREE"/share/ca-certs/trusted/*.pem; do
    _h="$(basename "$_f" .pem)"; printf '# %s\n' "$_h" >> "$_b"; cat "$_f" >> "$_b"
    printf '%s\n' "$_h" >> "$TREE/share/ca-certs/ca-certificates.sha1"
  done
  mkdir -p "$TREE/etc/openssl/certs"; cp "$_b" "$TREE/etc/openssl/certs/ca-certificates.crt"; cp "$_b" "$T/pristine$n"
}
bundle_has() { grep -qx "# $1" "$TREE/etc/openssl/certs/ca-certificates.crt"; }
bundle_ok() {  # every label in the contract bundle is followed by exactly one certificate
  [ "$(grep -c '^# ' "$TREE/etc/openssl/certs/ca-certificates.crt")" = "$(grep -c 'BEGIN CERTIFICATE' "$TREE/etc/openssl/certs/ca-certificates.crt")" ] \
    || fail "the rewritten bundle lost its shape: $(cat "$TREE/etc/openssl/certs/ca-certificates.crt")"
}

scenario "a root the admin trust settings deny for TLS is left out of the bundle, and the receipt says so"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"; B="$(mkcert b "$TREE/share/ca-certs/trusted")"; C="$(mkcert c "$TREE/share/ca-certs/trusted")"
mkbundle
"$SECURITY" add-trusted-cert -d -r deny -k kc "$TREE/share/ca-certs/trusted/$B.pem"
"$SECURITY" add-trusted-cert -d -r deny -p ssl -k kc "$TREE/share/ca-certs/trusted/$C.pem"
apply 2>/dev/null || fail "apply failed"
bundle_has "$A" || fail "A has no deny: it must stay in the bundle"
if bundle_has "$B"; then fail "B is denied for every use: OpenSSL programs must not trust it either"; fi
if bundle_has "$C"; then fail "C is denied for TLS: OpenSSL programs must not trust it either"; fi
bundle_ok
has "bundle-omitted $B"; has "bundle-omitted $C"; lacks "bundle-omitted $A"
cmp -s "$TREE/share/ca-certs/ca-certificates.crt" "$T/pristine$n" || fail "the shipped copy in share/ must stay as shipped, so the next run starts from it"

scenario "when the deny goes away, the next run puts the root back"
"$SECURITY" remove-trusted-cert -d "$TREE/share/ca-certs/trusted/$B.pem"
apply 2>/dev/null || fail "apply failed"
bundle_has "$B" || fail "B's deny is gone: B must be back in the bundle"
lacks "bundle-omitted $B"; has "bundle-omitted $C"
bundle_ok

scenario "a deny for email only, or for one hostname, leaves the root in the bundle"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"; B="$(mkcert b "$TREE/share/ca-certs/trusted")"
mkbundle
"$SECURITY" add-trusted-cert -d -r deny -p smime -k kc "$TREE/share/ca-certs/trusted/$A.pem"
"$SECURITY" add-trusted-cert -d -r deny -p ssl -s www.example.com -k kc "$TREE/share/ca-certs/trusted/$B.pem"
apply 2>/dev/null || fail "apply failed"
cmp -s "$TREE/etc/openssl/certs/ca-certificates.crt" "$T/pristine$n" || fail "neither deny is a TLS deny for the root: the bundle must stay as shipped"
if grep -q '^bundle-omitted ' "$VAR/receipt"; then fail "nothing was left out: $(cat "$VAR/receipt")"; fi

scenario "macOS 11 and later: no trust setting changes, but the bundle still leaves out what the admin settings deny"
fresh
export CA_CERTS_OS_VERSION=11.7.10
A="$(mkcert a "$TREE/share/ca-certs/trusted")"; B="$(mkcert b "$TREE/share/ca-certs/trusted")"
mkbundle
"$SECURITY" add-trusted-cert -d -r deny -k kc "$TREE/share/ca-certs/trusted/$B.pem"
: > "$SEC/log"
apply 2>/dev/null || fail "apply failed"
if grep -q -E '^(add-trusted-cert|remove-trusted-cert|delete-certificate)' "$SEC/log"; then fail "macOS 11 and later: no trust setting may change: $(cat "$SEC/log")"; fi
grep -q '^keychain no ' "$VAR/receipt" || fail "the receipt must say the keychain was left alone"
if bundle_has "$B"; then fail "B is denied: OpenSSL programs on this Mac must not trust it either"; fi
has "bundle-omitted $B"; bundle_ok

scenario "a disk that wasn't booted: its trust settings can't be read, so the bundle stays as shipped"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"; B="$(mkcert b "$TREE/share/ca-certs/trusted")"
mkbundle
"$SECURITY" add-trusted-cert -d -r deny -k kc "$TREE/share/ca-certs/trusted/$B.pem"
apply CA_CERTS_BOOTED_ROOT="$T" 2>/dev/null || fail "apply failed"
cmp -s "$TREE/etc/openssl/certs/ca-certificates.crt" "$T/pristine$n" || fail "the running system's settings say nothing about another disk: leave its bundle as shipped"
if grep -q '^bundle-omitted ' "$VAR/receipt"; then fail "nothing was left out: $(cat "$VAR/receipt")"; fi

scenario "no admin trust settings at all: the bundle stays as shipped"
fresh
A="$(mkcert a "$TREE/share/ca-certs/trusted")"
mkbundle
rm -f "$SEC/admin"
apply CA_CERTS_OS_VERSION=11.0 2>/dev/null || fail "apply failed"
cmp -s "$TREE/etc/openssl/certs/ca-certificates.crt" "$T/pristine$n" || fail "with nothing denied, the bundle must stay as shipped"

echo "apply: ok"
