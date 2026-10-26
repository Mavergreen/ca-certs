#!/bin/sh
# platform: macOS-only -- builds a fixture DMG with pkgbuild, productbuild and hdiutil, as the generator reads one
# spec: docs/TRUST-POLICY.md #12
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/caatroots.XXXXXX")"
trap 'rm -rf "$T"' EXIT
G="$R/build/aquatransport-roots.sh"
C="$R/build/aquatransport-conflicts.sh"
L="$R/aquatransport-roots.txt"

scenario "the committed list: a header, then trust and distrust lines with a SHA-1 and a label"
[ -f "$L" ] || fail "aquatransport-roots.txt is missing"
bad="$(awk '!/^#/ && !(($1 == "trust" || $1 == "distrust") && $2 ~ /^[0-9A-F]+$/ && length($2) == 40 && NF >= 3) { print NR ": " $0 }' "$L")"
[ -z "$bad" ] || fail "aquatransport-roots.txt has lines that are neither a comment nor 'trust|distrust SHA1 label':
$bad"
grep -q '^trust ' "$L" && grep -q '^distrust ' "$L" || fail "aquatransport-roots.txt must list both trusted and distrusted roots"
grep -q '^# .*Wowfunhappy.AquaTransport.ModernRootCertificates [0-9]' "$L" || fail "aquatransport-roots.txt's header must name the component and its version"

mkcert() {
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key" -out "$2" -days 2 -subj "/CN=$1" >/dev/null 2>&1
  openssl x509 -noout -fingerprint -sha1 -in "$2" | sed 's/.*=//' | tr -d :
}
fixture() {  # $1=DMG to write; trusts "Root One", distrusts "Old Root"
  rm -rf "$T/s" "$T/img"; mkdir -p "$T/s/trust" "$T/s/distrust" "$T/img"
  printf '#!/bin/sh\nexit 0\n' > "$T/s/postinstall"; chmod 755 "$T/s/postinstall"
  ONE="$(mkcert one "$T/s/trust/Root One.pem")"
  OLD="$(mkcert old "$T/s/distrust/Old Root.pem")"
  pkgbuild --nopayload --scripts "$T/s" --identifier Wowfunhappy.AquaTransport.ModernRootCertificates \
    --version 2026.09.03 "$T/mrc.pkg" >/dev/null 2>&1 || fail "pkgbuild failed"
  productbuild --package "$T/mrc.pkg" "$T/img/AquaTransport.pkg" >/dev/null 2>&1 || fail "productbuild failed"
  rm -f "$1"
  hdiutil create -quiet -srcfolder "$T/img" -format UDZO "$1" || fail "hdiutil create failed"
}

scenario "the generator reads the component's trust and distrust certificates out of the DMG"
fixture "$T/at.dmg"
sh "$G" "$T/at.dmg" > "$T/out" || fail "the generator failed on the fixture DMG"
grep -q '^# .*Wowfunhappy.AquaTransport.ModernRootCertificates 2026.09.03' "$T/out" || fail "the header must name the component's version: $(cat "$T/out")"
grep -qx "trust $ONE Root One" "$T/out" || fail "want 'trust $ONE Root One' in: $(cat "$T/out")"
grep -qx "distrust $OLD Old Root" "$T/out" || fail "want 'distrust $OLD Old Root' in: $(cat "$T/out")"
[ "$(grep -vc '^#' "$T/out")" = 2 ] || fail "the fixture has two roots: $(cat "$T/out")"

scenario "--check passes when only the header differs, and fails, showing the difference, when a root does"
{ echo "# an older header"; grep -v '^#' "$T/out"; } > "$T/same"
sh "$G" --check "$T/same" "$T/at.dmg" >/dev/null 2>&1 || fail "--check must ignore the header"
grep -v "^distrust " "$T/out" > "$T/fewer"
rc=0; sh "$G" --check "$T/fewer" "$T/at.dmg" > "$T/diff" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "--check must exit 1 when the DMG distrusts a root the list lacks, exited $rc"
grep -q "Old Root" "$T/diff" || fail "--check must show the root that differs: $(cat "$T/diff")"

scenario "aquatransport-conflicts.sh fails when AquaTransport trusts a root we distrust, or the other way round"
mkdir -p "$T/ours/trusted" "$T/ours/distrust"
: > "$T/none"
cp "$T/s/trust/Root One.pem" "$T/ours/trusted/$ONE.pem"; cp "$T/s/distrust/Old Root.pem" "$T/ours/distrust/$OLD.pem"
sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/none" >/dev/null 2>&1 || fail "aquatransport-conflicts.sh must pass when we agree"
mv "$T/ours/distrust/$OLD.pem" "$T/ours/trusted/$OLD.pem"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/none" > "$T/c" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "aquatransport-conflicts.sh must fail when AquaTransport distrusts a root we trust"
grep -q "$OLD" "$T/c" || fail "aquatransport-conflicts.sh must name the root: $(cat "$T/c")"
mv "$T/ours/trusted/$ONE.pem" "$T/ours/distrust/$ONE.pem"; mv "$T/ours/trusted/$OLD.pem" "$T/ours/distrust/$OLD.pem"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/none" > "$T/c" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "aquatransport-conflicts.sh must fail when AquaTransport trusts a root we distrust"
grep -q "$ONE" "$T/c" || fail "aquatransport-conflicts.sh must name the root: $(cat "$T/c")"

scenario "aquatransport-conflicts.sh fails when AquaTransport trusts or distrusts a root we have no position on"
rm -rf "$T/ours"; mkdir -p "$T/ours/trusted" "$T/ours/distrust"
cp "$T/s/distrust/Old Root.pem" "$T/ours/distrust/$OLD.pem"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/none" > "$T/c" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "aquatransport-conflicts.sh must fail when AquaTransport trusts a root we don't, exited $rc"
grep -q "$ONE" "$T/c" || fail "aquatransport-conflicts.sh must name the root we don't trust: $(cat "$T/c")"
rm -rf "$T/ours"; mkdir -p "$T/ours/trusted" "$T/ours/distrust"
cp "$T/s/trust/Root One.pem" "$T/ours/trusted/$ONE.pem"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/none" > "$T/c" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "aquatransport-conflicts.sh must fail when AquaTransport distrusts a root we don't, exited $rc"
grep -q "$OLD" "$T/c" || fail "aquatransport-conflicts.sh must name the root we don't distrust: $(cat "$T/c")"

scenario "a declared difference, with its reason, excuses only the root it names"
printf '# why\ndistrust %s we leave it alone for a reason\n' "$OLD" > "$T/diffs"
sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/diffs" > "$T/c" 2>&1 || fail "a declared difference must excuse its root: $(cat "$T/c")"
printf 'trust %s the wrong kind\n' "$OLD" > "$T/diffs"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/diffs" > "$T/c" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "a 'trust' difference must not excuse a root AquaTransport distrusts, exited $rc"
grep -q "AquaTransport distrusts $OLD" "$T/c" || fail "a 'trust' difference must leave the distrusted root unexcused: $(cat "$T/c")"
printf 'distrust %s\n' "$OLD" > "$T/diffs"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/diffs" > "$T/c" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "a declared difference with no reason must fail"
grep -q "reason" "$T/c" || fail "a difference with no reason must say so: $(cat "$T/c")"

scenario "a declared difference that excuses nothing fails, so none outlives its reason"
cp "$T/s/distrust/Old Root.pem" "$T/ours/distrust/$OLD.pem"
printf 'distrust %s we leave it alone for a reason\n' "$OLD" > "$T/diffs"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/diffs" > "$T/c" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "a difference for a root we now distrust too must fail, exited $rc"
grep -q "$OLD" "$T/c" || fail "a stale difference must name its root: $(cat "$T/c")"

scenario "a declared difference never excuses a contradiction"
mv "$T/ours/distrust/$OLD.pem" "$T/ours/trusted/$OLD.pem"
rc=0; sh "$C" "$T/out" "$T/ours/trusted" "$T/ours/distrust" "$T/diffs" > "$T/c" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "a difference must not excuse AquaTransport distrusting a root we trust, exited $rc"

scenario "the committed differences each name a root and give a reason"
Df="$R/aquatransport-differences.txt"
[ -f "$Df" ] || fail "aquatransport-differences.txt is missing"
bad="$(awk '!/^#/ && NF && !(($1 == "trust" || $1 == "distrust") && $2 ~ /^[0-9A-F]+$/ && length($2) == 40 && NF >= 3) { print NR ": " $0 }' "$Df")"
[ -z "$bad" ] || fail "aquatransport-differences.txt has lines that are neither a comment nor 'trust|distrust SHA1 reason':
$bad"

scenario "the watcher compares the live download with the committed list, daily"
Wf="$R/.github/workflows/aquatransport-roots.yml"
[ -f "$Wf" ] || fail "aquatransport-roots.yml is missing: nothing would notice AquaTransport changing its roots"
grep -qE '^ +- cron: ' "$Wf" || fail "aquatransport-roots.yml must run on a schedule"
grep -q 'sh build/aquatransport-roots.sh --check aquatransport-roots.txt ' "$Wf" || fail "aquatransport-roots.yml must run --check against the committed list"
grep -q 'https://mavericksforever.com/downloads/AquaTransport.dmg' "$Wf" || fail "aquatransport-roots.yml must read the DMG users download"

echo "aquatransport-roots: ok"
