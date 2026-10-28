#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #2 and #5 -- the generated data is what the product installs; check it before it ships
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/cabundle.XXXXXX")"
trap 'rm -rf "$T"' EXIT
. "$R/tests/lib/assert.sh"

# spec: build/build-bundle.sh -- its refusals, on a fixture tree: certdata is stubbed (a "# label" and a PEM, which
#       the stubbed certdata-to-pem passes through), so this needs no download
F="$T/root"
mkdir -p "$F/build" "$F/withdrawn" "$F/blocked"
for f in build-bundle.sh lib.sh msc.sh aquatransport-conflicts.sh; do cp "$R/build/$f" "$F/build/"; done
mkcert() {  # NAME: a self-signed certificate in $T/NAME.pem
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key" -out "$T/$1.pem" -days 2 -subj "/CN=$1" >/dev/null 2>&1 || fail "openssl could not make $1"
}
fpr() { openssl x509 -noout -fingerprint "-$1" -in "$T/$2.pem" | sed 's/.*=//' | tr -d :; }
for c in rootA withdrawnW blockedB; do mkcert "$c"; done
printf '#!/bin/sh\n# platform: host-agnostic\n# spec: tests/bundle-sanity.sh -- a stub: the fixture root, as certdata-to-pem would print it\n{ echo "# Root A"; cat "%s"; } > "$1/certdata.txt"\n' "$T/rootA.pem" > "$F/build/fetch-certdata.sh"
echo '{ print }' > "$F/build/certdata-to-pem.awk"
W256="$(fpr sha256 withdrawnW)"; B256="$(fpr sha256 blockedB)"
cp "$T/withdrawnW.pem" "$F/withdrawn/$W256.pem"; cp "$T/blockedB.pem" "$F/blocked/$B256.pem"
printf '| Withdrawn W | `%s` | 2038 |\n' "$W256" > "$F/withdrawn.md"
blocks() {  # NAME...: blocked.md, blocked/ and blocked.entries list exactly these fixture certificates
  rm -rf "$F/blocked"; mkdir "$F/blocked"; : > "$F/blocked.md"; : > "$F/blocked.entries"
  for _c in "$@"; do
    _s="$(fpr sha256 "$_c")"; cp "$T/$_c.pem" "$F/blocked/$_s.pem"
    printf '| %s | `%s` | [1](https://bugzilla.mozilla.org/show_bug.cgi?id=1) | 2030 |\n' "$_c" "$_s" >> "$F/blocked.md"
    printf '%s %s ISSUER SERIAL\n' "$_s" "$(fpr sha1 "$_c")" >> "$F/blocked.entries"
  done
}
at() { { echo "# AquaTransport fixture"; printf '%s\n' "$@"; } > "$F/aquatransport-roots.txt"; }
echo '# none' > "$F/aquatransport-differences.txt"
build() { _rc=0; MAVERICKS_ROOT="$F" MAVERICKS_BUILD_ROOT="$T/mbr" sh "$F/build/build-bundle.sh" > "$T/build.out" 2>&1 || _rc=$?; return "$_rc"; }

scenario "build-bundle.sh builds the fixture tree"
blocks blockedB; at "trust $(fpr sha1 rootA) Root A"
build || fail "build-bundle.sh failed on the fixture tree: $(cat "$T/build.out")"

scenario "build-bundle.sh refuses a certificate listed in both withdrawn.md and blocked.md"
blocks blockedB withdrawnW
! build || fail "build-bundle.sh must refuse a certificate both withdrawn and blocked"
grep -q "withdrawnW is listed in both withdrawn.md and blocked.md" "$T/build.out" || fail "the refusal must name the certificate and both lists: $(cat "$T/build.out")"

scenario "build-bundle.sh refuses a release whose blocked certificate AquaTransport trusts"
blocks blockedB; at "trust $(fpr sha1 rootA) Root A" "trust $(fpr sha1 blockedB) Blocked B"
! build || fail "build-bundle.sh must refuse when AquaTransport trusts a certificate we block"
grep -q "AquaTransport trusts $(fpr sha1 blockedB) (Blocked B), which we block" "$T/build.out" || fail "the refusal must name the blocked certificate: $(cat "$T/build.out")"

: "${MAVERICKS_BUILD_ROOT:=${TMPDIR:-/tmp}/mm-build}"
D="$MAVERICKS_BUILD_ROOT/$(basename "$R")/data"
[ -s "$D/ca-certificates.crt" ] || { echo "bundle-sanity: not built (sh build/build-bundle.sh) -- skipping"; exit 77; }
n="$(grep -c 'BEGIN CERTIFICATE' "$D/ca-certificates.crt")"
[ "$n" -ge 100 ] && [ "$n" -le 250 ] || fail "$n roots is outside 100-250; Mozilla trusted 121 in NSS 3.130"
t="$(ls "$D/trusted" | grep -c '\.pem$')"
[ "$t" = "$n" ] || fail "trusted/ has $t files for $n roots in the bundle"
for f in "$D"/trusted/*.pem "$D"/distrust/*.pem; do
  s="$(openssl x509 -noout -fingerprint -sha1 -in "$f" | sed 's/.*=//' | tr -d :)" || fail "$f does not parse"
  [ "$(basename "$f" .pem)" = "$s" ] || fail "$f is named for another certificate (its SHA-1 is $s)"
done
# spec: docs/TRUST-POLICY.md #14 -- blocked intermediates ship apart from withdrawn roots: blocked/, never distrust/
for f in "$R"/blocked/*.pem; do
  s="$(openssl x509 -noout -fingerprint -sha1 -in "$f" | sed 's/.*=//' | tr -d :)" || fail "$f does not parse"
  [ -f "$D/blocked/$s.pem" ] || fail "blocked/$(basename "$f") is not in this release's blocked/"
  [ ! -f "$D/distrust/$s.pem" ] || fail "blocked/$(basename "$f") is in distrust/, which is for withdrawn roots"
done
for f in "$D"/distrust/*.pem; do
  [ ! -f "$D/trusted/$(basename "$f")" ] || fail "$(basename "$f") is both trusted and distrusted"
done
[ "$(grep -c '^trusted ' "$D/roots.txt")" = "$n" ] || fail "roots.txt does not list every trusted root"
[ "$(grep -c '^distrusted ' "$D/roots.txt")" = "$(ls "$D/distrust" | grep -c '\.pem$')" ] || fail "roots.txt does not list every distrusted root"
b="$(ls "$D/blocked" | grep -c '\.pem$')"
[ "$b" -gt 0 ] || fail "blocked/ is empty"
[ "$(grep -c '^blocked ' "$D/roots.txt")" = "$b" ] || fail "roots.txt does not list every blocked intermediate"
[ "$(grep -c -v '^#' "$D/blocked.entries")" = "$b" ] || fail "blocked.entries must have one line per file in blocked/"
sort -c "$D/blocked.entries" || fail "blocked.entries must be sorted"
while read -r s1 iss ser; do
  [ -f "$D/blocked/$s1.pem" ] && [ -n "$iss" ] && [ -n "$ser" ] || fail "blocked.entries line for $s1 is not SHA1 ISSUER_B64 SERIAL_B64 for a file in blocked/"
done < "$D/blocked.entries"
cmp -s "$D/aquatransport-roots.txt" "$R/aquatransport-roots.txt" || fail "the build must carry aquatransport-roots.txt as committed"
[ -f "$D/ca-certificates.sha1" ] || fail "no ca-certificates.sha1: the applier needs it to leave denied roots out of the bundle"
[ "$(wc -l < "$D/ca-certificates.sha1" | tr -d ' ')" = "$n" ] || fail "ca-certificates.sha1 must list one SHA-1 per certificate in the bundle"
awk '/-----BEGIN CERTIFICATE-----/ { f = sprintf("%s/blk%04d.pem", d, ++i) } f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' d="$T" "$D/ca-certificates.crt"
i=0
while read -r h; do
  i=$((i + 1))
  got="$(openssl x509 -noout -fingerprint -sha1 -in "$(printf '%s/blk%04d.pem' "$T" "$i")" | sed 's/.*=//' | tr -d :)"
  [ "$got" = "$h" ] || fail "ca-certificates.sha1 line $i says $h, but the bundle's certificate $i is $got"
done < "$D/ca-certificates.sha1"
echo "bundle-sanity: ok ($n trusted)"
