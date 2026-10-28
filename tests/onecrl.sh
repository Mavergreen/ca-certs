#!/bin/sh
# platform: host-agnostic -- python3 and openssl
# spec: docs/TRUST-POLICY.md #14 -- build/onecrl.py turns OneCRL and CCADB into blocked.md, blocked/ and blocked.entries
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/caonecrl.XXXXXX")"
trap 'rm -rf "$T"' EXIT
G="$R/build/onecrl.py"
NOW=2026-10-28

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/ca.key" -out "$T/ca.pem" \
  -days 30 -subj "/O=Test Org/CN=Test Root" >/dev/null 2>&1
n=0
for c in X Z W V1 V2 V3 V4 V5 V6; do
  n=$((n + 1))
  case "$c" in V*) subj="/O=Filler Org/CN=Sub $c" ;; *) subj="/O=Test Org/CN=Sub $c" ;; esac
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/$c.key" -out "$T/$c.csr" \
    -subj "$subj" >/dev/null 2>&1
  openssl x509 -req -in "$T/$c.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -set_serial "$((4660 + n))" -days 30 \
    -out "$T/$c.pem" >/dev/null 2>&1
done
# spec: build/onecrl.py -- Y's subject has no CN, so its row names the subject's O, its pipe made a slash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/Y.key" -out "$T/Y.csr" \
  -subj "/O=Pipe|Org" >/dev/null 2>&1
openssl x509 -req -in "$T/Y.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -set_serial 9999 -days 30 -out "$T/Y.pem" >/dev/null 2>&1
fp() { openssl x509 -noout -fingerprint "-$1" -in "$T/$2.pem" | sed 's/.*=//' | tr -d :; }
for c in X Y Z W V1 V2 V3 V4 V5 V6; do eval "S256_$c=\$(fp sha256 $c); S1_$c=\$(fp sha1 $c)"; done

# spec: build/onecrl.py -- the fixture values, computed here: a DER walk for issuer, subject and
#       serial; OneCRL's key hash straight from openssl, so the generator's own SPKI walk is checked against it
cat > "$T/fixture.py" <<'EOF'
import base64, csv, hashlib, json, subprocess, sys
T, fillers = sys.argv[1], int(sys.argv[2])
def b64(b): return base64.b64encode(b).decode()
def der(c): return subprocess.run(['openssl', 'x509', '-in', f'{T}/{c}.pem', '-outform', 'DER'], capture_output=True, check=True).stdout
def tlv(b, i):
    t, l, j = b[i], b[i + 1], i + 2
    if l & 0x80: n = l & 0x7f; l = int.from_bytes(b[j:j + n], 'big'); j += n
    return t, j, j + l
def parts(c):
    b = der(c); _, s, _ = tlv(b, 0); _, i, e = tlv(b, s); out = []
    while i < e:
        t, cs, ce = tlv(b, i); out.append((t, b[i:ce], b[cs:ce])); i = ce
    if out[0][0] == 0xa0: out = out[1:]
    return {'serial': out[0][2], 'issuer': out[2][1], 'subject': out[4][1]}
def keyhash(c):
    spki = subprocess.run(f"openssl x509 -in '{T}/{c}.pem' -noout -pubkey | openssl pkey -pubin -outform DER", shell=True, capture_output=True, check=True).stdout
    return b64(hashlib.sha256(spki).digest())
def bug(n): return {'bug': f'https://bugzilla.mozilla.org/show_bug.cgi?id={n}', 'who': '', 'why': '', 'name': '', 'created': '2025-01-01T00:00:00Z'}
def by_serial(c, n):
    p = parts(c); return {'issuerName': b64(p['issuer']), 'serialNumber': b64(p['serial']), 'details': bug(n), 'enabled': True}
recs = [by_serial('X', 1111),
        {'subject': b64(parts('Y')['subject']), 'pubKeyHash': keyhash('Y'), 'details': bug(2222), 'enabled': True},
        by_serial('Z', 3333)]
recs += [by_serial(f'V{k}', 6000 + k) for k in range(1, 7)]
recs[-1]['details']['bug'] = ''
recs[-2]['details']['bug'] = '6005'
recs += [dict(by_serial('Z', 3333)) for _ in range(fillers)]
gap = lambda n, name, created: {'issuerName': b64(b'0\x00'), 'serialNumber': b64(bytes([n % 256])), 'enabled': True,
                                'details': {'bug': f'https://bugzilla.mozilla.org/show_bug.cgi?id={n}', 'name': name, 'created': created}}
recs += [gap(4444, 'Recent Gap CA', '2026-09-28T00:00:00Z'), gap(5555, 'Old Gap CA', '2023-10-28T00:00:00Z')]
for k, r in enumerate(recs): r['id'] = f'rec-{k}'; r['last_modified'] = 1792622041776 - k
json.dump({'data': recs}, open(f'{T}/onecrl.json', 'w'))
for c in 'XYZW':
    p = parts(c); print(f"{c} {b64(p['issuer'])} {b64(p['serial'])}")
REVOKED = ["CA Owner","Revocation Status","RFC 5280 Revocation Reason Code","Date of Revocation","OneCRL Status","Certificate Serial Number","CA Owner/Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Subject Common Name","Certificate Subject Organization","SHA-256 Fingerprint","Subject + SPKI SHA256","Valid From [GMT]","Valid To [GMT]","Public Key Algorithm","Signature Hash Algorithm","CRL URL(s)","Alternate CRL","Comments","PEM Info"]
ALL = ["CA Owner","Parent Name","Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Subject Common Name","Certificate Subject Organization","Certificate Serial Number","SHA-256 Fingerprint","Valid From [GMT]","Valid To [GMT]","PEM Info"]
def row(c, cn, org, until):
    fp = subprocess.run(['openssl', 'x509', '-in', f'{T}/{c}.pem', '-noout', '-fingerprint', '-sha256'], capture_output=True, text=True, check=True).stdout
    return {'Certificate Issuer Common Name': 'Test Root', 'Certificate Issuer Organization': 'Test Org',
            'Certificate Subject Common Name': cn, 'Certificate Subject Organization': org,
            'SHA-256 Fingerprint': fp.split('=')[1].strip().replace(':', ''), 'Valid To [GMT]': until,
            'PEM Info': "'" + open(f'{T}/{c}.pem').read().strip() + "'"}
def write(name, header, rows):
    with open(f'{T}/{name}', 'w', newline='') as f:
        w = csv.DictWriter(f, header, quoting=csv.QUOTE_ALL, restval=''); w.writeheader(); w.writerows(rows)
write('revoked.csv', REVOKED, [row('X', 'Sub X', 'Test Org', '2031 Mar 15'), row('Z', 'Sub Z', 'Test Org', '2020 Jan 01')])
write('all.csv', ALL, [row('X', 'Sub X', 'Test Org', '2031 Mar 15'), row('Y', '', 'Pipe|Org', '2030 Jan 01'),
                       row('W', 'Sub W', 'Test Org', '2030 Jan 01')]
                      + [row(f'V{k}', f'Sub V{k}', 'Filler Org', '2029 Jun 30') for k in range(1, 7)])
write('nopem.csv', [h for h in ALL if h != 'PEM Info'], [])
EOF
# spec: build/onecrl.py -- 988 fillers plus 11 records is 999, one short of the guard
python3 -I "$T/fixture.py" "$T" 988 >/dev/null
mv "$T/onecrl.json" "$T/short.json"
python3 -I "$T/fixture.py" "$T" 1000 > "$T/der"
: > "$T/empty.csv"
gen() {  # REPO [ARG...]: run the generator on the fixtures, writing into REPO
  _repo="$1"; shift
  python3 -I "$G" --onecrl "$T/onecrl.json" --ccadb "$T/revoked.csv" --ccadb "$T/all.csv" --now "$NOW" --repo "$_repo" "$@"
}
mkdir "$T/repo"
gen "$T/repo" > "$T/out" 2>&1 || { cat "$T/out" >&2; fail "the generator failed on good input"; }
M="$T/repo/blocked.md"; E="$T/repo/blocked.entries"

scenario "matches by issuer and serial"
[ -f "$T/repo/blocked/$S256_X.pem" ] || fail "blocked/ lacks X, which an issuer+serial record names"
read -r _ iss ser <<EOF
$(grep '^X ' "$T/der")
EOF
grep -qx "$S256_X $S1_X $iss $ser" "$E" || fail "blocked.entries lacks X as '$S256_X $S1_X $iss $ser':
$(cat "$E")"

scenario "matches by subject and key"
[ -f "$T/repo/blocked/$S256_Y.pem" ] || fail "blocked/ lacks Y, which a subject+key record names"
grep -q "^$S256_Y $S1_Y " "$E" || fail "blocked.entries lacks Y"
grep -q "^| Pipe/Org, signed by Test Root | \`$S256_Y\` | " "$M" || fail "Y's row must name its subject's O, its pipe a slash:
$(cat "$M")"

scenario "drops expired and unlisted"
for c in Z W; do
  eval "s=\$S256_$c"
  [ ! -f "$T/repo/blocked/$s.pem" ] || fail "blocked/ has $c"
  ! grep -q "$s" "$M" "$E" || fail "blocked.md or blocked.entries lists $c"
done
[ "$(ls "$T/repo/blocked" | wc -l | tr -d ' ')" -eq 8 ] || fail "blocked/ should hold X, Y and the six V certificates: $(ls "$T/repo/blocked")"
[ "$(grep -vc '^#' "$E")" -eq 8 ] || fail "blocked.entries should have 8 lines"
[ "$(grep -v '^#' "$E" | LC_ALL=C sort)" = "$(grep -v '^#' "$E")" ] || fail "blocked.entries is not sorted by SHA-256"

scenario "cites each record's bug"
grep -qx "| Sub X, signed by Test Root | \`$S256_X\` | \[1111\](https://bugzilla.mozilla.org/show_bug.cgi?id=1111) | 2031 |" "$M" \
  || fail "X's row must cite bug 1111 and expire in 2031:
$(cat "$M")"
grep -q "^| Pipe/Org, signed by Test Root | \`$S256_Y\` | \[2222\](https://bugzilla.mozilla.org/show_bug.cgi?id=2222) | 2030 |\$" "$M" || fail "Y's row must cite bug 2222"
grep -q "^| Sub V3, signed by Test Root | \`$S256_V3\` | \[6003\](https://bugzilla.mozilla.org/show_bug.cgi?id=6003) | 2029 |\$" "$M" || fail "V3's row must cite bug 6003"
grep -q '^| Intermediate | SHA-256 | Bug | Expires |$' "$M" || fail "blocked.md's table header is not | Intermediate | SHA-256 | Bug | Expires |"
grep -q 'build/onecrl.sh' "$M" && grep -q "$NOW" "$M" && grep -q '2026-10-21' "$M" \
  || fail "blocked.md must say build/onecrl.sh generated it, from OneCRL as of 2026-10-21, on $NOW"

scenario "spells out a bare-number bug"
grep -q "^| Sub V5, signed by Test Root | \`$S256_V5\` | \[6005\](https://bugzilla.mozilla.org/show_bug.cgi?id=6005) | 2029 |\$" "$M" \
  || fail "V5's record gives its bug as a bare number, so its row must link it in full"

scenario "cites the record itself when it has no bug"
grep -q "^| Sub V6, signed by Test Root | \`$S256_V6\` | \[OneCRL\](https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records/rec-8) | 2029 |\$" "$M" \
  || fail "V6's record cites no bug, so its row must link the OneCRL record itself"

scenario "reports the gap"
grep -q '\*\*2 OneCRL records\*\*' "$M" || fail "blocked.md must count 2 unmatched records:
$(cat "$M")"
grep -q 'Recent Gap CA' "$M" && grep -q 'id=4444' "$M" || fail "blocked.md must list the recent unmatched record by bug and name"
! grep -q 'Old Gap CA\|id=5555' "$M" || fail "blocked.md lists an unmatched record older than 365 days"

scenario "is deterministic"
cp -R "$T/repo" "$T/before"
gen "$T/repo" >/dev/null 2>&1 || fail "a second run failed"
diff -r "$T/before" "$T/repo" || fail "a second run on the same input changed the output"
mkdir "$T/repo2"
gen "$T/repo2" >/dev/null 2>&1 || fail "a run into a fresh directory failed"
diff -r "$T/before" "$T/repo2" || fail "two runs into fresh directories differ"

scenario "guards"
refuses() {  # REPO WHY ARG...: the generator exits 1 naming WHY and leaves REPO as it was
  _repo="$1"; _why="$2"; shift 2
  rm -rf "$T/snap"; cp -R "$_repo" "$T/snap"
  _rc=0; python3 -I "$G" "$@" --now "$NOW" --repo "$_repo" > "$T/out" 2>&1 || _rc=$?
  [ "$_rc" -eq 1 ] || fail "expected exit 1 ($_why), got $_rc: $(cat "$T/out")"
  grep -qi "$_why" "$T/out" || fail "the refusal does not name '$_why': $(cat "$T/out")"
  diff -r "$T/snap" "$_repo" || fail "a refused run ($_why) changed the repo"
}
refuses "$T/repo" "fewer than 1000" --onecrl "$T/short.json" --ccadb "$T/revoked.csv" --ccadb "$T/all.csv"
refuses "$T/repo" "empty" --onecrl "$T/onecrl.json" --ccadb "$T/empty.csv" --ccadb "$T/all.csv"
refuses "$T/repo" "PEM Info" --onecrl "$T/onecrl.json" --ccadb "$T/revoked.csv" --ccadb "$T/nopem.csv"
mkdir "$T/mass"; cp -R "$T/repo/blocked" "$T/mass/"
cp "$T/Z.pem" "$T/mass/blocked/$S256_Z.pem"; cp "$T/W.pem" "$T/mass/blocked/$S256_W.pem"
refuses "$T/mass" "mass removal" --onecrl "$T/onecrl.json" --ccadb "$T/revoked.csv" --ccadb "$T/all.csv"
gen "$T/mass" --allow-mass-removal > "$T/out" 2>&1 || fail "--allow-mass-removal still refused: $(cat "$T/out")"
[ ! -f "$T/mass/blocked/$S256_Z.pem" ] && [ ! -f "$T/mass/blocked/$S256_W.pem" ] || fail "--allow-mass-removal kept stale files"
diff -r "$T/before/blocked" "$T/mass/blocked" || fail "--allow-mass-removal left a different blocked/"

echo "onecrl: ok"
