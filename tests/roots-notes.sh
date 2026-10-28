#!/bin/sh
# platform: host-agnostic
# spec: docs/TRUST-POLICY.md #11 -- every release says, by name and fingerprint, what it trusts and distrusts differently
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/carn.XXXXXX")"
trap 'rm -rf "$T"' EXIT
a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
b=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
c=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
d=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
printf 'distrusted %s Old CA\ntrusted %s Alpha Root\ntrusted %s Beta Root\n' "$d" "$a" "$b" > "$T/prev"
printf 'distrusted %s Old CA\ntrusted %s Alpha Root\ntrusted %s Gamma Root G2\n' "$d" "$a" "$c" > "$T/cur"

out="$(sh "$R/build/roots-notes.sh" "$T/cur" "$T/prev")"
want="$(printf '\n%s\n\n%s\n%s' '### Roots' "- Newly trusted: Gamma Root G2 (\`$c\`)" "- No longer trusted: Beta Root (\`$b\`)")"
[ "$out" = "$want" ] || fail "diff section was:
$out"

same="$(sh "$R/build/roots-notes.sh" "$T/cur" "$T/cur")"
printf '%s\n' "$same" | grep -q '^- No change to which roots are trusted or distrusted\.$' || fail "an unchanged list must say so: $same"

first="$(sh "$R/build/roots-notes.sh" "$T/cur")"
printf '%s\n' "$first" | grep -q '^- Trusts 2 roots, distrusts 1, and blocks 0 intermediates\.$' || fail "a first release must give the counts: $first"
[ "$(printf '%s\n' "$first" | head -n 1)" = "" ] || fail "the section must start with a blank line, or Sparkle's dialog runs it into the previous paragraph"

# spec: docs/TRUST-POLICY.md #11 -- blocked intermediates: counts, and names only when the change is small
gen() {  # $1=count, $2=prefix: that many blocked lines, each with a distinct 64-hex id
  awk -v n="$1" -v p="$2" 'BEGIN { for (i = 1; i <= n; i++) printf "blocked %s%s Blocked CA %d\n", p, sprintf("%063d", i), i }'
}
cp "$T/cur" "$T/cur0"; gen 3 1 > "$T/b3"; gen 25 2 > "$T/b25"
cat "$T/cur0" "$T/b25" > "$T/cur25"
big="$(sh "$R/build/roots-notes.sh" "$T/cur25" "$T/cur0")"
printf '%s\n' "$big" | grep -qx -- '- Newly blocks 25 intermediates Mozilla blocks in OneCRL\.' || fail "25 added must print the count line: $big"
printf '%s\n' "$big" | grep -q 'Blocked CA' && fail "25 added must not list names: $big"
cat "$T/cur0" "$T/b3" > "$T/cur3"
small="$(sh "$R/build/roots-notes.sh" "$T/cur3" "$T/cur0")"
printf '%s\n' "$small" | grep -qx -- '- Newly blocks 3 intermediates Mozilla blocks in OneCRL\.' || fail "3 added must print the count line: $small"
[ "$(printf '%s\n' "$small" | grep -c '^- Newly blocked: Blocked CA ')" = 3 ] || fail "3 added must list 3 named lines: $small"
gone="$(sh "$R/build/roots-notes.sh" "$T/cur0" "$T/cur3")"
printf '%s\n' "$gone" | grep -qx -- '- No longer blocks 3 (expired or unblocked)\.' || fail "3 removed must print the count line: $gone"
[ "$(printf '%s\n' "$gone" | grep -c '^- No longer blocked: Blocked CA ')" = 3 ] || fail "3 removed must list 3 named lines: $gone"
firstb="$(sh "$R/build/roots-notes.sh" "$T/cur3")"
printf '%s\n' "$firstb" | grep -qx -- '- Trusts 2 roots, distrusts 1, and blocks 3 intermediates\.' || fail "a first release must count blocked: $firstb"

# spec: docs/TRUST-POLICY.md #11 -- names come from CCADB, which the CA supplies, and Sparkle shows the notes as HTML on 10.9
e=EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
f=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
{ cat "$T/cur0"; printf 'trusted %s Evil <b>Root</b> & Co\nblocked %s Sub <script>x</script> & Co, signed by A&B\n' "$e" "$f"; } > "$T/curx"
evil="$(sh "$R/build/roots-notes.sh" "$T/curx" "$T/cur0")"
! printf '%s\n' "$evil" | grep -q '[<>&]' || fail "a name's <, > and & must not reach the notes: $evil"
printf '%s\n' "$evil" | grep -qx -- "- Newly trusted: Evil bRoot/b  Co (\`$e\`)" || fail "the newly trusted root must still be named, less <, > and &: $evil"
printf '%s\n' "$evil" | grep -qx -- "- Newly blocked: Sub scriptx/script  Co, signed by AB (\`$f\`)" || fail "the newly blocked intermediate must still be named, less <, > and &: $evil"

printf 'Some earlier notes.\n' > "$T/notes1"
sh "$R/build/roots-notes.sh" --append "$T/notes1" "$T/cur" || fail "--append on a plain notes file failed"
grep -q '^### Roots$' "$T/notes1" || fail "--append must write the section into the notes file"

printf '## T\n\n### What changed\n- x\n\n---\nRequires Mac OS X 10.9.5 or later.\n' > "$T/notes2"
sh "$R/build/roots-notes.sh" --append "$T/notes2" "$T/cur" || fail "--append on a footered notes file failed"
roots_ln="$(grep -n '^### Roots$' "$T/notes2" | head -n 1 | cut -d: -f1)"
dashes_ln="$(grep -n '^---$' "$T/notes2" | head -n 1 | cut -d: -f1)"
[ "$roots_ln" -lt "$dashes_ln" ] || fail "### Roots ($roots_ln) must land before the footer's --- ($dashes_ln)"
echo "roots-notes: ok"
