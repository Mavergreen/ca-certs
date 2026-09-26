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
printf '%s\n' "$first" | grep -q '^- Trusts 2 roots and distrusts 1\.$' || fail "a first release must give the counts: $first"
[ "$(printf '%s\n' "$first" | head -n 1)" = "" ] || fail "the section must start with a blank line, or Sparkle's dialog runs it into the previous paragraph"

printf 'Some earlier notes.\n' > "$T/notes1"
sh "$R/build/roots-notes.sh" --append "$T/notes1" "$T/cur" || fail "--append on a plain notes file failed"
grep -q '^### Roots$' "$T/notes1" || fail "--append must write the section into the notes file"

printf '## T\n\n### What changed\n- x\n\n---\nRequires Mac OS X 10.9.5 or later.\n' > "$T/notes2"
sh "$R/build/roots-notes.sh" --append "$T/notes2" "$T/cur" || fail "--append on a footered notes file failed"
roots_ln="$(grep -n '^### Roots$' "$T/notes2" | head -n 1 | cut -d: -f1)"
dashes_ln="$(grep -n '^---$' "$T/notes2" | head -n 1 | cut -d: -f1)"
[ "$roots_ln" -lt "$dashes_ln" ] || fail "### Roots ($roots_ln) must land before the footer's --- ($dashes_ln)"
echo "roots-notes: ok"
