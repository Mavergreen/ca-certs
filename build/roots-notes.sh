#!/bin/sh
# platform: host-agnostic
#   usage: roots-notes.sh [--append NOTES] CURRENT_ROOTS_TXT [PREVIOUS_ROOTS_TXT]
#          Prints the release notes' "### Roots" section: roots newly trusted or distrusted, and
#          no longer trusted or distrusted, since the previous release. With no previous list, the
#          counts. Starts with a blank line, so it appends as its own paragraph. With --append
#          NOTES, writes the section into NOTES instead, immediately before its first line that is
#          exactly "---" (or at the end, if there is none), and refuses a missing or empty NOTES.
# spec: tests/roots-notes.sh
set -eu
append=""
if [ "${1:-}" = --append ]; then
  append="${2:?usage: roots-notes.sh --append NOTES ...}"
  [ -s "$append" ] || { echo "roots-notes: $append is missing or empty" >&2; exit 1; }
  shift 2
fi
cur="${1:?usage: roots-notes.sh [--append NOTES] CURRENT [PREVIOUS]}"; prev="${2:-}"

section() {
  printf '\n### Roots\n\n'
  if [ -z "$prev" ]; then
    printf -- '- Trusts %s roots and distrusts %s.\n' "$(grep -c '^trusted ' "$cur" || :)" "$(grep -c '^distrusted ' "$cur" || :)"
    return 0
  fi
  T="$(mktemp -d "${TMPDIR:-/tmp}/roots-notes.XXXXXX")"
  trap 'rm -rf "$T"' EXIT
  cut -d' ' -f1,2 "$cur" | sort > "$T/c"
  cut -d' ' -f1,2 "$prev" | sort > "$T/p"
  comm -23 "$T/c" "$T/p" > "$T/added"
  comm -13 "$T/c" "$T/p" > "$T/removed"
  if [ ! -s "$T/added" ] && [ ! -s "$T/removed" ]; then
    printf -- '- No change to which roots are trusted or distrusted.\n'
    return 0
  fi
  line() { grep "^$1 $2 " "$3" | head -n 1 | cut -d' ' -f3-; }
  group() {
    while read -r k s; do
      [ "$k" = "$1" ] || continue
      printf -- '- %s: %s (`%s`)\n' "$3" "$(line "$k" "$s" "$4")" "$s"
    done < "$2"
  }
  group trusted "$T/added" "Newly trusted" "$cur"
  group trusted "$T/removed" "No longer trusted" "$prev"
  group distrusted "$T/added" "Newly distrusted" "$cur"
  group distrusted "$T/removed" "No longer distrusted" "$prev"
}

if [ -z "$append" ]; then
  section
  exit 0
fi

out="$(section)"
tmp="$(mktemp "${TMPDIR:-/tmp}/roots-notes-out.XXXXXX")"
if grep -n '^---$' "$append" >/dev/null 2>&1; then
  ln="$(grep -n '^---$' "$append" | head -n 1 | cut -d: -f1)"
  head -n "$((ln - 1))" "$append" > "$tmp"
  printf '%s\n' "$out" >> "$tmp"
  tail -n "+$ln" "$append" >> "$tmp"
else
  cat "$append" > "$tmp"
  printf '%s\n' "$out" >> "$tmp"
fi
mv "$tmp" "$append"
