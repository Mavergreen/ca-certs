#!/bin/sh
# platform: host-agnostic
#   usage: fetch-certdata.sh OUTDIR
#          Downloads the NSS release NSS_TAG names, verifies it against the SHA256SUMS Mozilla
#          publishes beside it, and writes OUTDIR/certdata.txt. Refuses a tarball the sums don't list.
# spec: docs/TRUST-POLICY.md #1
set -eu
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
out="${1:?usage: fetch-certdata.sh OUTDIR}"
tag="$(nss_tag)"
v="$(sh "$MAVERICKS_ROOT/build/derive-upstream-version.sh" --nss-spelling)"
base="https://ftp.mozilla.org/pub/security/nss/releases/$tag/src"
tarball="nss-$v.tar.gz"
cache="$MAVERICKS_BUILD_ROOT/ca-certs-cache"
mkdir -p "$cache" "$out"
sums="$(curl -fsSL "$base/SHA256SUMS")" || build_die "could not download $base/SHA256SUMS"
sha="$(printf '%s\n' "$sums" | awk -v f="$tarball" '$2 == f || $2 == ("*" f) { print $1 }')"
case "$sha" in
  *[!0-9a-f]*|'') build_die "$tarball is not listed in $base/SHA256SUMS; refusing an unverified download" ;;
esac
[ "${#sha}" -eq 64 ] || build_die "$base/SHA256SUMS lists '$sha' for $tarball, which is not a SHA-256"
member="nss-$v/nss/lib/ckfw/builtins/certdata.txt"
. "$SHIPYARD/mavericks_fetch.sh"
mav_fetch_pinned "$base/$tarball" "$sha" "$cache" "$tarball" "$member" || build_die "fetching $tarball failed"
[ -s "$cache/$member" ] || build_die "$tarball has no $member"
cp "$cache/$member" "$out/certdata.txt"
