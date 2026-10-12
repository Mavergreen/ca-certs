#!/bin/sh
# platform: macOS-only -- stage_product.sh, pkgbuild and productbuild build the pkg
#   usage: package-pkg.sh --version V --updater APP --out DIR
#          Stages the ca-certs tree from $CA_BUILD/data and payload/, lets shipyard write the
#          install scripts and manifest, and builds DIR/ca-certs-V.pkg with the family's install
#          floor. Copies roots.txt to DIR for the release notes of the next release.
# spec: tests/package-pkg.sh
set -eu
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
V=""; APP=""; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) V="$2"; shift 2 ;;
    --updater) APP="${2%/}"; shift 2 ;;
    --out) OUT="${2%/}"; shift 2 ;;
    *) build_die "unknown option $1" ;;
  esac
done
[ -n "$V" ] && [ -d "$APP" ] && [ -n "$OUT" ] || build_die "need --version, --updater APP and --out"
D="${CA_BUILD:?}/data"
[ -s "$D/ca-certificates.crt" ] || build_die "no trust data; run build/build-bundle.sh"
ST="$CA_BUILD/stage"; SCR="$CA_BUILD/scripts"
rm -rf "$ST" "$SCR"
P="$ST/usr/local/mavergreen/ca-certs"
mkdir -p "$P/libexec/mavergreen" "$P/share/ca-certs/trusted" "$P/share/ca-certs/distrust" "$P/etc/openssl/certs" "$OUT"
cp "$MAVERICKS_ROOT/payload/libexec/ca-certs-apply" "$MAVERICKS_ROOT/payload/libexec/ca-certs-lib.sh" "$P/libexec/"
cp "$MAVERICKS_ROOT/payload/libexec/mavergreen/pre-uninstall" "$P/libexec/mavergreen/"
chmod 755 "$P/libexec/ca-certs-apply" "$P/libexec/mavergreen/pre-uninstall"
chmod 644 "$P/libexec/ca-certs-lib.sh"
cp "$D"/trusted/*.pem "$P/share/ca-certs/trusted/"
cp "$D"/distrust/*.pem "$P/share/ca-certs/distrust/"
cp "$D/ca-certificates.crt" "$P/etc/openssl/certs/ca-certificates.crt"
cp "$D/aquatransport-roots.txt" "$P/share/ca-certs/"
cp "$MAVERICKS_ROOT/THIRD-PARTY-NOTICES.txt" "$P/share/ca-certs/"
sh "$MAVERICKS_ROOT/build/derive-upstream-version.sh" > "$P/share/ca-certs/nss-version"
sh "$SHIPYARD/stage_product.sh" --stage "$ST" --product ca-certs \
  --name "CA Certificates for Mavericks" --version "$V" --scripts-out "$SCR" \
  --updater-app "$APP" --postinstall-hook "$MAVERICKS_ROOT/build/postinstall-hook.sh"
id="$(sh "$SHIPYARD/product-name.sh" identifier ca-certs)" || build_die "ca-certs is not in shipyard's registry"
comp="$(sh "$SHIPYARD/build_component_pkg.sh" --root "$ST" --identifier "$id" --version "$V" \
  --install-location / --scripts "$SCR" --out "$CA_BUILD/ca-certs-component.pkg")"
sh "$SHIPYARD/set_install_floor.sh" --identifier "$id" --title "CA Certificates for Mavericks" \
  --component "$comp" --out "$OUT/ca-certs-$V.pkg" --require-scripts \
  --host-arch x86_64,arm64 --min-os 10.9.5 >/dev/null
cp "$D/roots.txt" "$OUT/roots.txt"
echo "package-pkg: $OUT/ca-certs-$V.pkg" >&2
