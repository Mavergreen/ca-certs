#!/bin/sh
# platform: macOS-only -- sw_vers picks the slices and lipo-merge-tree.sh merges them
#   usage: build-updater.sh OUT.app
#          Builds ca-certs-updater.app: x86_64 for 10.9 and, on a host that can, arm64 for 11.0,
#          merged into one. A 10.9 host builds the x86_64 slice alone; releases require both.
# spec: docs/TRUST-POLICY.md #10 -- modern Macs install this pkg too; an x86_64-only updater prompts for Rosetta there
set -eu
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
out="${1:?usage: build-updater.sh OUT.app}"
SC="$(command -v shipyard-cmake || echo /usr/local/mavergreen/bin/shipyard-cmake)"
app="$(basename "$(sh "$SHIPYARD/product-name.sh" updater-app ca-certs)")"
tc="$SHIPYARD/../MavericksToolchain.cmake"
[ -f "$tc" ] || build_die "no MavericksToolchain.cmake beside $SHIPYARD"
[ -f "$MAVERICKS_ROOT/UPSTREAM_VERSION" ] || build_die "UPSTREAM_VERSION is missing; run build/derive-upstream-version.sh first"
major="$(sw_vers -productVersion | cut -d. -f1)"
slices="x86_64:10.9"; [ "$major" -ge 11 ] && slices="x86_64:10.9 arm64:11.0"
for s in $slices; do
  a="${s%%:*}"; floor="${s#*:}"
  "$SC" -S "$MAVERICKS_ROOT" -B "$CA_BUILD/updater-$a" \
    -DCMAKE_OBJC_COMPILER=/usr/bin/clang -DCMAKE_OSX_ARCHITECTURES="$a" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$floor" -DCMAKE_TOOLCHAIN_FILE="$tc"
  "$SC" --build "$CA_BUILD/updater-$a"
done
rm -rf "$out"
if [ "$major" -ge 11 ]; then
  sh "$SHIPYARD/lipo-merge-tree.sh" --a "$CA_BUILD/updater-x86_64/$app" \
    --b "$CA_BUILD/updater-arm64/$app" --out "$out" --require-archs "x86_64 arm64"
else
  cp -R "$CA_BUILD/updater-x86_64/$app" "$out"
fi
