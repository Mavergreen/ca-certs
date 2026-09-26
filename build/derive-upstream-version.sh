#!/bin/sh
# platform: host-agnostic
#   usage: derive-upstream-version.sh [--nss-spelling]
#          Reads NSS_TAG (NSS_3_130_RTM, NSS_3_126_1_RTM) and prints this product's upstream version,
#          always three parts (3.130.0, 3.126.1), writing it to UPSTREAM_VERSION. With
#          --nss-spelling, prints NSS's own spelling instead (3.130, 3.126.1) and writes nothing.
# spec: tests/derive-upstream-version.sh
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tag="$(tr -d '[:space:]' < "$ROOT/NSS_TAG")"
refuse() { echo "derive-upstream-version: NSS_TAG '$tag' is not NSS_<major>_<minor>[_<patch>]_RTM" >&2; exit 1; }
case "$tag" in NSS_*_RTM) : ;; *) refuse ;; esac
nums="${tag#NSS_}"; nums="${nums%_RTM}"
case "$nums" in ''|*[!0-9_]*|_*|*_|*__*) refuse ;; esac
spelled="$(printf '%s' "$nums" | tr _ .)"
case "$spelled" in
  *.*.*.*) refuse ;;
  *.*.*) full="$spelled" ;;
  *.*) full="$spelled.0" ;;
  *) refuse ;;
esac
if [ "${1:-}" = --nss-spelling ]; then printf '%s\n' "$spelled"; exit 0; fi
printf '%s\n' "$full" > "$ROOT/UPSTREAM_VERSION"
printf '%s\n' "$full"
