#!/bin/sh
# platform: host-agnostic
#   usage: version.sh auto|local
#          Thin wrapper: the logic is shipyard's scripts/version.sh, reading UPSTREAM_VERSION
#          (write it first with build/derive-upstream-version.sh).
set -eu
SELF="$(cd "$(dirname "$0")" && pwd)"
MAVERICKS_ROOT="$(cd "$SELF/.." && pwd)"; export MAVERICKS_ROOT
. "$SELF/msc.sh"
exec sh "$SHIPYARD/version.sh" "$@"
