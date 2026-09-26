# platform: host-agnostic
#   usage: . build/lib.sh
#          Sets MAVERICKS_ROOT, SHIPYARD (via msc.sh), MAVERICKS_BUILD_ROOT and CA_BUILD, and
#          defines nss_tag, ca_fingerprint ALG FILE and build_die MSG.
: "${MAVERICKS_ROOT:=$(cd "$(dirname "$0")/.." && pwd)}"
export MAVERICKS_ROOT
. "$MAVERICKS_ROOT/build/msc.sh"
. "$SHIPYARD/lib.sh"
# platform: a family checkout may live on NFS, where a build cost 11.16s wall against 2.96s on local disk, identical user time
: "${MAVERICKS_BUILD_ROOT:=${TMPDIR:-/tmp}/mm-build}"
export MAVERICKS_BUILD_ROOT
# platform: keyed by checkout, as the family's presets key binaryDir by ${sourceDirName}: two checkouts never share one
CA_BUILD="$MAVERICKS_BUILD_ROOT/$(basename "$MAVERICKS_ROOT")"; export CA_BUILD
build_die() { echo "$(basename "$0"): $*" >&2; exit 1; }
nss_tag() { tr -d '[:space:]' < "$MAVERICKS_ROOT/NSS_TAG"; }
ca_fingerprint() {
  _fp="$(openssl x509 -noout -fingerprint "-$1" -in "$2")" || return 1
  printf '%s\n' "${_fp#*=}" | tr -d :
}
