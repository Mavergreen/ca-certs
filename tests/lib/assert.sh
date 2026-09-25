# platform: host-agnostic
#   usage: . "$R/tests/lib/assert.sh"
#          fail MSG     -- print MSG as a test failure and exit 1
#          scenario MSG -- print the case about to run, so a failure's context is on screen
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
scenario() { printf '  %s\n' "$*"; }
