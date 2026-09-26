#!/bin/sh
# platform: host-agnostic
# spec: .github/workflows/release.yml -- ${{ }} is pasted into a run: script's text before the shell sees it, so a
#       value derived from a tag name becomes shell in the step that holds SPARKLE_PRIVATE_KEY; values
#       reach run: scripts through env: instead
set -eu
R="$(cd "$(dirname "$0")/.." && pwd)"
. "$R/tests/lib/assert.sh"
W="$R/.github/workflows/release.yml"
RECONCILE_W="$R/.github/workflows/reconcile.yml"

scenario "no run: script interpolates \${{ }}"
bad="$(awk '
  function indent(s) { match(s, /^ */); return RLENGTH }
  inrun && NF && indent($0) <= runind { inrun = 0 }
  inrun && index($0, "${{") { print FILENAME ":" NR ": " $0; next }
  /^ *(- )?run: *[|>][-+]? *$/ { inrun = 1; runind = indent($0); next }
  /^ *(- )?run: / && index($0, "${{") { print FILENAME ":" NR ": " $0 }
' "$W")"
[ -z "$bad" ] || fail "pass these through env: and use \"\$NAME\" in the script:
$bad"

scenario "no tags: trigger -- a workflow_dispatch covers every case a tag used to"
if grep -qE '^[[:space:]]*tags:' "$W"; then
  fail "release.yml still has a tags: trigger; SKILL.md \"Release workflow\" says a new repo adds none"
fi

scenario "the tag branch and its check-release-tag.sh call are gone"
if grep -q 'check-release-tag' "$W"; then
  fail "release.yml must not call build/check-release-tag.sh -- the tag trigger is retired, and so is the script"
fi
if grep -q 'GITHUB_REF_TYPE' "$W"; then
  fail "release.yml must not branch on GITHUB_REF_TYPE -- there is no tag-triggered path left to branch on"
fi

scenario "the ver step forces rel=no unless this run is a push to refs/heads/main or a workflow_dispatch"
grep -q "refs/heads/main" "$W" || fail "the ver step must check GITHUB_REF against refs/heads/main"
grep -qE '^[[:space:]]*workflow_dispatch\) : ;;' "$W" || fail "the ver step's guard must leave rel alone for workflow_dispatch"

scenario "the reconcile caller dispatches with reconcile=true, not shipyard's local_release=true default"
grep -q 'dispatch-field: *reconcile=true' "$RECONCILE_W" \
  || fail "reconcile.yml must pass 'with: dispatch-field: reconcile=true' to the reusable workflow -- its default (local_release=true) always cuts N+1 ungated"

scenario "release.yml declares a workflow_dispatch boolean input named reconcile, default false"
grep -qE '^ *reconcile:$' "$W" || fail "release.yml's workflow_dispatch.inputs must declare a 'reconcile:' key"
awk '/^ *reconcile:$/{f=1;next} f && /type:/{print;exit}' "$W" | grep -q 'boolean' \
  || fail "the reconcile input must be type: boolean"
awk '/^ *reconcile:$/{f=1;next} f && /default:/{print;exit}' "$W" | grep -q 'false' \
  || fail "the reconcile input must default to false"
awk '/^ *reconcile:$/{f=1;next} f && /description:/{print;exit}' "$W" | grep -q 'reconcile backstop' \
  || fail "the reconcile input's description should say it is set by the nightly reconcile backstop"

scenario "the ver step gates rel=no on release-needed.sh only for the reconcile path, not for local_release"
grep -q 'release-needed.sh' "$W" || fail "the ver step must call release-needed.sh"
# spec: .github/workflows/release.yml -- the nearest 'if [' line above the release-needed.sh call
#       is the one that actually guards it; it must test both rel and RECONCILE, so a plain
#       local_release=true dispatch (RECONCILE=false) never reaches release-needed.sh and is never
#       gated by it.
GUARD_IF="$(awk '/release-needed\.sh/{print lastif; exit} /if \[/{lastif=$0}' "$W")"
[ -n "$GUARD_IF" ] || fail "release-needed.sh must be called inside an if [ ... ]; then block"
printf '%s\n' "$GUARD_IF" | grep -q 'RECONCILE' \
  || fail "the if guarding release-needed.sh must test RECONCILE, not just rel -- otherwise a human local_release=true dispatch is gated by it too: $GUARD_IF"
printf '%s\n' "$GUARD_IF" | grep -q 'rel' \
  || fail "the if guarding release-needed.sh must also test rel=yes -- no point asking release-needed.sh about a run that already won't publish: $GUARD_IF"

scenario "the ver step, actually run: reconcile gates on release-needed.sh, local_release stays ungated, a failing lookup fails the step"
# spec: .github/workflows/release.yml -- the scenario above only greps the guarding `if` line's
#       text, so a mutation that leaves that text alone but breaks its EFFECT (a `case` arm that
#       stops forcing rel=no, `|| true` swallowing a release-needed.sh failure, the gate relocated
#       after publish= is computed, the reconcile-to-local-mode line deleted, GH_TOKEN dropped from
#       the step's env:) still passes it. This scenario instead EXTRACTS the step's own env: names
#       and run: text and executes them, so it fails on the effect, not just the wording.
if [ -z "${SHIPYARD_SCRIPTS:-}" ] || [ ! -x "$SHIPYARD_SCRIPTS/release-state.sh" ] \
   || [ ! -x "$SHIPYARD_SCRIPTS/release-needed.sh" ] || [ ! -x "$SHIPYARD_SCRIPTS/release-mode.sh" ]; then
  echo "release-workflow: SHIPYARD_SCRIPTS not set to an installed shipyard -- skipping the ver-step scenario" >&2
  exit 77
fi
command -v git >/dev/null 2>&1 || { echo "release-workflow: git not found -- skipping the ver-step scenario" >&2; exit 77; }

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/release-ver-step.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT

# platform: a plain recursive copy, not `git clone` -- a clone reads committed history, and this
#           scenario must exercise whatever release.yml/build/* currently sit in the WORKING TREE
#           (this test run may itself be verifying an uncommitted edit). .git comes along too:
#           release-state.sh's upstream check runs `git ls-files` on build/derive-upstream-version.sh.
cp -R "$R/." "$SANDBOX/repo"

ENV_NAMES="$(awk '
  /^      - name: Derive version and release plan/ { instep=1 }
  instep && /^      - name:/ && !/Derive version and release plan/ { exit }
  instep && /^        env:/ { inenv=1; next }
  instep && inenv && /^        run:/ { inenv=0 }
  instep && inenv && /^          [A-Za-z_][A-Za-z0-9_]*:/ { print }
' "$W" | sed -E 's/^ *([A-Za-z_][A-Za-z0-9_]*):.*/\1/')"
[ -n "$ENV_NAMES" ] || fail "could not find the ver step's env: names in $W -- extraction is broken, or the step moved"

awk '
  /^      - name: Derive version and release plan/ { instep=1 }
  instep && /^      - name:/ && !/Derive version and release plan/ { exit }
  instep && /^        run: \|/ { inrun=1; next }
  instep && inrun {
    if ($0 ~ /^          /) { print substr($0, 11) }
    else if ($0 !~ /^[[:space:]]*$/) { exit }
  }
' "$W" > "$SANDBOX/ver-step.sh"
[ -s "$SANDBOX/ver-step.sh" ] || fail "could not extract the ver step's run: text from $W -- extraction is broken, or the step moved"

mkdir -p "$SANDBOX/bin"
# spec: .github/workflows/release.yml -- stands in for `gh` so release-needed.sh's lookup runs
#       against a fixture instead of the network. Fails without GH_TOKEN set (as the real `gh` would
#       refuse or rate-limit unauthenticated), so a mutation that drops GH_TOKEN from the ver step's
#       env: shows up as this scenario's release-needed.sh call failing, not as a silent pass.
cat > "$SANDBOX/bin/gh" <<'FAKEGH'
#!/bin/sh
set -eu
[ "${1:-}" = api ] || { echo "fake-gh: unsupported args: $*" >&2; exit 1; }
[ "${GH_FAKE_FAIL:-0}" != 1 ] || { echo "fake-gh: simulated API failure" >&2; exit 1; }
[ -n "${GH_TOKEN:-}" ] || { echo "fake-gh: authentication required (GH_TOKEN not set)" >&2; exit 1; }
cat "${GH_FAKE_RELEASES:?GH_FAKE_RELEASES not set}"
FAKEGH
chmod +x "$SANDBOX/bin/gh"

# platform: MAVERICKS_TAGS is version.sh's own test hook (its header: "Tag set comes from `git tag`,
#           or from $MAVERICKS_TAGS ... (tests)") -- it stands in for the git tag set so this
#           scenario does not depend on this checkout's actual release history.
U="$(cd "$SANDBOX/repo" && sh build/derive-upstream-version.sh)"
TAGSET="$U-mavericks.1"
EXPECT_FULL="$U-mavericks.2"
DIGEST="$(cd "$SANDBOX/repo" && sh "$SHIPYARD_SCRIPTS/release-state.sh")"

MATCH_RELEASES="$SANDBOX/releases-match.tsv"
printf 'v-test\tfalse\tMavergreen-State: %s\n' "$DIGEST" > "$MATCH_RELEASES"
NOMATCH_RELEASES="$SANDBOX/releases-nomatch.tsv"
printf 'v-other\tfalse\tMavergreen-State: v1:sha256:%s\n' \
  "0000000000000000000000000000000000000000000000000000000000000000" > "$NOMATCH_RELEASES"

out_field() { sed -n "s/^$2=//p" "$1" | tail -1; }   # $1=GITHUB_OUTPUT file  $2=key

run_ver_step() {  # $1=out-file $2=LOCAL_RELEASE $3=RECONCILE $4=GH_TOKEN $5=releases-file $6=GH_FAKE_FAIL
  outfile="$1"; want_local="$2"; want_reconcile="$3"; want_token="$4"; relfile="$5"; failflag="$6"
  : > "$outfile"
  env_args=""
  for name in $ENV_NAMES; do
    case "$name" in
      LOCAL_RELEASE) env_args="$env_args LOCAL_RELEASE=$want_local" ;;
      RECONCILE)     env_args="$env_args RECONCILE=$want_reconcile" ;;
      GH_TOKEN)      env_args="$env_args GH_TOKEN=$want_token" ;;
    esac
  done
  ( cd "$SANDBOX/repo" && env $env_args \
      PATH="$SANDBOX/bin:$PATH" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main \
      MAVERICKS_TAGS="$TAGSET" GH_FAKE_RELEASES="$relfile" GH_FAKE_FAIL="$failflag" \
      GITHUB_OUTPUT="$outfile" sh "$SANDBOX/ver-step.sh" ) > "$outfile.log" 2>&1
  return $?
}

rcA=0; run_ver_step "$SANDBOX/out-A" false true dummy-token "$MATCH_RELEASES" 0 || rcA=$?
[ "$rcA" -eq 0 ] || fail "reconcile=true with a release already carrying the digest: the ver step must still succeed, exited $rcA:
$(cat "$SANDBOX/out-A.log")"
[ "$(out_field "$SANDBOX/out-A" publish)" = false ] \
  || fail "reconcile=true with a release already carrying the digest must NOT publish (got publish=$(out_field "$SANDBOX/out-A" publish)) -- this is the double-cut this gate exists to stop"

rcB=0; run_ver_step "$SANDBOX/out-B" false true dummy-token "$NOMATCH_RELEASES" 0 || rcB=$?
[ "$rcB" -eq 0 ] || fail "reconcile=true with no release carrying the digest: the ver step must succeed, exited $rcB:
$(cat "$SANDBOX/out-B.log")"
[ "$(out_field "$SANDBOX/out-B" publish)" = true ] \
  || fail "reconcile=true with no release carrying the digest must publish (got publish=$(out_field "$SANDBOX/out-B" publish))"
[ "$(out_field "$SANDBOX/out-B" full)" = "$EXPECT_FULL" ] \
  || fail "reconcile=true must still cut local mode (N+1): expected full=$EXPECT_FULL, got $(out_field "$SANDBOX/out-B" full)"

rcC=0; run_ver_step "$SANDBOX/out-C" true false dummy-token "$MATCH_RELEASES" 0 || rcC=$?
[ "$rcC" -eq 0 ] || fail "a human local_release=true dispatch must succeed, exited $rcC:
$(cat "$SANDBOX/out-C.log")"
[ "$(out_field "$SANDBOX/out-C" publish)" = true ] \
  || fail "a human local_release=true dispatch must stay ungated even when a release already carries the digest (got publish=$(out_field "$SANDBOX/out-C" publish))"

rcD=0; run_ver_step "$SANDBOX/out-D" false true dummy-token "$NOMATCH_RELEASES" 1 || rcD=$?
[ "$rcD" -ne 0 ] || fail "reconcile=true with a failing release-needed.sh lookup must fail the ver step, not silently continue and publish"

echo "release-workflow: ok"
