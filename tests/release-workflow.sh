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

job() { awk -v j="  $1:" '$0 == j { f = 1; print; next } f && /^  [A-Za-z]/ { exit } f { print }' "$W"; }
step_run() {  # print the run: | body of the step in job $1 whose header line matches $2
  job "$1" | awk -v s="$2" '
    index($0, s) { f = 1; next }
    f && /^      - / { exit }
    f && /^ *run: \|/ { r = 1; match($0, /^ */); ind = RLENGTH + 2; next }
    r { if (substr($0, 1, ind) ~ /^ +$/ && length($0) > ind) print substr($0, ind + 1)
        else if ($0 !~ /^[[:space:]]*$/) exit
        else print "" }'
}

scenario "an on-mavericks job runs acceptance-onbox.sh on a 10.9 guest, and publish waits for it"
ONM="$(job on-mavericks)"
[ -n "$ONM" ] || fail "release.yml needs an on-mavericks job: tests/acceptance-onbox.sh on Mavergreen/mavericks-vm, the only place the applier meets a real 10.9 trust store before a release ships"
printf '%s\n' "$ONM" | grep -qE '^    needs: \[build\]$' || fail "on-mavericks must need [build], whose ca-certs-dist artifact it installs"
printf '%s\n' "$ONM" | grep -q 'uses: Mavergreen/mavericks-vm@v1' || fail "on-mavericks must boot its guest with Mavergreen/mavericks-vm@v1"
printf '%s\n' "$ONM" | grep -qE '^ +sync-time: true$' \
  || fail "on-mavericks must pass sync-time: true -- verify-cert judges validity dates by the guest's clock, and a cached guest's clock is stale"
job publish | grep -E '^    needs:' | grep -q 'on-mavericks' || fail "publish must need on-mavericks, so no release ships that failed on the guest"

scenario "an on-macos job runs acceptance-onbox.sh on Apple Silicon and on Intel, and publish waits for it"
ONM2="$(job on-macos)"
[ -n "$ONM2" ] || fail "release.yml needs an on-macos job: tests/acceptance-onbox.sh on the newest macOS runners, where the product promises to change no trust settings"
printf '%s\n' "$ONM2" | grep -qE '^    needs: \[build\]$' || fail "on-macos must need [build], whose ca-certs-dist artifact it installs"
printf '%s\n' "$ONM2" | grep -qE '^ +fail-fast: false$' || fail "on-macos must set fail-fast: false, so one runner's failure does not hide the other's result"
printf '%s\n' "$ONM2" | grep -qE '^ +runs-on: \$\{\{ matrix.runner \}\}$' || fail "on-macos must run on its matrix's runner"
printf '%s\n' "$ONM2" | awk '/- runner: macos-26$/ { getline; print }' | grep -qE "arm64: '1'$" \
  || fail "on-macos's matrix must include runner: macos-26 with arm64: '1' (Apple Silicon)"
printf '%s\n' "$ONM2" | awk '/- runner: macos-26-intel$/ { getline; print }' | grep -qE "arm64: '0'$" \
  || fail "on-macos's matrix must include runner: macos-26-intel with arm64: '0' (Intel)"
job publish | grep -E '^    needs:' | grep -q 'on-macos' || fail "publish must need on-macos, so no release ships that failed on a modern Mac"

ONB="$(mktemp -d "${TMPDIR:-/tmp}/release-onmavericks.XXXXXX")"
trap 'rm -rf "$ONB"' EXIT
step_run on-mavericks 'uses: Mavergreen/mavericks-vm@v1' > "$ONB/guest.sh"
[ -s "$ONB/guest.sh" ] || fail "could not extract the mavericks-vm step's run: text from on-mavericks"
step_run on-macos "name: Acceptance on this runner's macOS" > "$ONB/macos.sh"
[ -s "$ONB/macos.sh" ] || fail "on-macos needs a step named \"Acceptance on this runner's macOS\""
for j in on-mavericks on-macos; do
  step_run "$j" 'name: The latest published release, to upgrade from' > "$ONB/previous-$j.sh"
  [ -s "$ONB/previous-$j.sh" ] || fail "$j needs a step named 'The latest published release, to upgrade from' that fetches the pkg it upgrades from"
done

mkdir -p "$ONB/bin"
cat > "$ONB/bin/sysctl" <<'FAKESYSCTL'
#!/bin/sh
[ "$*" = "-n hw.optional.arm64" ] || { echo "fake-sysctl: unsupported: $*" >&2; exit 1; }
[ -n "${FAKE_ARM64:-}" ] || { echo "sysctl: unknown oid 'hw.optional.arm64'" >&2; exit 1; }
echo "$FAKE_ARM64"
FAKESYSCTL
chmod +x "$ONB/bin/sysctl"
acceptance() {  # $1=step script; $2=stub exit status; $3=1 to stage a previous pkg; $4=hw.optional.arm64 ('' = no such oid); $5=WANT_ARM64
  rm -rf "$ONB/g"; mkdir -p "$ONB/g/dist" "$ONB/g/tests" "$ONB/g/previous"
  : > "$ONB/g/dist/ca-certs-9.9.9-mavericks.2.pkg"; : > "$ONB/g/dist/roots.txt"; : > "$ONB/g/dist/ca-certs.xml"
  [ "$3" != 1 ] || : > "$ONB/g/previous/ca-certs-9.9.9-mavericks.1.pkg"
  printf '#!/bin/sh\nprintf "%%s|%%s\\n" "${CA_CERTS_ONBOX:-}" "$*" > "%s/g/args"\nexit %s\n' "$ONB" "$2" > "$ONB/g/tests/acceptance-onbox.sh"
  ( cd "$ONB/g" && PATH="$ONB/bin:$PATH" FAKE_ARM64="$4" WANT_ARM64="$5" sh -e "$1" ) > "$ONB/g/log" 2>&1
}
for step in guest macos; do
  scenario "the $step step passes the pkg, and the previous release's pkg when there is one, to acceptance-onbox.sh"
  rc=0; acceptance "$ONB/$step.sh" 0 0 1 1 || rc=$?
  [ "$rc" -eq 0 ] || fail "$step: with acceptance-onbox.sh passing and no previous release, the step must pass, exited $rc: $(cat "$ONB/g/log")"
  [ "$(cat "$ONB/g/args")" = "1|dist/ca-certs-9.9.9-mavericks.2.pkg" ] \
    || fail "$step: with no previous release, want CA_CERTS_ONBOX=1 and the one pkg, got: $(cat "$ONB/g/args")"
  rc=0; acceptance "$ONB/$step.sh" 0 1 1 1 || rc=$?
  [ "$rc" -eq 0 ] || fail "$step: with a previous release staged, the step must pass, exited $rc: $(cat "$ONB/g/log")"
  [ "$(cat "$ONB/g/args")" = "1|dist/ca-certs-9.9.9-mavericks.2.pkg previous/ca-certs-9.9.9-mavericks.1.pkg" ] \
    || fail "$step: with a previous release staged, want the pkg and then the previous pkg, got: $(cat "$ONB/g/args")"
  rc=0; acceptance "$ONB/$step.sh" 77 0 1 1 || rc=$?
  [ "$rc" -ne 0 ] || fail "$step: acceptance-onbox.sh exiting 77 (a skip) must fail the step: this job exists so that it runs"
  rc=0; acceptance "$ONB/$step.sh" 1 1 1 1 || rc=$?
  [ "$rc" -ne 0 ] || fail "$step: acceptance-onbox.sh failing must fail the step"
done

scenario "the macos step refuses a runner whose hardware is not what its matrix leg says"
rc=0; acceptance "$ONB/macos.sh" 0 0 '' 0 || rc=$?
[ "$rc" -eq 0 ] || fail "on Intel (no hw.optional.arm64) with WANT_ARM64=0, the step must pass, exited $rc: $(cat "$ONB/g/log")"
rc=0; acceptance "$ONB/macos.sh" 0 0 1 0 || rc=$?
[ "$rc" -ne 0 ] || fail "an Apple Silicon runner on the Intel leg must fail the step -- the label did not give the hardware the leg tests"
rc=0; acceptance "$ONB/macos.sh" 0 0 '' 1 || rc=$?
[ "$rc" -ne 0 ] || fail "an Intel runner on the Apple Silicon leg must fail the step -- a macos-26 label has landed on x86_64 before"
rc=0; acceptance "$ONB/macos.sh" 0 0 0 1 || rc=$?
[ "$rc" -ne 0 ] || fail "hw.optional.arm64=0 on the Apple Silicon leg must fail the step"

cat > "$ONB/bin/gh" <<'FAKEGH'
#!/bin/sh
set -eu
echo "$*" >> "$GH_LOG"
[ "${GH_FAKE_FAIL:-0}" != 1 ] || { echo "fake-gh: simulated API failure" >&2; exit 1; }
case "$1 $2" in
  "release list") printf '%s' "$GH_FAKE_LATEST"; [ -z "$GH_FAKE_LATEST" ] || echo ;;
  "release download") d=""; while [ $# -gt 0 ]; do case "$1" in --dir|-D) d="$2"; shift ;; esac; shift; done
                      : > "${d:?}/ca-certs-$GH_FAKE_LATEST.pkg" ;;
  *) echo "fake-gh: unsupported: $*" >&2; exit 1 ;;
esac
FAKEGH
chmod +x "$ONB/bin/gh"
previous() {  # $1=step script; $2=latest tag or empty; $3=1 to fail every gh call
  rm -rf "$ONB/p"; mkdir -p "$ONB/p"; : > "$ONB/p/gh.log"
  ( cd "$ONB/p" && PATH="$ONB/bin:$PATH" GH_LOG="$ONB/p/gh.log" GH_FAKE_LATEST="$2" GH_FAKE_FAIL="$3" \
      GH_TOKEN=dummy GITHUB_REPOSITORY=Mavergreen/ca-certs bash -e "$1" ) > "$ONB/p/log" 2>&1
}
for j in on-mavericks on-macos; do
  scenario "$j's previous-release step downloads the latest release's pkg, fetches nothing when there is none, and fails when gh does"
  rc=0; previous "$ONB/previous-$j.sh" 3.130.0-mavericks.1 0 || rc=$?
  [ "$rc" -eq 0 ] || fail "$j: with a published release, the step must pass, exited $rc: $(cat "$ONB/p/log")"
  [ -f "$ONB/p/previous/ca-certs-3.130.0-mavericks.1.pkg" ] || fail "$j: with a published release, its pkg must land in previous/: $(cat "$ONB/p/gh.log")"
  grep -q 'release list.*--exclude-drafts' "$ONB/p/gh.log" || fail "$j: the latest release must exclude drafts -- a draft is no release anyone installed: $(cat "$ONB/p/gh.log")"
  rc=0; previous "$ONB/previous-$j.sh" "" 0 || rc=$?
  [ "$rc" -eq 0 ] || fail "$j: with no release yet, the step must pass, exited $rc: $(cat "$ONB/p/log")"
  [ -d "$ONB/p/previous" ] && [ -z "$(ls "$ONB/p/previous")" ] || fail "$j: with no release yet, previous/ must exist and be empty"
  grep -q 'release download' "$ONB/p/gh.log" && fail "$j: with no release yet, nothing may be downloaded: $(cat "$ONB/p/gh.log")"
  rc=0; previous "$ONB/previous-$j.sh" 3.130.0-mavericks.1 1 || rc=$?
  [ "$rc" -ne 0 ] || fail "$j: a failing gh must fail the step -- an unanswered lookup must not read as 'no previous release' and skip the upgrade leg"
done
rm -rf "$ONB"; trap - EXIT

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
