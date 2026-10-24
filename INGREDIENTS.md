# Build ingredients

Everything baked into the shipped package, and how a change to it reaches a release. At the end:
what other products can rely on once it's installed, and how to uninstall it.

| Ingredient | Pinned in | Renovate | On a bump |
|---|---|---|---|
| Mozilla NSS `certdata.txt` (own upstream) | `NSS_TAG` (`NSS_x_y[_z]_RTM`) | ✅ custom datasource on Mozilla's release directory (`ftp.mozilla.org/pub/security/nss/releases/`), regex versioning. Not `mozilla/nss`'s tags: a tag can precede its tarball and `SHA256SUMS` by hours (3.132: 18:20 tag, 23:12 files), and a bump proposed in between fails its build with nothing to re-run it | `build/version.sh` cuts `<x.y.z>-mavericks.1` |
| Withdrawn roots | `withdrawn.md` + `withdrawn/` | not an ingredient: our own reviewed policy | a change moves the declared state below; the nightly backstop re-cuts it, or `workflow_dispatch local_release=true` ships it immediately |
| AquaTransport's root list | `aquatransport-roots.txt` | ❌ untrackable by Renovate: the DMG's URL is overwritten in place, so no feed names a release. `aquatransport-roots.yml` compares it with the live DMG daily and goes red when they differ | regenerate with `build/aquatransport-roots.sh`, read the difference, commit; that moves the declared state below and cuts a release |
| MacOSX SDK, Sparkle, packaging helpers | `Mavergreen/shipyard@v1` | ✅ github-actions manager | `@v1` moves without a pin change; nothing repackages by itself |

`UPSTREAM_VERSION` is derived from `NSS_TAG` by `build/derive-upstream-version.sh` and is
gitignored. It always has three parts (`3.130.0`), because NSS writes `3.130` but means `3.130.0`,
and Sparkle must order `3.130.0-mavericks.2` below `3.130.1-mavericks.1`.

The NSS tarball is verified against the `SHA256SUMS` file Mozilla publishes beside it, so a bump
needs no hand-pasted hash.

## Declared state

- upstream: NSS_TAG
- withdrawn: withdrawn.md
- aquatransport-roots: aquatransport-roots.txt

`withdrawn.md` is declared because a change to it is a change to what machines trust, and should
ship. Its certificates in `withdrawn/` are pinned by the fingerprints `withdrawn.md` lists
(`tests/withdrawn.sh`).

`aquatransport-roots.txt` is declared for the same reason: it decides which trust settings ca-certs
leaves to AquaTransport (docs/TRUST-POLICY.md #12).

Any edit to `withdrawn.md` changes the declared state and cuts a release, prose included, because
the whole file is hashed, not just its table.

## No repackage-on-ingredient-bump caller here

The only versioned input is the own upstream, which `release.yml` already turns into a
`-mavericks.1`. `withdrawn.md` is policy, not a pin, so there's no `repackage-decision.sh` caller
watching it for a push-time dispatch. A change to it now moves the declared state above, so the
nightly `reconcile.yml` backstop re-cuts a release that didn't happen; an immediate repackage still
means `workflow_dispatch local_release=true` by hand.

## Release notes

`release.yml` calls shipyard's `release-notes.sh` (`--product "CA Certificates"`, `--min-os
10.9.5`), then appends `build/roots-notes.sh`'s `### Roots` section. It compares this release's
`roots.txt` with the previous release's. One file is both the appcast description and the Release
body.

A new NSS release links NSS's own notes, through `build/upstream-release-notes-url.sh`. NSS names
those pages with its own spelling (`nss_3_130.html`, `nss_3_126_1.html`), so the hook drops the
`.0` that `UPSTREAM_VERSION` adds.

## Conformance deviations

(The section is empty: nothing is installed outside the family's paths.)

## What other products can rely on

- **The bundle path is a contract:** `/usr/local/mavergreen/ca-certs/etc/openssl/certs/ca-certificates.crt`.
  It is registered with ca-certs' short name in shipyard's `scripts/product-names`, and won't move.
  It holds every root Mozilla trusts for websites (`docs/TRUST-POLICY.md` #2, #3), on every macOS,
  less any root the running Mac's admin trust settings deny for TLS (#13).
- **Only root can change it:** every file under `/usr/local/mavergreen/ca-certs` is owned by root,
  and only the installer, running as root, rewrites the bundle.
- **Who it's for:** programs that can't read the keychain. A program that reads the keychain too
  should let the keychain's denials win, as Mavergreen's Go toolchains do: they add the bundle to what
  they trust, never in front of the keychain.
- **Installed?** `/usr/local/mavergreen/ca-certs/mavergreen.plist` exists. Its `version` key is the
  release (`3.130.0-mavericks.1`).
- **Which Mozilla data?** `/usr/local/mavergreen/var/ca-certs/receipt` has a line `nss <version>`
  (`nss 3.130.0`).
- **Were trust settings changed?** The same receipt has `keychain yes`, or `keychain no <reason>` on
  macOS 11 and later, or when installed onto a disk that wasn't booted.
- **Which roots were left out of the bundle?** One `bundle-omitted <SHA-1>` line each.

## Uninstall

    sudo mavergreen uninstall ca-certs

This reverses exactly what the receipt records. It leaves your own settings, and AquaTransport's,
alone (`docs/TRUST-POLICY.md` #8, #12).

To go back to the trust settings from before the first install, all at once, run this **before**
uninstalling, because uninstall deletes `/usr/local/mavergreen/var/ca-certs/`, where the saved copy
lives:

    sudo security trust-settings-import -d /usr/local/mavergreen/var/ca-certs/trust-settings-backup.plist
