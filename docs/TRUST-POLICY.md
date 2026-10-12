# Trust policy

Every choice this product makes about whom your Mac trusts: the decision, what it beat, the evidence,
and what would change it. This file is the authority.

Measured on 2026-09-25, on a real Mac OS X 10.9.5 machine, against NSS 3.130.

## At a glance

**What gets trusted**

1. Mozilla's data is the source.
2. Only roots Mozilla trusts for websites are added.
3. A root past its "distrust after" date is left out.
4. Added roots are trusted for all uses, not only websites.

**What gets distrusted**

5. Only CAs Mozilla withdrew for misbehavior.
6. Distrust applies to secure websites (TLS) only.
7. Apple's own roots are never distrusted, and Apple's files are never edited.

**How your Mac is changed**

8. A trust setting that already exists is never touched.
9. Every change is recorded and can be undone.
10. On macOS 11 and later, only the bundle file is installed.
11. Updates are automatic, and every release says what changed.
12. Roots AquaTransport's root component also sets are left to it, whichever was installed first.

---

## 1. Mozilla's data is the source

**Decision:** use `certdata.txt` from a pinned NSS release (Mozilla's security library), checked
against the SHA256SUMS file Mozilla publishes beside it.

**Instead of:**

| Alternative | Why not |
|---|---|
| curl.se's `cacert.pem`, or Python's certifi | They list only what to trust, so they can never say what to stop trusting. curl's has no versions, so updates can't be tracked. |
| Apple's current trust store | Its releases can't be pinned to. It's still used as evidence in #5. |

**Evidence:** our trusted set is fingerprint-identical to curl's bundle, which curl builds from
Mozilla's data, generated on the same day, apart from the roots in #3.

**Reconsider when:** Mozilla stops publishing `certdata.txt` with NSS releases.

## 2. Only roots Mozilla trusts for websites are added

**Decision:** add a root only if Mozilla marks it trusted for server authentication. That was 121
roots as of NSS 3.130.

**Not added:** roots Mozilla trusts only for email, and roots it retired from website use. Mozilla
retires a root by keeping the certificate and switching off its website trust.

## 3. A root past its "distrust after" date is left out

**Decision:** once a root's "distrust certificates issued after" date has passed, leave it out of
both the keychain and the bundle. As of NSS 3.130 that's one root: Izenpe.com, dated 2026-04-15.

**Instead of:** including it, as curl's bundle does. Neither the keychain nor a PEM file can express
"only before a date", so including it would also trust newer certificates that Mozilla rejects.

## 4. Added roots are trusted for all uses

**Decision:** `security add-trusted-cert -d -r trustRoot`, trusted for every purpose.

**Instead of:**

| Alternative | What it broke, measured with `www.google.com`'s chain |
|---|---|
| Websites only (`-p ssl`), Mozilla's exact scope | X.509 "basic" validation: success → `NOT_TRUSTED` |
| Websites + basic (`-p ssl -p basic`) | S/MIME validation: usage check → `NOT_TRUSTED` |
| **All uses (chosen)** | Nothing: every result matched the untouched machine |

**Why the narrower options break things:** many modern roots are cross-signed by a root Apple shipped
in 2013, and today 10.9 validates their chains through that old root, for every purpose. Once we add
the modern root itself, 10.9 anchors the chain on our copy. It finds no trust for the other purposes
and doesn't fall back to the old path.

**Cost:** a root Mozilla trusts only for websites is also trusted here for other purposes, such as
signed email. A certificate still has to be issued for that purpose to pass.

**Also:** AquaTransport and hand-added roots are already trusted this way.

**Reconsider when:** a root we add is shown to issue non-website certificates Mozilla wouldn't accept.

## 5. Only CAs Mozilla withdrew for misbehavior are distrusted

**Decision:** distrust only the roots of CAs Mozilla removed *for cause*, each listed with evidence in
[`withdrawn.md`](../withdrawn.md): 25 roots from Symantec (GeoTrust, thawte, VeriSign), StartCom,
Camerfirma, Certinomis and Entrust (including AffirmTrust), as of September 2026. Adding one is a
reviewed change.

**The scale:** 10.9 ships 211 roots, and 181 aren't trusted by Mozilla for websites. Apple's own
current store (`apple-oss-distributions/security_certificates`) still ships 38 of those and has
dropped the other 143.

**Instead of:** two stricter choices, below. Both stay possible. Each needs evidence we don't have
yet, and the steps to get it are listed.

### 5a. Stricter: also distrust roots retired for age

**What it would do:** also distrust roots Mozilla retired because they got old, not because their CA
misbehaved. Among them:

- the 17 that Mozilla still lists but no longer trusts for websites, such as GlobalSign Root CA,
  DigiCert Global Root CA, and the Go Daddy, COMODO and Entrust roots;
- the roots Mozilla removed outright for age, such as AddTrust, UTN-USERFirst, Baltimore and DST Root
  CA X3.

**Why not now:**

- **Age isn't evidence of harm.** Mozilla retires old roots as hygiene, on a schedule, while their
  CAs are in good standing.
- **A current Mac still trusts all 17.** Distrusting them would make a 10.9 machine stricter than
  Apple is today.
- **Big parts of the web chain through them.** In our test, distrusting GlobalSign Root CA broke
  `www.google.com` on 10.9. Adding GTS Root R1 (as #2 does) should give that chain another way to
  verify, but we tested the two changes separately, never together. Whether this choice breaks a site
  depends on which roots we've already added.
- **Unmeasured.** Nobody has counted what still depends on these roots.

**To make it with confidence:**

1. **Census.** For each candidate, count the unexpired certificates in the public Certificate
   Transparency logs that reach this root and *no root we trust*, cross-signs included.
   Pass: zero, or every one looked at and accepted.
2. **Site replay.** On a 10.9 machine with our added roots, load thousands of popular and
   long-tail sites, with and without this choice. Pass: every site that fails only under this choice
   also fails on a current Mac or in Firefox.
3. **Apple services.** Under this choice on 10.9, check Software Update, the App Store, iCloud
   sign-in and Mail. Pass: each works exactly as before.

About a day of work, most of it the census query.

### 5b. Strictest: distrust everything Mozilla doesn't trust, except Apple's own roots

**What it would do:** distrust 176 roots: the 181 that 10.9 trusts and Mozilla doesn't, less Apple's
own 5. That's 158 more than today. It includes everything in 5a, plus roots Mozilla never included
at all: government roots (the US Department of Defense and Federal PKI, Japan, Belgium…), national
ID schemes, and older commercial CAs.

**Why not now:**

- **Absence isn't distrust.** Mozilla's program decides what Firefox trusts by default. A root it
  never took in isn't a root it found unsafe.
- **Government and enterprise sites could break.** Sites that use their own PKI, like the US
  Department of Defense's, chain to roots Mozilla never included. Firefox users there install those
  roots themselves; on 10.9 we'd be actively blocking the ones Apple shipped.
- **Stricter than a current Mac.** Apple still ships 38 of these roots today.
- **Unmeasured,** like 5a, and with a longer tail of affected sites that are harder to find.

**To make it with confidence:** everything in 5a, plus:

1. **A government and institutional site list.** Add `.gov` and `.mil` sites and the national
   portals of countries whose roots are affected to the replay. Pass: as in 5a.
2. **A reason per root.** For each of the 38 a current Mac still trusts, find a reason beyond
   "Mozilla doesn't include it". Leave out any root that has none.
3. **A tested escape hatch.** Document how a user re-trusts one root for themselves (a user-level
   setting in Keychain Access overrides ours), and confirm on 10.9 that it works.

A few days of work, mostly finding sites and reviewing results.

### In between: distrust what both Apple and Mozilla have dropped

143 of the 181 are gone from both Mozilla's store and Apple's current one. Distrusting exactly those
can't make 10.9 stricter than a current Mac or Firefox, by construction. It's the natural first
widening once 5a's census exists, and needs the same three steps.

We found no published census of this kind. Mozilla's own discussions show nobody has taken on the
job: when Mozilla surveyed CAs about removing old roots, CAs asked Mozilla to publish usage data, and
Mozilla replied that measuring the impact was the CAs' job.

**Not repeated:** roots already on Apple's own 10.9 blocklist (DigiNotar, CNNIC, Trustwave and others,
in `SystemTrustSettings.plist`).

## 6. Distrust applies to secure websites (TLS) only

**Decision:** `security add-trusted-cert -d -r deny -p ssl`.

**Instead of:** distrusting for all uses. Mozilla's decisions are about website trust, so websites
only is the smallest change that does the job.

**Evidence, from a TLS-only distrust of one of Apple's built-in roots:**

- Keychain-verified `curl` rejected the site: `kSecTrustResultDeny`.
- X.509 "basic" validation of the same chain still passed.
- Mavergreen's Go toolchain honored the distrust.

**Why #4's problem doesn't apply:** the distrusted root is one of Apple's own certificates. A copy
of it goes into System.keychain alongside the setting and is recorded, so uninstall removes it,
but it's the same certificate, so chain building doesn't change.

## 7. Apple's own roots are never distrusted, and Apple's files are never edited

**Decision:** every change is a trust setting in the admin domain. That's the documented, reversible
mechanism Keychain Access itself uses. Apple's roots underpin software updates, the App Store and code
signing, so they're never distrusted.

**Instead of:**

| Alternative | Why not |
|---|---|
| Per-user trust settings | They help one user only, and writing them prompts for a password. |
| Replacing Apple's root store file | Hard to undo, and it breaks Apple's own verification. |

## 8. A trust setting that already exists is never touched

**Decision:** if a certificate already has an admin trust setting (yours, your IT department's,
AquaTransport's), leave it exactly as it is, record that, and never remove it on uninstall. If that
setting later goes away, the next update adds ours, and from then on it is ours.

**Instead of:** applying ours over it. Measured: re-adding a certificate *replaces* its settings. A
hand-added ISRG Root X1 went from 13 per-purpose settings to our 1.

**What this doesn't cover:** a trust setting this product made is ours. If you delete one of ours in
Keychain Access, the next update puts it back, because the record says it's ours and the release
still asks for it. To opt out of one root for yourself, give it a user-level setting in Keychain
Access, which takes precedence over admin settings, or uninstall.

## 9. Every change is recorded and can be undone

**Decision:** before its first change, save the admin trust settings. Then record every setting added
and every certificate imported. Uninstall reverses exactly that record.

**Evidence:**

- Restoring the saved settings brings the file back byte for byte.
- Restoring does *not* remove imported certificates from the keychain, which is why the record lists
  them too.

Uninstalling from a disk you haven't booted from is refused while that disk's record lists changes.
Its trust settings can only be undone by booting from it, and removing the record would strand them.

## 10. On macOS 11 and later, only the bundle file is installed

**Decision:** install the PEM bundle and change no trust settings. From Big Sur on, macOS requires a
password to change admin trust.

**Instead of:**

| Alternative | Why not |
|---|---|
| Refuse to install | Developers on modern Macs would lose the bundle other products rely on. |
| Prompt for a password | `security` itself would ask for the password, which an installer script can't answer. |

## 11. Updates are automatic, and every release says what changed

**Decision:** each new NSS release is picked up, rebuilt, and released if the build and its checks
pass. Each release's notes list the roots added, removed and distrusted since the previous release,
by name and fingerprint.

**Instead of:** keeping the generated certificate files in the repository. They'd be stale in every
automated update, and the release notes already show every change.

## 12. Roots AquaTransport's root component also sets are left to it, whichever was installed first

**Decision:** when AquaTransport's "Modern Root Certificates" component has been installed on the
disk, any root on its list that has an admin trust setting is treated as its setting, not ours. We
drop it from our record, so no update and no uninstall ever undoes it. Its list is
`aquatransport-roots.txt`, read from the AquaTransport download.

**Why:** that component never undoes its settings, even when AquaTransport is uninstalled. It
skips a root that's already in the System keychain, and denies its 7 roots for every use, replacing
any setting already there. So when it's installed *after* ca-certs, it leaves no trace for the roots
we'd already added. Without this rule, uninstalling ca-certs would take away the trust it meant to
add (Let's Encrypt, Amazon, Google and others) and its 7 denials. Installed *before* ca-certs, its
settings already exist, and #8 leaves them alone.

**Instead of:**

| Alternative | Why not |
|---|---|
| Say in the README which order to install in | Every AquaTransport update runs the root component again unless you uncheck it, so the order isn't really yours to keep. |
| Warn at uninstall only | You'd still lose the roots; the warning only says so. |
| Read AquaTransport's list from its source repository | The download is what's installed. The repository can differ from it. |

**What this costs:** a root on AquaTransport's list keeps its trust after you uninstall ca-certs,
even if you installed ca-certs first. That's what the root component would have done on its own.
The list comes from the current download, not the version you installed. A root a newer version
added is left alone even if your older one never set it.

**How it stays current:** the download's address never changes, so nothing announces a new version.
A daily check (`aquatransport-roots.yml`) compares the download's list with ours and fails when they
differ. A person then regenerates the file with `build/aquatransport-roots.sh`, reads the change and
commits it, which cuts a release. The build refuses to ship if AquaTransport trusts a root we
distrust, or the other way round. Today the two lists agree: its 14 trusted roots are all among
ours, and its 7 distrusted roots are all in `withdrawn.md`.

**Reconsider when:** AquaTransport records its own claims somewhere we can read, or stops shipping
its root component.
