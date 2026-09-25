# Withdrawn roots

The roots this product distrusts for secure websites (TLS). Each one is a root that Mac OS X 10.9
trusts and that Mozilla withdrew **for cause**, meaning the certificate authority misbehaved. Why
only these: [`docs/TRUST-POLICY.md`](docs/TRUST-POLICY.md) #5.

**25 roots from 5 certificate authorities.** Checked 2026-09-26 against:

- the roots a 10.9.5 machine ships;
- Mozilla's [removed-root report](https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReport);
- each root's removal bug.

Every entry below is unexpired, and none is already on Apple's own 10.9 blocklist.

**To add a root:** open a pull request that adds one row, with its SHA-256 fingerprint and a link to
Mozilla's record showing it was withdrawn for cause. A root withdrawn for age, or retired by its own
CA, doesn't qualify.

## 1. Symantec (GeoTrust, thawte, VeriSign): 10 roots

**Why:** years of misissuance and oversight failures, after which Mozilla distrusted every Symantec
TLS certificate (Firefox 63, 2018) and later removed the roots "as per the continuation of the
distrust of Symantec root certificates."

**Evidence:** [Mozilla: Distrust of Symantec TLS Certificates](https://blog.mozilla.org/security/2018/03/12/distrust-symantec-tls-certificates/),
[Symantec issues list](https://wiki.mozilla.org/CA/Symantec_Issues), removal bugs
[1670769](https://bugzilla.mozilla.org/show_bug.cgi?id=1670769),
[1686854](https://bugzilla.mozilla.org/show_bug.cgi?id=1686854),
[1618402](https://bugzilla.mozilla.org/show_bug.cgi?id=1618402).

| Root | SHA-256 | Expires |
|---|---|---|
| GeoTrust Primary Certification Authority | `37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C` | 2036 |
| GeoTrust Primary Certification Authority - G2 | `5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766` | 2038 |
| GeoTrust Primary Certification Authority - G3 | `B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4` | 2037 |
| thawte Primary Root CA | `8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F` | 2036 |
| thawte Primary Root CA - G2 | `A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557` | 2038 |
| thawte Primary Root CA - G3 | `4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C` | 2037 |
| VeriSign Class 3 Public Primary Certification Authority - G3 | `EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244` | 2036 |
| VeriSign Class 3 Public Primary Certification Authority - G4 | `69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79` | 2038 |
| VeriSign Class 3 Public Primary Certification Authority - G5 | `9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF` | 2036 |
| VeriSign Universal Root Certification Authority | `2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C` | 2037 |

## 2. StartCom: 3 roots

**Why:** WoSign secretly acquired StartCom. Mozilla found WoSign backdating certificates and other
misissuance, and found the two CAs sharing infrastructure. Mozilla distrusted both CAs' certificates
issued after October 2016, then removed the roots.

**Evidence:** [Mozilla: Distrusting New WoSign and StartCom Certificates](https://blog.mozilla.org/security/2016/10/24/distrusting-new-wosign-and-startcom-certificates/),
[WoSign issues list](https://wiki.mozilla.org/CA:WoSign_Issues), bugs
[1309707](https://bugzilla.mozilla.org/show_bug.cgi?id=1309707) (distrust) and
[1392849](https://bugzilla.mozilla.org/show_bug.cgi?id=1392849) (removal).

| Root | SHA-256 | Expires |
|---|---|---|
| StartCom Certification Authority | `C766A9BEF2D4071C863A31AA4920E813B2D198608CB7B7CFE21143B836DF09EA` | 2036 |
| StartCom Certification Authority | `E17890EE09A3FBF4F48B9C414A17D637B7A50647E9BC752322727FCC1742A911` | 2036 |
| StartCom Certification Authority G2 | `C7BA6567DE93A798AE1FAA791E712D378FAE1F93C4397FEA441BB7CBE6FD5995` | 2039 |

The two "StartCom Certification Authority" rows are separate certificates with the same name.

## 3. Camerfirma: 4 roots

**Why:** a long record of compliance failures (misissuance, improper delegation, failing to revoke).
In 2021 Mozilla switched off website trust for the two 2008 roots and set an email cutoff for the two
2003 roots, so its action covered all four. The 2003 roots had already stopped being used for
websites, so distrusting them here costs nothing.

**Evidence:** [Camerfirma issues list](https://wiki.mozilla.org/CA/Camerfirma_Issues), bug
[1692094](https://bugzilla.mozilla.org/show_bug.cgi?id=1692094) (Mozilla's action on all four roots).

| Root | SHA-256 | Expires |
|---|---|---|
| Chambers of Commerce Root - 2008 | `063E4AFAC491DFD332F3089B8542E94617D893D7FE944E10A7937EE29D9693C0` | 2038 |
| Global Chambersign Root - 2008 | `136335439334A7698016A0D324DE72284E079D7B5220BB8FBD747816EEBEBACA` | 2038 |
| Chambers of Commerce Root | `0C258A12A5674AEF25F28BA7DCFAECEEA348E541E6F5CC4EE63B71B361606AC3` | 2037 |
| Global Chambersign Root | `EF3CB417FC8EBF6F97876C9E4ECE39DE1EA5FE649141D1028B7D11C0B2298CED` | 2037 |

## 4. Certinomis: 1 root

**Why:** compliance failures, including signing two intermediate CAs controlled by StartCom in 2017,
after StartCom was distrusted, and not disclosing them for 111 days. Removal followed "an issues list
and resulting discussion" on Mozilla's policy list.

**Evidence:** [Certinomis issues list](https://wiki.mozilla.org/CA/Certinomis_Issues), bug
[1552374](https://bugzilla.mozilla.org/show_bug.cgi?id=1552374).

| Root | SHA-256 | Expires |
|---|---|---|
| Certinomis - Root CA | `2A99F5BC1174B73CBB1D620884E01C34E51CCB3978DA125F0E33268883BF4158` | 2033 |

## 5. Entrust (including AffirmTrust): 7 roots

**Why:** 22 compliance incidents between March and May 2024 (EV certificates missing required fields,
slow incident reports, a missed certificate-problem-report deadline, and a large revocation backlog),
on top of commitments from 2020 that Mozilla found Entrust had broken. Mozilla concluded Entrust's
2024 commitments weren't meaningfully different from the ones it broke, and set a distrust-after date
for Entrust's roots, AffirmTrust included, since Entrust had acquired AffirmTrust.

**Evidence:** [Entrust issues list](https://wiki.mozilla.org/CA/Entrust_Issues), Mozilla's decision
thread ["Mozilla's Decision on Entrust's Root CA Certificates used for
TLS"](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/jCvkhBjg9Yw). NSS's
`certdata.txt` (NSS_3_107_RTM and NSS_3_112_RTM) gives all eight Entrust-owned roots
`CKA_NSS_SERVER_DISTRUST_AFTER` 2024-11-30 23:59:59Z; NSS 3.130 still carries it for the three
Entrust-branded roots below, having since removed the four AffirmTrust roots (bug
[2017460](https://bugzilla.mozilla.org/show_bug.cgi?id=2017460)) and the 2006 Entrust root (bug
[2032223](https://bugzilla.mozilla.org/show_bug.cgi?id=2032223)).

| Root | SHA-256 | Expires |
|---|---|---|
| Entrust Root Certification Authority - G2 | `43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339` | 2030 |
| Entrust Root Certification Authority - EC1 | `02ED0EB28C14DA45165C566791700D6451D7FB56F0B2AB1D3B8EB070E56EDFF5` | 2037 |
| Entrust.net Certification Authority (2048) | `6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177` | 2029 |
| AffirmTrust Commercial | `0376AB1D54C5F9803CE4B2E201A0EE7EEF7B57B636E8A93C9B8D4860C96F5FA7` | 2030 |
| AffirmTrust Networking | `0A81EC5A929777F145904AF38D5D509F66B5E2C58FCDB531058B0E17F3F0B41B` | 2030 |
| AffirmTrust Premium | `70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A` | 2040 |
| AffirmTrust Premium ECC | `BD71FDF6DA97E4CF62D1647ADD2581B07D79ADF8397EB4ECBA9C5E8488821423` | 2040 |

NSS labels the third row "Entrust.net Premium 2048 Secure Server CA"; it's the same certificate 10.9
calls "Entrust.net Certification Authority (2048)".

## Considered, not included

- **Expired, so they already can't vouch for anything:** GeoTrust Global CA (Symantec, 2022),
  E-Tugra Certification Authority (2023), and the three TÜRKTRUST roots (2015–2017).
- **Withdrawn, but not for cause:** most of Mozilla's removals of roots 10.9 ships were CAs retiring
  their own roots, ownership transfers, or age. Examples: AOL, TC TrustCenter, the Viking Cloud roots.
  See the removed-root report for all of them.
- **Entrust Root Certification Authority (2006)** (SHA-256
  `73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C`) is left out on purpose. Sectigo,
  which now runs Entrust's public CA business, keeps it for compatibility with older systems until it
  expires on 2026-11-27, and 10.9 doesn't fall back to another path when one is distrusted, so
  distrusting it could break current sites on 10.9.
- **Weak keys or missing audits:** the old 1024-bit VeriSign Class 1–3 roots. Removed for weak
  cryptography, not misbehavior.
- **Email only:** Symantec's Class 1 and 2 roots. A website-only distrust has no effect on them.
- **Not shipped by 10.9:** WoSign, CNNIC, TrustCor, and E-Tugra's newer roots. Nothing to distrust.
