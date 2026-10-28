# Blocked intermediates

The intermediate certificates this product distrusts for secure websites (TLS), because Mozilla
blocks them in OneCRL, its list of intermediates Firefox refuses. Why: [`docs/TRUST-POLICY.md`](docs/TRUST-POLICY.md) #14.

**12 certificates from 1 incident.** Copied by hand from OneCRL on 2026-10-27, until ca-certs reads
OneCRL itself. OneCRL names each one by its subject and key, or by its issuer and serial number;
each row below is a certificate published for one of those entries.

**To add one:** open a pull request that adds a row, with its SHA-256 fingerprint and the Mozilla bug
behind its OneCRL entry.

## 1. eMudhra: 6 intermediates, 12 certificates

**Why:** the private keys of these eMudhra intermediates could be recovered from their public
certificates. Mozilla blocked them in OneCRL on 2026-10-17 and 2026-10-21. Each was issued twice:
by eMudhra's own "emSign Root TLS CA - G3", and by Sectigo's "AAA Certificate Services", which 10.9
trusts. Sectigo revoked its cross-signatures on 2026-10-19, but 10.9 doesn't reliably check
revocation.

**Evidence:** bug [2083382](https://bugzilla.mozilla.org/show_bug.cgi?id=2083382),
[Sectigo's advisory](https://www.sectigo.com/resource-library/advisory-on-compromised-emudhra-intermediate-certificates).

| Intermediate | SHA-256 | Expires |
|---|---|---|
| EM DV TLS CA - G3B, signed by AAA Certificate Services | `45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE` | 2028 |
| EM DV TLS CA - G3B, signed by emSign Root TLS CA - G3 | `42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493` | 2040 |
| EM DV TLS CA - G3C, signed by AAA Certificate Services | `62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72` | 2028 |
| EM DV TLS CA - G3C, signed by emSign Root TLS CA - G3 | `0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19` | 2040 |
| EM EV TLS CA - G3B, signed by AAA Certificate Services | `579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512` | 2028 |
| EM EV TLS CA - G3B, signed by emSign Root TLS CA - G3 | `E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838` | 2040 |
| EM EV TLS CA - G3C, signed by AAA Certificate Services | `FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F` | 2028 |
| EM EV TLS CA - G3C, signed by emSign Root TLS CA - G3 | `432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3` | 2040 |
| EM OV TLS CA - G3B, signed by AAA Certificate Services | `5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699` | 2028 |
| EM OV TLS CA - G3B, signed by emSign Root TLS CA - G3 | `98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B` | 2040 |
| EM OV TLS CA - G3C, signed by AAA Certificate Services | `7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489` | 2028 |
| EM OV TLS CA - G3C, signed by emSign Root TLS CA - G3 | `CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F` | 2040 |
