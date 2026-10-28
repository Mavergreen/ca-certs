# platform: host-agnostic -- CI-only: python3, standard library only; the 10.9 build reads the committed output
#   usage: onecrl.py --onecrl FILE --ccadb FILE [--ccadb FILE] --now YYYY-MM-DD --repo DIR [--allow-mass-removal]
#          Matches each CCADB intermediate to OneCRL by issuer DER plus serial, or by subject DER plus
#          the SHA-256 of its SubjectPublicKeyInfo; keeps those CCADB says expire after --now; and
#          rewrites DIR/blocked.md, DIR/blocked/SHA256.pem and DIR/blocked.entries. A CCADB row whose
#          certificate it cannot read is counted and named in blocked.md's gap section. A guard or
#          input error exits 1, naming it, having written nothing.
# spec: tests/onecrl.sh, docs/TRUST-POLICY.md #14
import argparse, base64, csv, datetime, hashlib, json, os, re, sys

MIN_RECORDS = 1000
MAX_REMOVAL = 0.10
COLUMNS = ('Certificate Subject Common Name', 'Certificate Subject Organization',
           'Certificate Issuer Common Name', 'Certificate Issuer Organization', 'SHA-256 Fingerprint',
           'Valid To [GMT]', 'PEM Info')
PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', re.S)
ONECRL_RECORDS = 'https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records'
ENTRIES_FORMAT = '# SHA256 SHA1 ISSUER_DER_BASE64 SERIAL_CONTENT_BASE64, one per blocked.md row, sorted by SHA-256'


class Refusal(Exception):
    pass


def b64(b):
    return base64.b64encode(b).decode()


def tlv(b, i):  # -> (tag, content_start, end)
    t, l, j = b[i], b[i + 1], i + 2
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[j:j + n], 'big')
        j += n
    return t, j, j + l


def tbs_fields(der):
    """serial content, issuer TLV, subject TLV and SPKI TLV of a DER certificate."""
    _, s, _ = tlv(der, 0)
    _, i, end = tlv(der, s)
    out = []
    while i < end:
        t, cs, ce = tlv(der, i)
        out.append((t, der[i:ce], der[cs:ce]))
        i = ce
    if out[0][0] == 0xa0:
        out = out[1:]
    serial, _sig, issuer, _validity, subject, spki = out[:6]
    return {'serial': serial[2], 'issuer': issuer[1], 'subject': subject[1], 'spki': spki[1]}


def common_name(name_der):
    """The last CN in a DER Name, or ''."""
    _, i, end = tlv(name_der, 0)
    cn = ''
    while i < end:
        _, si, se = tlv(name_der, i)  # SET of AttributeTypeAndValue
        while si < se:
            _, ai, ae = tlv(name_der, si)
            _, oi, oe = tlv(name_der, ai)
            if name_der[oi:oe] == b'\x55\x04\x03':
                _, vi, ve = tlv(name_der, oe)
                cn = name_der[vi:ve].decode('utf-8', 'replace')
            si = ae
        i = se
    return cn


def pem_der(text):
    """(PEM, DER) of the first certificate in text; (None, None) when there is none or it does not decode."""
    m = PEM_RE.search(text or '')
    if not m:
        return None, None
    try:
        return m.group(0) + '\n', base64.b64decode(''.join(m.group(1).split()), validate=True)
    except ValueError:
        return None, None


def entry_line(der):
    f = tbs_fields(der)
    return '%s %s %s %s' % (hashlib.sha256(der).hexdigest().upper(), hashlib.sha1(der).hexdigest().upper(),
                            b64(f['issuer']), b64(f['serial']))


def entries_text(header, ders):
    return '\n'.join(header + [ENTRIES_FORMAT] + sorted(entry_line(d) for d in ders)) + '\n'


def details(record):
    d = record.get('details')
    return d if isinstance(d, dict) else {}


def bug_number(record):
    m = re.search(r'(\d+)\s*$', str(details(record).get('bug') or ''))
    return int(m.group(1)) if m else None


def citation(records):
    """A link to the bug behind the first record, by id, that cites one; else to the first record."""
    records = sorted(records, key=lambda r: str(r.get('id', '')))
    for r in records:
        n = bug_number(r)
        if n is not None:
            return '[%d](https://bugzilla.mozilla.org/show_bug.cgi?id=%d)' % (n, n)
    return '[OneCRL](%s/%s)' % (ONECRL_RECORDS, records[0].get('id', ''))


def cell(s):
    return ' '.join(s.replace('|', '/').split())


def load_onecrl(path):
    try:
        with open(path, encoding='utf-8') as f:
            records = json.load(f)['data']
        if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise Refusal('%s: OneCRL download is empty or does not parse' % path)
    if len(records) < MIN_RECORDS:
        raise Refusal('%s: OneCRL has %d records, fewer than %d' % (path, len(records), MIN_RECORDS))
    return records


def load_ccadb(path):
    csv.field_size_limit(sys.maxsize)
    try:
        with open(path, encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            if not header:
                raise Refusal('%s: CCADB download is empty' % path)
            missing = [c for c in COLUMNS if c not in header]
            if missing:
                raise Refusal('%s: CCADB report lacks expected columns: %s' % (path, ', '.join(missing)))
            rows = list(reader)
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        raise Refusal('%s: CCADB download does not parse: %s' % (path, e))
    if not rows:
        raise Refusal('%s: CCADB download is empty' % path)
    return rows


def generate(onecrl_path, ccadb_paths, now, repo, allow_mass_removal):
    records = load_onecrl(onecrl_path)
    reports = [load_ccadb(p) for p in ccadb_paths]
    by_key = {}
    # spec: no filtering of our own -- Firefox's updateCertBlocklist (RemoteSecuritySettings.sys.mjs)
    #       enforces every record and never reads `enabled`, so neither does this
    for r in records:
        if 'issuerName' in r and 'serialNumber' in r:
            by_key.setdefault(('serial', r['issuerName'], r['serialNumber']), []).append(r)
        if 'subject' in r and 'pubKeyHash' in r:
            by_key.setdefault(('key', r['subject'], r['pubKeyHash']), []).append(r)

    matched_ids, kept, unreadable = set(), {}, {}
    for rows in reports:
        for row in rows:
            pem, der = pem_der(row['PEM Info'])
            try:
                f = tbs_fields(der) if der is not None else None
            except (IndexError, ValueError):
                f = None
            if f is None:
                # spec: a certificate this cannot read might be one OneCRL blocks, so it is named, not skipped
                unreadable[cell(row['SHA-256 Fingerprint'] or '')] = cell(
                    row['Certificate Subject Common Name'] or row['Certificate Subject Organization'] or '')
                continue
            hits = (by_key.get(('serial', b64(f['issuer']), b64(f['serial'])), [])
                    + by_key.get(('key', b64(f['subject']), b64(hashlib.sha256(f['spki']).digest())), []))
            if not hits:
                continue
            matched_ids.update(id(r) for r in hits)
            try:
                until = datetime.datetime.strptime((row['Valid To [GMT]'] or '').strip(), '%Y %b %d').date()
            except ValueError:
                raise Refusal('CCADB row %s has a Valid To I cannot read: %r'
                              % (row['SHA-256 Fingerprint'], row['Valid To [GMT]']))
            if until <= now:
                continue
            sha256 = hashlib.sha256(der).hexdigest().upper()
            if sha256 in kept:
                kept[sha256]['hits'] += hits
                continue
            kept[sha256] = {'pem': pem, 'der': der, 'until': until, 'hits': hits,
                            'name': '%s, signed by %s' % (
                                cell(row['Certificate Subject Common Name'] or row['Certificate Subject Organization'] or ''),
                                cell(row['Certificate Issuer Common Name'] or row['Certificate Issuer Organization'] or ''))}

    blocked_dir = os.path.join(repo, 'blocked')
    current = sorted(n[:-4] for n in os.listdir(blocked_dir) if n.endswith('.pem')) if os.path.isdir(blocked_dir) else []
    stale = [s for s in current if s not in kept]
    if current and len(stale) > MAX_REMOVAL * len(current) and not allow_mass_removal:
        raise Refusal('mass removal: this run would remove %d of the %d certificates in blocked/; '
                      'rerun with --allow-mass-removal if that is real' % (len(stale), len(current)))

    snapshot = max((r.get('last_modified', 0) for r in records), default=0)
    snapshot = datetime.datetime.fromtimestamp(snapshot / 1000, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    stamp = 'Generated by `build/onecrl.sh` on %s from CCADB and from OneCRL as last modified %s.' % (now, snapshot)

    unmatched = [r for r in records if id(r) not in matched_ids]
    since = now - datetime.timedelta(days=365)
    recent = []
    for r in unmatched:
        created = str(details(r).get('created') or '')
        try:
            day = datetime.date.fromisoformat(created[:10])
        except ValueError:
            continue
        if since <= day <= now:
            recent.append((created[:10], str(r.get('id', '')), citation([r]), cell(gap_name(r))))
    recent.sort()

    md = ['# Blocked intermediates', '',
          '%s Do not edit it by hand: the next run overwrites it.' % stamp, '',
          'The intermediate certificates this product distrusts for secure websites (TLS), because Mozilla',
          'blocks them in OneCRL, its list of intermediates Firefox refuses. Why: '
          '[`docs/TRUST-POLICY.md`](docs/TRUST-POLICY.md) #14.', '',
          '**%d certificates.** Each matches a OneCRL entry by its issuer and serial number, or by its' % len(kept),
          'subject and key, and expires after %s. The Bug column cites the Mozilla bug behind that entry,' % now,
          'or the entry itself when it cites no bug.', '',
          '| Intermediate | SHA-256 | Bug | Expires |', '|---|---|---|---|']
    for sha256, c in sorted(kept.items(), key=lambda kv: (kv[1]['name'], kv[0])):
        md.append('| %s | `%s` | %s | %d |' % (c['name'], sha256, citation(c['hits']), c['until'].year))
    md += ['', '## Not matched', '',
           '**%d OneCRL records** name no certificate in CCADB, so this list cannot include them. Most' % len(unmatched),
           'are long-expired certificates CCADB has dropped. Those Mozilla added in the 365 days before %s:' % now, '']
    if recent:
        md += ['| Bug | Name | Added |', '|---|---|---|']
        md += ['| %s | %s | %s |' % (cite, name, day) for day, _id, cite, name in recent]
    else:
        md.append('None.')
    md += ['', '**%d CCADB rows** carry no certificate the generator can read (no PEM, or one that does not parse), so it' % len(unreadable),
           'can\'t tell whether OneCRL blocks them.']
    if unreadable:
        md += ['', '| SHA-256 | Subject |', '|---|---|']
        md += ['| `%s` | %s |' % (sha256, name) for sha256, name in sorted(unreadable.items())]

    write_all(repo, kept, stale, '\n'.join(md) + '\n',
              entries_text(['# ' + stamp + ' Do not edit it by hand.'], [c['der'] for c in kept.values()]))


def gap_name(record):
    name = details(record).get('name') or ''
    if name:
        return name
    try:
        if 'subject' in record:
            return common_name(base64.b64decode(record['subject']))
        return 'serial %s from %s' % (base64.b64decode(record['serialNumber']).hex(),
                                      common_name(base64.b64decode(record['issuerName'])))
    except (KeyError, IndexError, ValueError):
        return ''


def replace(path, text):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    os.replace(tmp, path)


def write_all(repo, kept, stale, md, entries):
    blocked_dir = os.path.join(repo, 'blocked')
    os.makedirs(blocked_dir, exist_ok=True)
    for sha256, c in kept.items():
        replace(os.path.join(blocked_dir, sha256 + '.pem'), c['pem'])
    for s in stale:
        os.remove(os.path.join(blocked_dir, s + '.pem'))
    replace(os.path.join(repo, 'blocked.entries'), entries)
    replace(os.path.join(repo, 'blocked.md'), md)


def main():
    p = argparse.ArgumentParser(prog='onecrl.py')
    p.add_argument('--onecrl', required=True)
    p.add_argument('--ccadb', action='append', required=True)
    p.add_argument('--now', type=datetime.date.fromisoformat, required=True)
    p.add_argument('--repo', required=True)
    p.add_argument('--allow-mass-removal', action='store_true')
    a = p.parse_args()
    try:
        generate(a.onecrl, a.ccadb, a.now, a.repo, a.allow_mass_removal)
    except Refusal as e:
        print('onecrl: %s' % e, file=sys.stderr)
        return 1
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
        # spec: an input shaped unlike any seen is named, not a traceback; nothing has been written yet
        print('onecrl: the input is not shaped as expected (%s: %s); nothing written' % (type(e).__name__, e), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
