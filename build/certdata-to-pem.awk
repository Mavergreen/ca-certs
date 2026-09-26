# usage: awk -v now=YYYYMMDDhhmmss -f certdata-to-pem.awk certdata.txt
#        Prints "# <label>" and a PEM block for every root Mozilla trusts for server authentication
#        (CKT_NSS_TRUSTED_DELEGATOR), leaving out any whose CKA_NSS_SERVER_DISTRUST_AFTER is at or
#        before `now` (UTC), and naming each one left out on stderr. BWK awk: no intervals, no gawk.
# spec: tests/certdata-to-pem.sh

function octval(s,   v, i) { v = 0; for (i = 1; i <= length(s); i++) v = v * 8 + substr(s, i, 1); return v }

function bytes_of(oct, out,   n, parts, i) {
  n = split(oct, parts, "\\\\")
  for (i = 2; i <= n; i++) out[i - 1] = octval(parts[i])
  return n - 1
}

function b64(by, n,   out, i, a, b, c, t) {
  out = ""
  for (i = 1; i <= n; i += 3) {
    a = by[i]; b = (i + 1 <= n) ? by[i + 1] : 0; c = (i + 2 <= n) ? by[i + 2] : 0
    t = a * 65536 + b * 256 + c
    out = out substr(B64, int(t / 262144) % 64 + 1, 1) substr(B64, int(t / 4096) % 64 + 1, 1)
    out = out ((i + 1 <= n) ? substr(B64, int(t / 64) % 64 + 1, 1) : "=")
    out = out ((i + 2 <= n) ? substr(B64, t % 64 + 1, 1) : "=")
  }
  return out
}

function ascii(oct,   n, i, s, by) {
  n = bytes_of(oct, by); s = ""
  for (i = 1; i <= n; i++) s = s sprintf("%c", by[i])
  return s
}

function stamp(t,   yy) {
  if (length(t) == 13 && t ~ /^[0-9]+Z$/) { yy = substr(t, 1, 2) + 0; return ((yy < 50) ? "20" : "19") substr(t, 1, 12) }
  if (length(t) == 15 && t ~ /^[0-9]+Z$/) return substr(t, 1, 14)
  return ""
}

BEGIN {
  B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  if (length(now) != 14 || now !~ /^[0-9]+$/) {
    print "certdata-to-pem: pass -v now=YYYYMMDDhhmmss (UTC)" > "/dev/stderr"
    usage_error = 1
    exit 2
  }
  ncert = 0
}

/^CKA_CLASS / { cls = $3; tiss = ""; tser = ""; if (cls == "CKO_CERTIFICATE") ncert++; next }

/^CKA_LABEL UTF8 / {
  lab = $0; sub(/^CKA_LABEL UTF8 "/, "", lab); sub(/"$/, "", lab)
  if (cls == "CKO_CERTIFICATE") certlabel[ncert] = lab
  next
}

/ MULTILINE_OCTAL$/ {
  attr = $1; buf = ""
  while ((getline line) > 0 && line != "END") buf = buf line
  if (cls == "CKO_CERTIFICATE") {
    if (attr == "CKA_VALUE") certval[ncert] = buf
    else if (attr == "CKA_ISSUER") certiss[ncert] = buf
    else if (attr == "CKA_SERIAL_NUMBER") certser[ncert] = buf
    else if (attr == "CKA_NSS_SERVER_DISTRUST_AFTER") certdta[ncert] = ascii(buf)
  } else if (cls == "CKO_NSS_TRUST") {
    if (attr == "CKA_ISSUER") tiss = buf
    else if (attr == "CKA_SERIAL_NUMBER") tser = buf
  }
  next
}

/^CKA_TRUST_SERVER_AUTH / && cls == "CKO_NSS_TRUST" { trust[tiss SUBSEP tser] = $3; next }

END {
  if (usage_error) exit 2
  for (c = 1; c <= ncert; c++) {
    t = trust[certiss[c] SUBSEP certser[c]]
    if (t == "") { printf "certdata-to-pem: no trust object for \"%s\"\n", certlabel[c] > "/dev/stderr"; failed = 1; continue }
    if (t != "CKT_NSS_TRUSTED_DELEGATOR") continue
    if (certdta[c] != "") {
      s = stamp(certdta[c])
      if (s == "") { printf "certdata-to-pem: \"%s\" has an unreadable distrust-after date\n", certlabel[c] > "/dev/stderr"; failed = 1; continue }
      if (s <= now "") { printf "certdata-to-pem: left out \"%s\": its server distrust-after date %s has passed\n", certlabel[c], s > "/dev/stderr"; continue }
    }
    n = bytes_of(certval[c], by)
    s = b64(by, n)
    printf "# %s\n-----BEGIN CERTIFICATE-----\n", certlabel[c]
    for (i = 1; i <= length(s); i += 64) print substr(s, i, 64)
    print "-----END CERTIFICATE-----"
    emitted++
  }
  if (!emitted && !failed) { print "certdata-to-pem: no website roots found" > "/dev/stderr"; failed = 1 }
  if (failed) exit 1
}
