#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_thuat_toan.py  —  Crypto-scheme reconnaissance for client-side JS bundles.

Given a URL or a local .js file, it scans for the crypto library, algorithm,
padding, AES mode, and — importantly — the KEY-GENERATION RULE (static hard-coded
public key vs ephemeral per-session keypair), extracts and decodes any RSA public
keys, and prints a ready-to-paste "crypto profile" for the Burp extension template.

Usage:
    python find_thuat_toan.py https://target/assets/index-XXXX.js
    python find_thuat_toan.py ./bundle.js
    python find_thuat_toan.py https://target/            --crawl      # pull <script src> from HTML
    python find_thuat_toan.py ./bundle.js --json profile.json --context 160

Pure stdlib (urllib/re/base64). Authorized testing only.
"""
import argparse, base64, json, re, ssl, sys
import urllib.request
from urllib.parse import urljoin

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0"}
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE


# ----------------------------------------------------------------- loading

def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40, context=_CTX).read().decode("utf-8", "replace")

def load(target, crawl):
    if re.match(r"^https?://", target):
        body = fetch(target)
        if crawl and ("<html" in body.lower() or "<script" in body.lower()):
            srcs = re.findall(r'(?:src|href)="([^"]+\.js)"', body)
            srcs = list(dict.fromkeys(srcs))
            chunks, where = [], []
            for s in srcs[:40]:
                u = s if s.startswith("http") else urljoin(target, s)
                try:
                    chunks.append(fetch(u)); where.append(u)
                except Exception as e:
                    print(f"  [warn] could not fetch {u}: {e}", file=sys.stderr)
            return "\n".join(chunks), where or [target]
        return body, [target]
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        return f.read(), [target]


# --------------------------------------------------------------- detectors

LIBS = {
    "jsencrypt (RSA, PKCS#1 v1.5 default)": r"JSEncrypt|JSEncryptRSAKey",
    "node-forge (RSA PKCS1/OAEP, AES, ...)": r"\bforge\.(?:pki|util|md|cipher)\b|node-forge",
    "Web Crypto API (crypto.subtle)": r"crypto\.subtle",
    "CryptoJS": r"\bCryptoJS\b",
    "TweetNaCl / libsodium": r"\bnacl\b|libsodium|sodium\.crypto_",
    # catches minified jsencrypt/forge where the brand name is renamed away
    "RSA via setPublicKey / PEM (jsencrypt/forge-style)": r"setPublicKey\(|publicKeyFromPem|-----BEGIN (?:RSA )?PUBLIC KEY-----",
}

PADDINGS = {
    "RSA-OAEP": r'["\']RSA-?OAEP["\']|RSAES-?OAEP|OAEPWith|OAEPPadding',
    "RSA PKCS#1 v1.5": r'RSAES-PKCS1-V1_5|PKCS1Padding|["\']RSASSA-PKCS1',
    "OAEP MGF1 hash hint": r'mgf1\s*[:=]\s*\{?\s*md\s*:\s*\w+\.(sha1|sha256|sha384|sha512)|MGF1ParameterSpec',
    "OAEP/sign hash hint": r'md\s*:\s*\w+\.(sha1|sha256|sha384|sha512)\.create|hash\s*:\s*["\']SHA-?(1|256|384|512)["\']',
}

AES = {
    "AES-GCM": r'["\']AES-?GCM["\']|GCMParameterSpec|tagLength',
    "AES-CBC": r'["\']AES-?CBC["\']|CBC/PKCS|createCipheriv\(\s*["\']aes-\d+-cbc',
    "AES-CTR/ECB/OFB": r'["\']AES-?(CTR|ECB|OFB)["\']',
    "IV length hint": r'new\s+Uint8Array\(\s*(\d{1,2})\s*\)|iv\s*[:=].{0,40}?(12|16)\b',
}

KEYGEN_EPHEMERAL = r'generateKeyPair|subtle\.generateKey|rsa\.generateKeyPair|KeyPairGenerator'
KEYGEN_STATIC    = r'setPublicKey\(|publicKeyFromPem\(|setRsaPublicKey|importKey\('

# identifiers that typically name exchanged key / session-key fields
FIELD_HINTS = r'\b([A-Za-z_]\w*(?:[Pp]ub(?:lic)?[Kk]ey|[Pp]b[Kk]ey|[Ss]ym[Kk]ey|[Pp]riv(?:ate)?[Kk]ey|[Aa]uth[Tt]oken))\b'
PWD_HINTS   = r'\b(password|passwd|pwd|txtPass|userPass|loginPwd)\b'
ENDPOINT_HINTS = r'\b(trcode)\s*[:=]\s*["\']([A-Z]{1,4}\d{3,6})["\']|["\'](/[a-zA-Z0-9_\-/]{2,60})["\']'


def snippets(text, pattern, ctx, limit=4, flags=re.I):
    out = []
    for m in re.finditer(pattern, text, flags):
        i = m.start()
        seg = text[max(0, i - ctx // 3): i + ctx].replace("\n", " ")
        out.append({"pos": i, "match": m.group(0)[:60], "snippet": seg})
        if len(out) >= limit:
            break
    return out


# -------------------------------------------------------- RSA key handling

def _der_len(b, i):
    l = b[i]; i += 1
    if l & 0x80:
        n = l & 0x7F; l = int.from_bytes(b[i:i + n], "big"); i += n
    return l, i

def decode_spki(der):
    """Return (bits, exponent) from an RSA SubjectPublicKeyInfo DER, or None."""
    try:
        assert der[0] == 0x30
        _, i = _der_len(der, 1)
        assert der[i] == 0x30                      # AlgorithmIdentifier
        alen, j = _der_len(der, i + 1); i = j + alen
        assert der[i] == 0x03                      # BIT STRING
        _, j = _der_len(der, i + 1); i = j + 1     # skip unused-bits byte
        assert der[i] == 0x30                      # RSAPublicKey SEQUENCE
        _, i = _der_len(der, i + 1)
        assert der[i] == 0x02                      # modulus INTEGER
        mlen, i = _der_len(der, i + 1)
        mod = der[i:i + mlen]; i += mlen
        assert der[i] == 0x02                      # exponent INTEGER
        elen, i = _der_len(der, i + 1)
        exp = der[i:i + elen]
        n = int.from_bytes(mod.lstrip(b"\x00"), "big")
        e = int.from_bytes(exp, "big")
        return n.bit_length(), e
    except Exception:
        return None

def find_public_keys(text):
    keys = []
    seen = set()
    # PEM blocks
    for m in re.finditer(r"-----BEGIN (?:RSA )?PUBLIC KEY-----([A-Za-z0-9+/=\s\\n]+?)-----END (?:RSA )?PUBLIC KEY-----", text):
        raw = re.sub(r"[^A-Za-z0-9+/=]", "", m.group(1))
        _add_key(keys, seen, raw, "PEM block", m.start())
    # bare base64 SPKI literals (validated by actually decoding the DER below)
    for m in re.finditer(r'["\'`](M(?:II|Fw|IG|Eg)[A-Za-z0-9+/]{70,2000}={0,2})["\'`]', text):
        raw = m.group(1).replace("\\n", "").replace("\\r", "")
        _add_key(keys, seen, raw, "base64 literal", m.start())
    return keys

def _add_key(keys, seen, b64, source, pos):
    if b64 in seen:
        return
    try:
        der = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        return
    info = decode_spki(der)
    if not info:
        return
    bits, e = info
    # sanity filter to avoid decoding random base64 blobs as "keys"
    if bits not in (512, 768, 1024, 2048, 3072, 4096) or e not in (3, 5, 17, 257, 65537):
        return
    seen.add(b64)
    keys.append({
        "source": source, "pos": pos, "bits": bits, "exponent": e,
        "weak": bits <= 1024, "preview": b64[:46] + "...", "b64": b64,
    })


# --------------------------------------------------------------- inference

def infer(text, libs, aes_hits, ephemeral, static, keys, pwd, fields):
    reasons = []
    hybrid = bool(aes_hits and (ephemeral or any("SymKey" in f or "SymKey".lower() in f.lower() for f in fields)))
    if hybrid:
        reasons.append("AES payload cipher + key-exchange/ephemeral keypair present")
        scheme = "HYBRID_RSA_AES"
    elif keys and static and not aes_hits:
        reasons.append("hard-coded RSA public key + direct encrypt, no AES payload layer")
        scheme = "DIRECT_RSA"
    elif pwd and keys:
        reasons.append("password field + RSA public key, no AES")
        scheme = "DIRECT_RSA"
    else:
        reasons.append("insufficient signal — review manually")
        scheme = "REVIEW"

    keygen = "EPHEMERAL (generated per session, exchanged)" if ephemeral else \
             ("STATIC (hard-coded public key)" if (static or keys) else "UNKNOWN")
    return scheme, keygen, reasons


# ----------------------------------------------------------------- report

def main():
    ap = argparse.ArgumentParser(description="Detect client-side crypto scheme + key-gen rule.")
    ap.add_argument("target", help="URL to a .js (or page with --crawl), or a local .js file")
    ap.add_argument("--crawl", action="store_true", help="treat URL as HTML and fetch its <script src> bundles")
    ap.add_argument("--context", type=int, default=140, help="chars of context per evidence snippet")
    ap.add_argument("--json", metavar="FILE", help="also write the profile as JSON")
    a = ap.parse_args()

    text, where = load(a.target, a.crawl)
    print("=" * 72)
    print("find_thuat_toan — crypto recon")
    print("source :", ", ".join(where))
    print("size   :", len(text), "chars")
    print("=" * 72)

    libs = [name for name, pat in LIBS.items() if re.search(pat, text, re.I)]
    print("\n[1] Libraries")
    print("    " + ("\n    ".join(libs) if libs else "(none of the known libraries matched)"))

    print("\n[2] RSA padding")
    pad_hits = {k: snippets(text, v, a.context, 2) for k, v in PADDINGS.items() if re.search(v, text, re.I)}
    for k, ev in pad_hits.items():
        print(f"    - {k}")
        for e in ev[:1]:
            print(f"        ~ {e['snippet'][:a.context]}")
    if not pad_hits:
        print("    (no explicit padding markers)")

    print("\n[3] AES mode")
    aes_hits = {k: snippets(text, v, a.context, 2) for k, v in AES.items() if re.search(v, text, re.I)}
    for k in aes_hits:
        print("    -", k)
    if not aes_hits:
        print("    (no AES markers — likely direct RSA)")

    print("\n[4] Key generation rule")
    ephemeral = bool(re.search(KEYGEN_EPHEMERAL, text))
    static = bool(re.search(KEYGEN_STATIC, text))
    for label, pat, flag in [("EPHEMERAL", KEYGEN_EPHEMERAL, ephemeral), ("STATIC", KEYGEN_STATIC, static)]:
        if flag:
            print(f"    - {label}:")
            for e in snippets(text, pat, a.context, 2):
                print(f"        ~ {e['snippet'][:a.context]}")

    print("\n[5] RSA public keys found")
    keys = find_public_keys(text)
    if not keys:
        print("    (none decoded — key may be ephemeral, PEM-split, or obfuscated)")
    for k in keys:
        warn = "  <-- WEAK (factorable / upgrade)" if k["weak"] else ""
        print(f"    - {k['bits']}-bit  e={k['exponent']}  [{k['source']}]  {k['preview']}{warn}")

    print("\n[6] Field / endpoint hints")
    fields = sorted(set(re.findall(FIELD_HINTS, text)))[:20]
    pwd = sorted(set(re.findall(PWD_HINTS, text, re.I)))[:10]
    trcodes = sorted(set(m[1] for m in re.findall(ENDPOINT_HINTS, text) if m[1]))[:15]
    print("    key/token fields :", ", ".join(fields) or "(none)")
    print("    password fields  :", ", ".join(pwd) or "(none)")
    print("    txn codes        :", ", ".join(trcodes) or "(none)")

    scheme, keygen, reasons = infer(text, libs, aes_hits, ephemeral, static, keys, pwd, fields)

    print("\n" + "=" * 72)
    print("[=] VERDICT")
    print("    Scheme    :", scheme)
    print("    Key-gen   :", keygen)
    print("    Reasoning :", "; ".join(reasons))
    print("=" * 72)

    # Suggested template Config profile
    oaep_hash = "SHA-256" if re.search(r'SHA-?256', text) else "SHA-1"
    mgf1_hash = "SHA-1" if re.search(r'mgf1.{0,30}sha1|MGF1ParameterSpec\.SHA1', text, re.I) else oaep_hash
    rsa_padding = "OAEP" if "OAEP" in " ".join(pad_hits.keys()).upper() else "PKCS1"
    aes_mode = "GCM" if "AES-GCM" in aes_hits else ("CBC" if "AES-CBC" in aes_hits else "none")

    print("\n[>] Suggested template Config (docs/06). Verify by reading the call sites!\n")
    print(f"    SCHEME          = {scheme}")
    print(f"    RSA_PADDING     = {rsa_padding}")
    if rsa_padding == "OAEP":
        print(f"    OAEP_HASH       = {oaep_hash}")
        print(f"    OAEP_MGF1_HASH  = {mgf1_hash}")
    print(f"    AES mode        = {aes_mode}  (GCM: iv=12, tag=128)")
    if keys:
        kk = min(keys, key=lambda x: x["bits"])
        print(f"    key size        = {kk['bits']}-bit" + ("  (WEAK — consider factoring, docs/03)" if kk["weak"] else ""))
    print(f"    field hints     = {', '.join(fields[:6]) or '(inspect manually)'}")

    if keys:
        print("\n[>] Match & Replace (swap the found key — see docs/05). Escape '+' as '\\+' in regex mode:")
        for k in keys[:2]:
            print(f"    Match : {re.sub(r'[+]', r'\\+', k['b64'])}")
            print(f"    Replace: <YOUR SPKI base64 here>")

    print("\nNext: docs/02 (confirm algo) -> docs/03 (key-gen) -> docs/04 (pipeline) -> template/\n")

    if a.json:
        profile = {
            "source": where, "scheme": scheme, "keygen": keygen, "reasons": reasons,
            "libraries": libs, "rsa_padding": rsa_padding,
            "oaep_hash": oaep_hash if rsa_padding == "OAEP" else None,
            "oaep_mgf1_hash": mgf1_hash if rsa_padding == "OAEP" else None,
            "aes_mode": aes_mode,
            "public_keys": [{k2: v2 for k2, v2 in k.items() if k2 != "b64"} for k in keys],
            "field_hints": fields, "password_fields": pwd, "txn_codes": trcodes,
        }
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON profile written to {a.json}")


if __name__ == "__main__":
    main()
