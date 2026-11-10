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

# Full browser-like headers — some servers (Next.js/Turbopack dev, WAFs) 404 requests
# that lack Accept / Sec-Fetch-* / Referer. Referer+Origin are filled per-request.
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",          # skip gzip so we don't need to decompress
    "Sec-Fetch-Dest": "script",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-origin",
    "Connection": "keep-alive",
}
EXTRA_HEADERS = {}   # populated from --header / --cookie
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

def _origin(url):
    m = re.match(r"^(https?://[^/]+)", url)
    return m.group(1) if m else url


# ----------------------------------------------------------------- loading

class FetchError(Exception):
    pass

def fetch(url):
    headers = dict(BASE_HEADERS)
    headers["Referer"] = _origin(url) + "/"
    headers["Origin"] = _origin(url)
    headers.update(EXTRA_HEADERS)
    try:
        return urllib.request.urlopen(
            urllib.request.Request(url, headers=headers), timeout=40, context=_CTX
        ).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise FetchError(f"cannot reach host ({e.reason})")
    except Exception as e:  # timeout, ssl, decode, ...
        raise FetchError(str(e))

def _script_urls(html, base):
    """Collect candidate .js URLs from an HTML page (handles Next.js/_next chunks)."""
    found = re.findall(r'(?:src|href)="([^"]+\.js)"', html)
    found += re.findall(r'"(/_next/static/[^"]+\.js)"', html)       # Next.js chunk refs
    found += re.findall(r'["\'`](https?://[^"\'`]+\.js)["\'`]', html)
    urls, seen = [], set()
    for s in found:
        u = s if s.startswith("http") else urljoin(base, s)
        if u not in seen:
            seen.add(u); urls.append(u)
    return urls

def load(target, crawl):
    if re.match(r"^https?://", target):
        body = fetch(target)
        looks_html = re.match(r"\s*(?:<!doctype html|<html[\s>])", body, re.I) is not None
        if crawl and looks_html:
            urls = _script_urls(body, target)
            if not urls:
                raise FetchError("page has no <script src=...> / _next chunks to crawl")
            chunks, where = [], []
            for u in urls[:60]:
                try:
                    chunks.append(fetch(u)); where.append(u)
                except FetchError as e:
                    print(f"  [warn] skip {u}: {e}", file=sys.stderr)
            if not chunks:
                raise FetchError("found script URLs but none could be fetched")
            return "\n".join(chunks), where
        if crawl and not looks_html:
            print("  [info] --crawl given but target is already a script; scanning it directly.", file=sys.stderr)
        # A .js URL that returns a tiny body (or an HTML doc) usually means the chunk
        # hash changed (redeploy) and the server served an error / SPA fallback with 200.
        if target.lower().split("?")[0].endswith(".js") and (looks_html or len(body) < 2000):
            print(f"  [warn] '{target}' returned "
                  + ("an HTML page" if looks_html else f"only {len(body)} chars")
                  + " — likely a stale/renamed chunk or error page. "
                    "Re-point at the app root with --crawl, or copy the current .js URL from DevTools.",
                  file=sys.stderr)
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
    "CryptoJS AES (default CBC)": r'CryptoJS\.AES\.(?:en|de)crypt|CryptoJS\.mode\.',
    "IV length hint": r'new\s+Uint8Array\(\s*(\d{1,2})\s*\)|iv\s*[:=].{0,40}?(12|16)\b',
}

KEYGEN_EPHEMERAL = r'generateKeyPair|subtle\.generateKey|rsa\.generateKeyPair|KeyPairGenerator'
# importKey only counts as RSA-static when it imports an "spki" key (not raw AES/PBKDF2 keys)
KEYGEN_STATIC    = r'setPublicKey\(|publicKeyFromPem\(|setRsaPublicKey|importKey\(\s*["\']spki["\']'

# node-forge / jsencrypt internal API + type names — library noise, NOT app data fields.
# Case-sensitive on purpose: excludes forge's "RSAPublicKey" but keeps an app's "rsaPublicKey".
LIB_NOISE = frozenset({
    "DSAPrivateKey", "ECPrivateKey", "EncryptedPrivateKey", "RSAPrivateKey", "RSAPublicKey",
    "subjectPrivateKey", "subjectPublicKey", "ed25519PublicKey", "recoverPubKey",
    "publicKeyToRSAPublicKey", "privateKeyToRSAPrivateKey", "encryptRsaPrivateKey",
    "decryptRsaPrivateKey", "publicKeyFromPrivateKey", "getPrivateKey", "getPublicKey",
    "setPrivateKey", "setPublicKey", "exportRSAPublicKey", "generateRSAKeyPair",
    "publicKeyFromPem", "privateKeyFromPem", "setRsaPublicKey", "setRsaPrivateKey",
})

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
    rsa_direct = any(("setPublicKey" in l) or ("jsencrypt" in l.lower()) for l in libs)
    hybrid = bool(aes_hits and (ephemeral or any("symkey" in f.lower() for f in fields)))

    if hybrid:
        reasons.append("AES payload cipher + key-exchange/ephemeral keypair present")
        scheme = "DIRECT_RSA" if False else "HYBRID_RSA_AES"
    elif (keys or rsa_direct) and pwd and not aes_hits:
        reasons.append("RSA encrypt (setPublicKey/.encrypt) on a password field, no AES payload")
        scheme = "DIRECT_RSA"
    elif keys and static:
        reasons.append("hard-coded RSA public key + direct encrypt")
        scheme = "DIRECT_RSA"
    elif pwd and keys:
        reasons.append("password field + RSA public key")
        scheme = "DIRECT_RSA"
    else:
        reasons.append("insufficient / ambiguous signal — review manually")
        scheme = "REVIEW"

    # DIRECT_RSA with no decodable key => the public key is supplied at runtime.
    dynamic_key = (scheme == "DIRECT_RSA" and not keys)
    if dynamic_key:
        reasons.append("public key not hard-coded here -> DYNAMIC (fetched/other chunk)")

    keygen = "EPHEMERAL (generated per session, exchanged)" if ephemeral else \
             ("STATIC (hard-coded public key)" if keys else
              ("DYNAMIC (public key supplied at runtime)" if dynamic_key else "UNKNOWN"))
    return scheme, keygen, reasons, dynamic_key


# ----------------------------------------------------------------- report

def main():
    ap = argparse.ArgumentParser(description="Detect client-side crypto scheme + key-gen rule.")
    ap.add_argument("target", help="URL to a .js (or page with --crawl), or a local .js file")
    ap.add_argument("--crawl", action="store_true", help="treat URL as HTML and fetch its <script src> bundles")
    ap.add_argument("--context", type=int, default=140, help="chars of context per evidence snippet")
    ap.add_argument("--json", metavar="FILE", help="also write the profile as JSON")
    ap.add_argument("--header", "-H", action="append", default=[], metavar='"K: V"',
                    help="extra request header (repeatable), e.g. -H \"Referer: https://app/\"")
    ap.add_argument("--cookie", metavar="STR", help="Cookie header value for authenticated chunks")
    a = ap.parse_args()

    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1); EXTRA_HEADERS[k.strip()] = v.strip()
    if a.cookie:
        EXTRA_HEADERS["Cookie"] = a.cookie

    try:
        text, where = load(a.target, a.crawl)
    except FetchError as e:
        print(f"[!] Could not load target: {e}\n", file=sys.stderr)
        if re.match(r"^https?://", a.target):
            print("    Hints:", file=sys.stderr)
            print("      - Chunk hashes change every build (esp. Next.js /_next/static/chunks).", file=sys.stderr)
            print("        Point at the app ROOT with --crawl to auto-discover current chunks:", file=sys.stderr)
            base = re.match(r"^(https?://[^/]+)", a.target)
            print(f"            python find_thuat_toan.py {base.group(1) if base else '<host>'}/ --crawl", file=sys.stderr)
            print("      - Or copy the real .js URL from DevTools -> Network, or save it to a file", file=sys.stderr)
            print("        and pass the local path instead.", file=sys.stderr)
            print("      - Lazy-loaded chunks may not appear in the initial HTML; grab the specific", file=sys.stderr)
            print("        crypto chunk from DevTools if --crawl misses it.", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"[!] Cannot read file '{a.target}': {e}", file=sys.stderr)
        sys.exit(2)

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
    fields = sorted(set(re.findall(FIELD_HINTS, text)) - LIB_NOISE)[:20]
    pwd = sorted(set(re.findall(PWD_HINTS, text, re.I)))[:10]
    trcodes = sorted(set(m[1] for m in re.findall(ENDPOINT_HINTS, text) if m[1]))[:15]
    print("    key/token fields :", ", ".join(fields) or "(none)")
    print("    password fields  :", ", ".join(pwd) or "(none)")
    print("    txn codes        :", ", ".join(trcodes) or "(none)")

    scheme, keygen, reasons, dynamic_key = infer(text, libs, aes_hits, ephemeral, static, keys, pwd, fields)

    print("\n" + "=" * 72)
    print("[=] VERDICT")
    print("    Scheme    :", scheme)
    print("    Key-gen   :", keygen)
    print("    Reasoning :", "; ".join(reasons))
    if dynamic_key:
        kf = next((f for f in fields if re.search(r"pub.?key", f, re.I)), None)
        print("    [!] Public key is NOT in this file -> supplied at runtime"
              + (f" (field '{kf}')" if kf else "")
              + ". Find where it is delivered (an API response or another chunk)")
        print("        and swap it THERE with Match & Replace (docs/05).")
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
