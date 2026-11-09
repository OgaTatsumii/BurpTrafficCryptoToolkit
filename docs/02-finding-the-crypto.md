# 02 — Finding the crypto in a JS bundle

> **Shortcut:** [`tools/find_thuat_toan.py <url|file>`](../tools/find_thuat_toan.py)
> automates everything below — library, padding, AES mode, key-gen rule, decoded
> keys, and a ready `Config` profile. Use it first, then read the call sites here
> to confirm. The manual method follows so you can verify (and handle what the
> script flags as `REVIEW`).

Modern front-ends ship as one or a few **minified / bundled** JS files
(`assets/index-<hash>.js` for Vite, `main.<hash>.js` for webpack, a Hermes
bytecode blob for React Native). You rarely need to understand the whole bundle —
you only need to find the crypto entry points and the key material.

## Step 1 — Pull the bundle

- Web: load the login page, note the `<script src>`, fetch that file. (If it
  revalidates with `304`, see [`05`](05-match-and-replace.md#defeating-304).)
- Mobile (RN): extract `assets/index.android.bundle` from the APK; if it is
  Hermes bytecode, `strings`/`hbctool` still surface the key constants.

## Step 2 — Grep for library + algorithm

Search the bundle (case-insensitive) for these. The first hit usually tells you
the whole scheme.

### RSA libraries (client-side public-key encryption)

| Keyword | Meaning |
|---------|---------|
| `JSEncrypt`, `JSEncryptRSAKey` | `jsencrypt` lib — RSA, **PKCS#1 v1.5** by default. |
| `setPublicKey`, `setKey`, `getPublicBaseKeyB64` | public key being loaded into jsencrypt / forge. |
| `node-forge`, `forge.pki`, `pki.publicKeyFromPem`, `publicKeyToPem` | `node-forge` — supports PKCS#1 v1.5 **and** OAEP. |
| `.encrypt(`, `RSAES-PKCS1-V1_5`, `RSA-OAEP`, `RSAES-OAEP` | the actual padding scheme in use. |

### Web Crypto API (native, strong, often hybrid)

| Keyword | Meaning |
|---------|---------|
| `crypto.subtle`, `subtle.encrypt`, `subtle.decrypt` | Web Crypto in use. |
| `"RSA-OAEP"`, `modulusLength`, `hash:"SHA-256"` | RSA-OAEP params for key wrapping. |
| `"AES-GCM"`, `tagLength`, `iv` | AES-GCM for payload encryption (almost always 12-byte IV + 128-bit tag). |
| `"AES-CBC"`, `createEncryptionCipher` | AES-CBC (needs explicit IV; watch for static/zero IVs). |
| `importKey`, `exportKey`, `generateKey`, `deriveKey`, `wrapKey` | key handling — see [`03`](03-analyzing-keygen.md). |

### Key material itself

| Pattern | What it is |
|---------|-----------|
| `-----BEGIN PUBLIC KEY-----` | PEM SPKI public key (strip headers to get base64 DER). |
| `"MFw...CAwEAAQ=="` (≈128 b64 chars) | DER SPKI of a **512-bit** RSA key — weak, see [`03`](03-analyzing-keygen.md). |
| `"MIIBIj...IDAQAB"` (≈392 b64 chars) | DER SPKI of a **2048-bit** RSA key. |
| `AQAB` near the end | the public exponent 65537 (`0x010001`) — confirms you found an RSA public key. |

### Hashing / misc (context only)

`sha256`, `sha1`, `md5`, `pbkdf2`, `HMAC`, `GCM`, `base64`/`encode64`/`decode64`.
Note: a bundle containing `md5`/`rc4`/`des` is usually just the **library's
registry** (forge ships them all). Confirm an algorithm is actually *invoked*
before reporting it — grep for the call site, not the string.

## Step 3 — Read the call sites, not the library

Once a keyword hits, dump ~200 chars around it and look for:

- **Which padding** the encrypt/decrypt call specifies (`{md: sha256, mgf1: sha1}`
  → OAEP-SHA256 with MGF1-SHA1 — a non-default combo you must replicate exactly).
- **Which field name** carries the ciphertext in the request body
  (`password`, `message`, `cryPbKey`, `crySymKey`, …).
- **The endpoint / transaction code** that performs the key exchange.

## Step 4 — Record a "crypto profile"

Before touching Burp, write down:

```
Scheme:        [direct-RSA | hybrid RSA-wrap + AES]
RSA padding:   [PKCS1v15 | OAEP(hash=?, mgf1=?)]
RSA key size:  [512 | 1024 | 2048 ...]
AES mode:      [none | GCM(iv=12,tag=128) | CBC(iv=?)]
Key lifetime:  [static hard-coded | ephemeral per-session]  (see 03)
Request field: [name of ciphertext param]
Key-exchange:  [endpoint / trcode, or N/A]
```

This profile is exactly what you plug into the template's `Config`.
