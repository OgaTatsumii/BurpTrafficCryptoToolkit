# Crypto MITM Template (Montoya)

A minimal, documented Burp extension skeleton that decrypts/re-encrypts
application-layer-encrypted traffic. Point [`Config`](src/main/java/com/example/cryptomitm/config/Config.java)
at a target and build a `.jar`. See the repo [`docs/`](../docs) for the method.

## Layout

```
src/main/java/com/example/cryptomitm/
├── CryptoMitmExtension.java        BurpExtension entry point (registers handlers)
├── config/Config.java              ← EDIT THIS per target (crypto profile + attacker keypair)
├── crypto/
│   ├── CryptoUtil.java             RSA PKCS1/OAEP + AES-GCM/CBC primitives (JDK only)
│   └── RsaScheme.java              picks PKCS1 vs OAEP from Config
├── store/SessionStore.java         thread-safe recovered-key store
├── util/HttpUtil.java              single-decode form params + safe cookie parsing
├── proxy/
│   ├── CryptoProxyRequestHandler.java    DECRYPT request (history shows plaintext) + key swap
│   └── CryptoProxyResponseHandler.java   RE-ENCRYPT response for the browser (transparent mode)
└── http/CryptoHttpHandler.java     RE-ENCRYPT request for server + DECRYPT response + recover session key
```

## What it implements

- **Decrypt at the proxy layer, re-encrypt at the HTTP layer** (so history is
  readable *and* the backend still works). → [`../docs/04-burp-execution-flow.md`](../docs/04-burp-execution-flow.md)
- **Two schemes**, selected by `Config.SCHEME`:
  - `DIRECT_RSA` — one field (e.g. `password`) is RSA-encrypted. Decrypt with your
    key, re-encrypt with the server's real key.
  - `HYBRID_RSA_AES` — a key-exchange request carries a client public key; swap it,
    recover the AES session key from the response, then AES-GCM the whole session.
- **Cross-layer signalling via a custom header** (`X-TL-Crypto`), not annotations.
- **Operator path** (`X-TL-Tool`): send plaintext from Repeater and let the
  extension seal it.
- **Optional transparent re-wrap** (`Config.TRANSPARENT_REWRAP`) so the live
  browser keeps working in hybrid mode.

## Build

```bash
gradle jar          # -> build/libs/crypto-mitm-template-all.jar
```

No Gradle? See [`../docs/06-building-the-extension.md`](../docs/06-building-the-extension.md)
for the plain-`javac` recipe. JDK 17+ required. Montoya is `compileOnly` (Burp
supplies it at runtime); Gson and Bouncy Castle are bundled.

## Use

1. Fill `Config` (scheme, padding/hashes, field names, key-exchange marker,
   session cookie, and **your attacker keypair** — keep it out of git).
2. Pick transparency: `TRANSPARENT_REWRAP = false` for passive/operator-driven,
   `true` to keep the victim browser working.
3. Build, then **Burp → Extensions → Add → Java →** the jar.
4. If a public key must be substituted in a cached JS bundle, pair with the
   Match & Replace rules in [`../docs/05-match-and-replace.md`](../docs/05-match-and-replace.md).
5. Watch the extension's **Output/Errors** — every stage logs its decision.

## Notes & limits

- `SessionStore` keeps a **single-slot** pending client public key for transparent
  re-wrap. Fine for one operator/one session; correlate on an in-message UUID for
  concurrent sessions.
- The response `Content-Type` gate matches `application/json` case-insensitively;
  widen if your target varies.
- Authorized testing only. No target identifiers belong in `Config` once committed.
