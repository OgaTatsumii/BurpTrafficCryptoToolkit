# tools/

## `find_thuat_toan.py` — crypto-scheme recon

Point it at a JS bundle (URL or local file) and it auto-detects the client-side
crypto: library, RSA padding, AES mode, the **key-generation rule** (static
hard-coded key vs ephemeral per-session keypair), decodes any RSA public keys
(size + exponent, flags weak ≤1024-bit), surfaces field/endpoint hints, and prints
a **crypto profile** ready to drop into the extension [`template/config/Config.java`](../template/src/main/java/com/example/cryptomitm/config/Config.java).

Pure Python standard library — no dependencies.

```bash
# a single bundle
python find_thuat_toan.py https://target/assets/index-XXXX.js

# start from an HTML page and pull its <script src> bundles
python find_thuat_toan.py https://target/ --crawl

# a local file, also emit JSON
python find_thuat_toan.py ./bundle.js --json profile.json --context 180
```

### What it reports

```
[1] Libraries        jsencrypt / node-forge / Web Crypto / CryptoJS / setPublicKey-style
[2] RSA padding      PKCS#1 v1.5 vs OAEP (+ OAEP hash / MGF1 hash hints)
[3] AES mode         GCM / CBC / CTR (+ IV length hint)
[4] Key-gen rule     STATIC (hard-coded)  vs  EPHEMERAL (generateKeyPair / subtle.generateKey)
[5] RSA public keys  decoded: N-bit, exponent, WEAK flag for <=1024-bit
[6] Field/endpoint   ...PbKey / ...SymKey / ...AuthToken / password / trcodes
[=] VERDICT          DIRECT_RSA | HYBRID_RSA_AES | REVIEW  + a ready Config block
                     + an auto-generated Match & Replace rule for each found key
```

### Caveats

- Works on **text** JS. Hermes/React-Native bytecode must be decompiled first
  (`hbctool`) — then feed the extracted strings/JS.
- Minified bundles rename library names away; detection falls back to behavioural
  markers (`setPublicKey(`, PEM headers, `generateKeyPair`).
- A bundle may contain **several** crypto usages (e.g. login RSA + analytics AES).
  The tool surfaces every signal; **you** confirm the login path by reading the
  call sites ([`../docs/02-finding-the-crypto.md`](../docs/02-finding-the-crypto.md)).
  A `REVIEW` verdict means "multiple/ambiguous signals — decide manually."
- The output is a **starting profile**, not ground truth. Always verify padding
  and field names at the call site before trusting a decrypt.

Authorized testing only.
