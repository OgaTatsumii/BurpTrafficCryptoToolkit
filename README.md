# Burp Traffic Crypto Toolkit

A methodology and reusable Burp Suite (Montoya API) extension template for
**transparently decrypting and re-encrypting application-layer-encrypted HTTP
traffic** during authorized security assessments.

Many modern web and mobile apps encrypt request/response bodies *above* TLS
(RSA-wrapped payloads, hybrid RSA+AES schemes, per-session key exchange). When
you MITM such an app with your own CA, Burp shows you only ciphertext. This
toolkit documents a repeatable way to turn that ciphertext back into readable
plaintext inside Burp's HTTP history — and to tamper with it — by combining
**Match & Replace key substitution** with a small **Montoya extension** that
hooks the right stages of Burp's request/response pipeline.

> ⚠️ **Authorized use only.** Everything here is for testing systems you own or
> are explicitly contracted to assess. See [Ethics & Scope](#ethics--scope).

---

## What's inside

| Path | Contents |
|------|----------|
| [`docs/01-methodology.md`](docs/01-methodology.md) | The overall approach, threat model, and when this works (and when it doesn't). |
| [`docs/02-finding-the-crypto.md`](docs/02-finding-the-crypto.md) | Keyword cheat-sheet for locating the crypto algorithm inside minified JS bundles. |
| [`docs/03-analyzing-keygen.md`](docs/03-analyzing-keygen.md) | How to tell a *static* key from an *ephemeral* / exchanged key, and what each implies for the attack. |
| [`docs/04-burp-execution-flow.md`](docs/04-burp-execution-flow.md) | Burp's request/response pipeline mapped to exact Montoya callbacks — the single most important thing to get right. |
| [`docs/05-match-and-replace.md`](docs/05-match-and-replace.md) | Key substitution with Burp's built-in Match & Replace, regex that survives key rotation, and defeating `304` cache revalidation. |
| [`docs/06-building-the-extension.md`](docs/06-building-the-extension.md) | Building the template into a `.jar` (Gradle or plain `javac`) and wiring it to a new target. |
| [`docs/case-studies/`](docs/case-studies/) | Two anonymized real-world schemes and how each was handled. |
| [`tools/find_thuat_toan.py`](tools/find_thuat_toan.py) | Recon script: auto-detect the scheme, padding, **key-gen rule**, and keys from a JS bundle, and print a ready `Config` profile. |
| [`template/`](template/) | A ready-to-build Montoya extension skeleton covering RSA (PKCS#1 v1.5 / OAEP) and AES (GCM / CBC). |

## Quick mental model

```
REQUEST   client ──▶ Burp ─[Proxy: received ▸ to-be-sent ▸ HISTORY]─▶ [HTTP: request to-be-sent] ──▶ server
RESPONSE  server ──▶ Burp ─[HTTP: response received]─▶ [Proxy: received ▸ to-be-sent]─────────────▶ client
```

- **Decrypt for visibility** at the **Proxy** layer → Burp's HTTP history shows plaintext.
- **Re-encrypt for the server** at the **HTTP** layer → the backend still receives valid ciphertext.
- Pass state between the two layers with a **custom HTTP header**, not annotations
  (annotations do not reliably propagate from the proxy layer to the HTTP layer).

Read [`docs/04-burp-execution-flow.md`](docs/04-burp-execution-flow.md) before writing a single line of code — choosing the wrong stage is the number-one reason these extensions "work but show nothing" or "show plaintext but break login."

## 60-second overview of the method

1. **Find the algorithm** — run [`tools/find_thuat_toan.py <url|file>`](tools/find_thuat_toan.py)
   to auto-detect the library, padding, AES mode, key-gen rule and keys; or grep by
   hand for `JSEncrypt`, `forge`, `crypto.subtle`, `RSA-OAEP`, `AES-GCM`, `setPublicKey`…
   → [`02`](docs/02-finding-the-crypto.md)
2. **Classify the key** — is the public key *hard-coded* (swap it / maybe factor it)
   or *generated per session and exchanged* (swap it in the exchange)?
   → [`03`](docs/03-analyzing-keygen.md)
3. **Substitute a key you control** — Match & Replace the server/client public key
   with your own, so the material you need gets encrypted *to your private key*.
   → [`05`](docs/05-match-and-replace.md)
4. **Hook the pipeline** — decrypt at the proxy layer (visibility), re-encrypt at the
   HTTP layer (so the server/peer keeps working). → [`04`](docs/04-burp-execution-flow.md), [`template/`](template/)

## Ethics & Scope

This project documents defensive-relevant offensive technique. It is intended for:

- Penetration testers operating under a signed engagement / rules of engagement.
- Bug-bounty researchers within a program's stated scope.
- Blue teams validating that application-layer encryption is **not** mistaken for
  a substitute for certificate pinning and proper key authentication.

It must **not** be used against systems you are not authorized to test. No target
names, domains, keys, or transaction identifiers appear anywhere in this repo; the
case studies are deliberately generalized.

## License

[MIT](LICENSE) — the documentation and template code. The Montoya API and any
third-party crypto providers are under their own licenses.
