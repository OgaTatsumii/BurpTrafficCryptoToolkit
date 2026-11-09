# 03 — Analyzing key generation

The single most important question once you've found the crypto:

> **Where does the key the client encrypts with come from?**

The answer decides which message you substitute into, whether a factoring
shortcut exists, and how much the extension has to do.

## Pattern A — Static, hard-coded public key

The public key is a **constant string** in the JS/resources. The client encrypts
directly to it every time.

**How to recognize it**
- A base64 key literal assigned to a variable (`var k="MFw...=="`) or a PEM block.
- `setPublicKey(k)` / `publicKeyFromPem(k)` with `k` being that constant.
- No `generateKey` / `generateKeyPair` near the crypto.

**What it means**
- You can **substitute the key once** (Match & Replace on the bundle response) and
  every client session uses your key.
- If the key is **weak** (RSA-512, sometimes 768), you can additionally **factor**
  the modulus offline and recover the server's private key — then you decrypt
  passively with no substitution at all. (512-bit is factorable on commodity
  hardware; check public factor databases first.)

**Reporting angle:** weak/static key = a genuine crypto weakness, not just a MITM
observation.

### Extracting `n` and `e` from an SPKI blob

An RSA SPKI DER base64 begins with fixed bytes. For a 512-bit, `e=65537` key the
prefix `MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBA` and suffix `wEAAQ==` are **constant**;
only the 64-byte modulus in the middle varies. That is what makes a
rotation-proof Match & Replace regex possible (see [`05`](05-match-and-replace.md)).

## Pattern B — Ephemeral / exchanged key (hybrid)

The client **generates a fresh keypair per session** and sends its public key to
the server; the server returns a symmetric session key wrapped to it; subsequent
bodies use AES under that session key.

**How to recognize it**
- `crypto.subtle.generateKey({name:"RSA-OAEP", modulusLength:2048,...})` or
  `forge.pki.rsa.generateKeyPair({bits:2048})`.
- A request that carries a freshly-produced public key (`...PbKey`), followed by a
  response field carrying a wrapped symmetric key (`...SymKey`).
- An `AES-GCM` encrypt/decrypt helper used for everything after that exchange.

**What it means**
- Factoring is **out** (2048-bit).
- You attack the **key exchange**: substitute the *client's* public key in the
  outbound exchange request with **your** public key. The server then wraps the
  session key to your key, and your private key recovers it. From then on you hold
  the session key and can AES-decrypt the whole conversation.
- **Keeping the real client working is the subtle part.** If you overwrite the
  client's public key and do nothing else, the server wraps the session key to
  *your* key and the real client can no longer unwrap it — its session breaks.
  To stay transparent you must either:
  1. **Save the client's real public key** before overwriting, and **re-wrap** the
     recovered session key to it in the response (so the client derives the *same*
     key you did), **or**
  2. **Pin a fixed keypair into the client** by rewriting the bundle so
     `generateKeyPair()` returns a keypair you also hold — then both sides unwrap
     natively and nothing needs re-wrapping.

  Option 1 needs an RSA *encrypt* in the matching padding; option 2 needs a bundle
  rewrite but no response surgery. If you only need **passive visibility for your
  own driven session** (you are the client, via Burp/Repeater), you can skip both
  and accept that the live browser session won't continue.

## Pattern C — Password-only direct RSA (special case of A)

Only the `password` field is RSA-encrypted; the rest of the request is plaintext.
Simplest case: swap the (static) key, decrypt the one field at the proxy layer,
re-encrypt it with the real key at the HTTP layer. No AES involved.

## Decision table

| Observation | Attack surface | Factoring? | Extension complexity |
|-------------|----------------|-----------|----------------------|
| Static key, RSA-512 | swap in bundle **or** factor | ✅ | Low |
| Static key, RSA-2048 | swap in bundle | ❌ | Low |
| Ephemeral keypair + AES session | swap in key-exchange request | ❌ | Medium–High (RSA unwrap + AES + optional re-wrap) |
| Password-only direct RSA | swap + per-field re-encrypt | depends on size | Low |

Fill the matching fields of the template `Config` and move on to
[`04-burp-execution-flow.md`](04-burp-execution-flow.md).
