# Case Study B — Hybrid: ephemeral RSA-OAEP key-exchange + AES-GCM

*All identifying details (names, domains, keys, transaction codes, cookie/header
names) are omitted. This is a generalized account.*

## Context

A retail internet-banking front-end (SPA). Unlike Case A, there was **no static
key and no weak primitive** — the design was modern and, as primitives go, sound.

## Crypto profile (from the bundle)

```
Scheme:        hybrid — RSA-wrapped AES session key, then AES for every body
Libraries:     Web Crypto (crypto.subtle) + a forge fallback
Key exchange:  client GENERATES an ephemeral RSA-2048 keypair per session,
               sends its public key in a dedicated key-exchange request;
               server returns an AES session key wrapped with it
RSA padding:   OAEP, hash = SHA-256, MGF1 hash = SHA-1   ← non-default combo
AES mode:      AES-GCM, 128-bit key, 12-byte random IV prepended, 128-bit tag
Key lifetime:  ephemeral, per session
Session binding: a session cookie keyed the server-side session
```

Found by grepping for `crypto.subtle`, `"RSA-OAEP"`, `"AES-GCM"`, and
`generateKeyPair`. The OAEP parameters were read directly off the forge decrypt
call (`{md: sha256, mgf1: sha1}`) — this exact combo had to be replicated in Java
with an `OAEPParameterSpec(SHA-256, MGF1, MGF1ParameterSpec.SHA1, …)`.

## Why it fell (despite strong crypto)

Factoring was off the table (2048-bit). The weakness was **trust**, not math: the
exchanged public key was authenticated **only by TLS**, which our CA had broken.
No pinning, no signature over the key.

## Approach taken

1. **Substitute the client public key in the key-exchange request** (proxy request
   layer) with our attacker public key — so the server wrapped the AES session key
   **to our key**.
2. **Recover the session key** in the HTTP response handler: RSA-OAEP-decrypt the
   wrapped key with our private key (SHA-256 / MGF1-SHA-1) and store it, keyed by
   the session cookie, in a thread-safe map.
3. **AES-GCM decrypt** every subsequent body (IV = first 12 bytes, tag = 128 bits)
   at the HTTP response layer → plaintext in history; **re-encrypt** at the proxy
   response layer for the browser, and at the HTTP request layer for the server.
4. Cross-layer coordination used a **custom HTTP header**, not annotations.

## The transparency pitfall (worth internalizing)

Overwriting the client's public key and nothing else **breaks the real browser
session**: the server now wraps the session key to *our* key, so the browser's own
private key can no longer unwrap it, and every later AES call fails.

Two ways to stay transparent — pick before you build:

- **Re-wrap:** save the browser's real public key when you overwrite it, then
  re-encrypt the recovered session key to that key in the response so the browser
  derives the *same* key you did. Needs an RSA-OAEP **encrypt** in the matching
  padding.
- **Pin a fixed keypair into the client:** rewrite the bundle so `generateKeyPair`
  yields a keypair you also hold — both sides unwrap natively, no response surgery.

If you are only driving the session yourself (you are the client, through
Burp/Repeater), you can skip transparency entirely and accept that the live
browser won't continue past the exchange.

## Lessons that generalized

- **Non-default padding must be matched byte-for-byte** — `OAEP(SHA-256)/MGF1(SHA-1)`
  is a real combination; getting MGF1 wrong yields silent decrypt failures.
- **Attack the key exchange, not the payload** — with hybrid schemes the RSA step
  is a one-time session-key wrap; own that and you own everything after it.
- **Strong primitives ≠ safe under MITM** — the report framing here is a
  **key-authentication / pinning** finding, materially different from Case A's
  weak-key finding.
- **Keep the peer alive deliberately** — decide up front whether you need
  transparency, because retrofitting the re-wrap is the fiddly part.
