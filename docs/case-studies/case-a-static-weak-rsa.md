# Case Study A — Static, hard-coded, weak RSA

*All identifying details (names, domains, keys, parameters) are omitted. This is a
generalized account of a recurring pattern.*

## Context

A customer-facing trading platform with a shared code path between its web
front-end and a React Native mobile app. Login credentials were encrypted
client-side before submission.

## Crypto profile (from the bundle)

```
Scheme:        direct-RSA (the password field only)
Library:       jsencrypt (web) / the same routine compiled into the RN bundle
RSA padding:   PKCS#1 v1.5
RSA key size:  512-bit  ← weak
AES mode:      none
Key lifetime:  static, hard-coded public key (identical web + mobile)
Request field: the password form parameter
Key-exchange:  none
```

Found by grepping the bundle for `JSEncrypt` and `setPublicKey`; the key was a
~128-char base64 SPKI literal ending in `AQAB`.

## Why it fell

- **No certificate pinning** → the whole thing sat inside a channel we already
  MITM'd with our CA.
- **Static key** → one substitution covers every session.
- **512-bit modulus** → additionally factorable offline, so even without
  substitution the server's private key is recoverable and the password decrypts
  passively. (Public factor databases are worth checking before spending compute.)

## Approach taken

Two interchangeable routes, both documented in this repo:

1. **Substitution (no rebuild):**
   - Match & Replace Rule 1 stripped `If-None-Match` to defeat `304` and force a
     full bundle download (the Vite bundle revalidated every load).
   - Match & Replace Rule 2 swapped the static key for ours using the
     rotation-proof 512-bit regex (fixed DER prefix + modulus wildcard + fixed
     `e` tail).
   - The extension decrypted the password at the **proxy request** layer (so
     history showed the cleartext password) and re-encrypted it with the real key
     at the **HTTP request** layer (so login still succeeded).

2. **Factoring (passive):** recover the private key from the 512-bit modulus and
   decrypt captured passwords directly — no browser interaction, works on traffic
   captured earlier.

## Lessons that generalized

- The **`304` trap**: a response-body swap silently does nothing when the server
  answers `Not Modified` with an empty body. Always pair the key swap with a
  conditional-header strip. → [`05`](../05-match-and-replace.md#defeating-304)
- **Decrypt-at-proxy / re-encrypt-at-http** is what makes history readable *and*
  login functional at the same time. → [`04`](../04-burp-execution-flow.md)
- Report framing: here the finding is **two** things — a MITM key-substitution
  observation *and* a real **weak-primitive** finding (RSA-512).
