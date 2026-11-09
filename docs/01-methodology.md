# 01 — Methodology

## The problem

You are testing a web or mobile application through Burp with your own CA
installed. TLS is terminated at Burp, yet the request and response bodies are
**still unreadable** — the application encrypts payloads a second time, at the
application layer, before they ever hit the socket. Common shapes:

- A password (or whole request) is **RSA-encrypted in the browser** with a
  public key baked into the JavaScript.
- The client and server perform a **key exchange** (one side sends an RSA public
  key, the other returns an AES session key wrapped with it), and every
  subsequent body is **AES-encrypted** under that session key.

The goal of this methodology is to make that traffic readable (and tamperable)
inside Burp **without breaking the application**, so you can test the real
endpoints behind the encryption layer.

## Why it is possible at all

Application-layer encryption delivered over a channel you already MITM is only
as strong as the **authentication of the key material**. If the public key is:

- hard-coded and shipped in client code you can rewrite, or
- exchanged at runtime with **no signature / pinning / out-of-band trust**,

then you can substitute a key **you** control. The cryptographic primitives may
be perfectly strong (RSA-OAEP-2048, AES-GCM-256) and it still falls, because the
*trust* in the key is inherited entirely from the TLS session you have broken.

> This is the core finding to report: *"application-layer encryption relies
> solely on TLS for key authenticity; with a trusted CA an active MITM can
> substitute key material and recover plaintext."* It is a design observation,
> not necessarily a primitive weakness.

## The four steps

1. **Locate the crypto** — identify the library and algorithm from the JS
   bundle. → [`02-finding-the-crypto.md`](02-finding-the-crypto.md)
2. **Classify the key** — static/hard-coded vs ephemeral/exchanged. This decides
   *which* message you substitute into and whether a factoring shortcut exists.
   → [`03-analyzing-keygen.md`](03-analyzing-keygen.md)
3. **Substitute a controlled key** — via Burp Match & Replace (no rebuilds) so
   the secret you need is encrypted to *your* private key.
   → [`05-match-and-replace.md`](05-match-and-replace.md)
4. **Hook the pipeline** — a Montoya extension decrypts at the proxy layer (for
   visibility in history) and re-encrypts at the HTTP layer (so the server/peer
   still works). → [`04-burp-execution-flow.md`](04-burp-execution-flow.md)

## Two roles the extension plays

- **Passive visibility** — decrypt what flows by and show plaintext in HTTP
  history / Logger. Lowest risk, great for mapping the API.
- **Active transparency** — additionally re-encrypt so you can edit a decrypted
  request in Repeater, forward it, and have the backend accept it. This is what
  lets you fuzz the *real* parameters.

## When this does **not** work

- **Certificate / public-key pinning that you cannot strip** (e.g. a hardened
  mobile binary with native pinning + anti-Frida). You must first defeat pinning;
  that is out of scope for this repo.
- **Keys delivered out-of-band** (hard-coded in a separately-signed native blob
  with integrity checks, or provisioned via a channel you don't see).
- **Authenticated key exchange** — if the exchanged public key is itself signed
  by a key the client pins, substitution is detected.

## Deliverables you get from this method

- Readable request/response bodies in Burp for the whole session.
- The ability to send crafted plaintext through Repeater/Intruder against the
  real endpoints.
- Concrete evidence for the report: the recovered plaintext of your *own* test
  account's sensitive fields, proving the layer is bypassable under MITM.
