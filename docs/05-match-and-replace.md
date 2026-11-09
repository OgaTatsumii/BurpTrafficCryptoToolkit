# 05 — Key substitution with Match & Replace

Match & Replace (Burp → **Settings → Proxy → Match and replace rules**) lets you
swap key material **without rebuilding the extension**. It cannot do crypto — it
is pure string substitution — so it pairs with the extension, which does the
decrypt/encrypt.

Division of labour:

- **Match & Replace** → force a full response (defeat `304`) and swap the target
  public key for **yours**.
- **Extension** → decrypt with your private key (visibility) and re-encrypt with
  the real key (so the peer still works).

## Rule 1 — Defeat `304` cache revalidation <a name="defeating-304"></a>

Hashed bundles (`index-<hash>.js`) are served with `Cache-Control: max-age=0` +
an `ETag`. The browser then sends a **conditional request** (`If-None-Match`) and
the server answers **`304 Not Modified` with an empty body** — so there is nothing
for a response-body rule to rewrite, and the browser keeps using its cached copy
with the original key.

Strip the conditional headers so the server must return a full `200`:

| Field | Value |
|-------|-------|
| Type | `Request header` |
| Match | `^If-None-Match.*$` |
| Replace | *(empty)* |
| Regex | ✔ |

Add a second identical rule for `^If-Modified-Since.*$`. (The template's HTTP
handler can also do this with `withRemovedHeader` if you prefer code over config.)

## Rule 2 — Swap the public key

| Field | Value |
|-------|-------|
| Type | `Response body` |
| Match | *(the target key — literal or regex, see below)* |
| Replace | *(your public key, SPKI base64, one line)* |
| Regex | ✔ |

### Literal match (simplest)

Paste the exact base64 key as `Match`. Because Burp treats the field as a regex,
escape regex metacharacters — in base64 that is just `+` → `\+` (`/` and `=` are
literal in a Java regex).

### Rotation-proof regex (recommended)

A 512-bit RSA SPKI has a **constant header and tail** (fixed DER + `e=65537`); only
the 64-byte modulus varies. Match the stable ends and wildcard the middle so the
rule still fires after the server rotates to a new key of the same size:

```
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBA[A-Za-z0-9+/]{80,110}wEAAQ==
```

- `MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBA` — fixed DER prefix of a 512-bit RSA SPKI.
- `[A-Za-z0-9+/]{80,110}` — the varying modulus (add `?` to make it non-greedy if
  two keys sit back-to-back).
- `wEAAQ==` — fixed tail encoding `e=65537`.

> Only matches **512-bit, e=65537** keys. If the server upgrades the key *size*,
> the prefix changes — but so does the whole premise (a larger key likely closed
> the weakness). For 2048-bit keys, anchor on the `MIIBIjANBgkqhkiG9w0BAQEF…`
> prefix instead and widen the modulus quantifier.

## Where to swap, by scheme

| Scheme (see [`03`](03-analyzing-keygen.md)) | Swap target |
|------|-------------|
| Static key, direct RSA | the key literal in the **bundle response** body |
| Ephemeral keypair + AES | the **client public key in the key-exchange request** — a `Request body` rule (or do it in code; the template does it in the proxy request handler so it can also save the original for re-wrapping) |

## Keeping the two halves consistent

The private key your extension decrypts with **must** match the public key you
inject. The cleanest workflow:

1. Generate one attacker keypair; keep the private key in the extension's config,
   the public key in the Match & Replace `Replace` field.
2. Never commit either (see `.gitignore`).

## Verifying it took

- The swapped response is now `200` (not `304`) and, searched in history,
  contains **your** key, not the original.
- The outbound ciphertext length changes to match **your** key size (e.g. a
  2048-bit key produces a 256-byte wrapped value instead of the original size).
- The extension log prints a recovered session key / decrypted field.
