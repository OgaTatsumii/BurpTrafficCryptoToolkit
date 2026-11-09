# 06 — Building the extension

The [`template/`](../template) folder is a ready Montoya extension. Point its
`Config` at your target's crypto profile (from [`02`](02-finding-the-crypto.md) /
[`03`](03-analyzing-keygen.md)) and build a `.jar`.

## Prerequisites

- JDK 17+ (`javac -version`).
- Montoya API jar (pulled by Gradle, or downloaded manually for `javac`).
- Optional: Bouncy Castle (`bcprov-jdk18on`) if you want a provider beyond the
  JDK's SunJCE. The JDK already supports `RSA/ECB/OAEPPadding` with an explicit
  `OAEPParameterSpec` and `AES/GCM/NoPadding`, so BC is usually optional.

## Option A — Gradle (recommended)

`template/build.gradle` is preconfigured. From `template/`:

```bash
gradle jar          # or: ./gradlew jar
# output: build/libs/crypto-mitm-template-all.jar
```

The build produces a **fat jar** (bundles Gson/BC). Montoya itself is provided by
Burp at runtime, so it does not need to be shaded — but bundling is harmless.

## Option B — plain javac (no Gradle)

Download the Montoya jar once:

```
https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/<VERSION>/montoya-api-<VERSION>.jar
```

Then (PowerShell / bash equivalents):

```bash
LIBS="montoya-api.jar;gson.jar;bcprov.jar"   # ';' on Windows, ':' on *nix
javac -cp "$LIBS" -d build/classes $(find template/src -name '*.java')
jar cf build/libs/crypto-mitm-template.jar -C build/classes .
```

If you avoid Gson/BC (use `org.json` or hand-rolled parsing, and JDK crypto only),
you only need `montoya-api.jar` on the classpath and no shading at all.

## Loading into Burp

**Extensions → Add → Type: Java → Select file →** `…/build/libs/…​.jar`.
Watch the **Output / Errors** tabs of the extension for the log lines.

## Wiring the template to a new target

Edit `template/src/main/java/com/example/cryptomitm/config/Config.java`:

1. `TARGET_HOST` / scope match — restrict with `isInScope()` too.
2. `SCHEME` — `DIRECT_RSA` or `HYBRID_RSA_AES`.
3. RSA padding — `PKCS1` or `OAEP(hash, mgf1hash)`.
4. AES — `GCM` (iv 12, tag 128) or `CBC`.
5. `CIPHERTEXT_PARAM` — the body field carrying ciphertext.
6. Key-exchange detection — the endpoint/marker, and the request/response field
   names (`...PbKey` out, `...SymKey` back).
7. `ATTACKER_PUBLIC_KEY` / `ATTACKER_PRIVATE_KEY` — your keypair (keep out of git).

Then decide transparency (see [`03`](03-analyzing-keygen.md)):

- **Passive only** — leave the re-wrap logic off; drive the session yourself.
- **Transparent** — enable re-wrap: the proxy request handler saves the client's
  real public key; the HTTP response handler re-wraps the recovered session key to
  it before the browser sees it.

## Iterating

Edit → rebuild → in Burp, untick/retick (or use the extension's reload) to load
the new jar. Keep the Output tab open; the template logs every stage decision so
you can see exactly which branch fired.

## Build-hygiene checklist

- [ ] `Config` reflects the crypto profile exactly (padding + hashes matter).
- [ ] Attacker keypair present, **not** committed.
- [ ] `isInScope()` set so you never touch out-of-scope hosts.
- [ ] Session store is `ConcurrentHashMap`.
- [ ] Cross-layer header stripped before egress.
- [ ] Logs confirm: swap took → key/field recovered → plaintext in history.
