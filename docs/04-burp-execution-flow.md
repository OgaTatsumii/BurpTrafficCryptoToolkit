# 04 — Burp execution flow (Montoya API)

> Read this before writing code. Choosing the wrong stage is why extensions
> "run but history still shows ciphertext" or "show plaintext but break the app."

All class/interface names below are
[Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/package-summary.html)
types. Links point at the official javadoc.

## The pipeline, conceptually

```
REQUEST
  client ─▶ Burp ──▶ [Proxy: received] ──▶ [Proxy: to-be-sent] ──▶ ★HISTORY★
                                                   │
                                                   ▼
                              [HTTP: request to-be-sent] ──▶ server

RESPONSE
  server ─▶ Burp ──▶ [HTTP: response received] ──▶ [Proxy: received] ──▶ [Proxy: to-be-sent] ──▶ client
```

## Exact Montoya callbacks

### Request path (proxied request)

| # | Interface · method | Return type | Fires | Use it for |
|---|--------------------|-------------|-------|-----------|
| 1 | [`ProxyRequestHandler`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyRequestHandler.html) · `handleRequestReceived(InterceptedRequest)` | [`ProxyRequestReceivedAction`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyRequestReceivedAction.html) | proxy only, before the intercept window | **Decrypt here** so the plaintext is what the intercept view and history show. |
| 2 | *(Proxy intercept editor, if enabled)* | — | — | manual edits |
| 3 | `ProxyRequestHandler` · `handleRequestToBeSent(InterceptedRequest)` | [`ProxyRequestToBeSentAction`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyRequestToBeSentAction.html) | proxy only, after intercept | Proxy **HTTP history is recorded from this stage**. |
| 4 | [`HttpHandler`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/handler/HttpHandler.html) · `handleHttpRequestToBeSent(HttpRequestToBeSent)` | [`RequestToBeSentAction`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/handler/RequestToBeSentAction.html) | **all tools**, last stop before egress | **Re-encrypt here** so the server receives valid ciphertext. Also fires for Repeater/Intruder. |

### Response path

| # | Interface · method | Return type | Fires | Use it for |
|---|--------------------|-------------|-------|-----------|
| 1 | `HttpHandler` · `handleHttpResponseReceived(HttpResponseReceived)` | [`ResponseReceivedAction`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/handler/ResponseReceivedAction.html) | **all tools**, first thing after server reply | **Decrypt the response** and (for key-exchange) recover the session key. |
| 2 | [`ProxyResponseHandler`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyResponseHandler.html) · `handleResponseReceived(InterceptedResponse)` | [`ProxyResponseReceivedAction`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyResponseReceivedAction.html) | proxy only | **Re-encrypt the response** for the browser if you want the app to keep working. |
| 3 | `ProxyResponseHandler` · `handleResponseToBeSent(InterceptedResponse)` | [`ProxyResponseToBeSentAction`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyResponseToBeSentAction.html) | proxy only | final form delivered to the client. |

Register all three in your [`BurpExtension.initialize`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/BurpExtension.html):

```java
api.proxy().registerRequestHandler(new CryptoProxyRequestHandler(api));
api.proxy().registerResponseHandler(new CryptoProxyResponseHandler(api));
api.http().registerHttpHandler(new CryptoHttpHandler(api));
```

## The golden rule

```
DECRYPT at the Proxy layer   → plaintext appears in HTTP history.
RE-ENCRYPT at the HTTP layer → server/peer still receives valid ciphertext.
```

Because the Proxy records history at stage 3 of the request path, a modification
made later (stage 4, `HttpHandler`) is **not** reflected in history. That is
exactly what you want: history shows the decrypted body, the wire shows ciphertext.

## Passing state between the two layers

The proxy layer and the HTTP layer are different handlers. You often need to tell
the HTTP layer "this request was decrypted by the proxy layer; please re-encrypt
it." Two options:

| Mechanism | Verdict |
|-----------|---------|
| [`Annotations`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/core/Annotations.html) / notes | **Do not rely on it** for proxy→HTTP. In practice notes set at the proxy layer do not consistently reach `handleHttpRequestToBeSent`. |
| A **custom HTTP header** (e.g. `X-TL-Crypto: 1`) | **Recommended.** It is part of the request, survives into the HTTP layer, and you strip it before egress with [`HttpRequest.withRemovedHeader`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/requests/HttpRequest.html). |

The template uses the header approach. A second header (e.g. `X-TL-Tool: 1`) marks
requests *you* originate in Repeater as "already plaintext, please encrypt" so you
can type cleartext and let the extension seal it.

## Message-mutation helpers you will use

- [`HttpRequest.withBody`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/requests/HttpRequest.html) / [`HttpResponse.withBody`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/responses/HttpResponse.html) — recomputes `Content-Length`.
- `withUpdatedHeader`, `withAddedHeader`, `withRemovedHeader`.
- `parameterValue(name, HttpParameterType.BODY)` for form params — but verify you
  are not **double-URL-decoding** (base64 `+` becomes a space if you decode twice).
- [`ByteArray`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/core/ByteArray.html) for raw bodies.
- `request.isInScope()` to limit blast radius to your configured target scope.

## Concurrency

Burp invokes handlers on **multiple threads**. Any shared session store
(recovered keys keyed by cookie) must be thread-safe — use `ConcurrentHashMap`,
not `HashMap`.
