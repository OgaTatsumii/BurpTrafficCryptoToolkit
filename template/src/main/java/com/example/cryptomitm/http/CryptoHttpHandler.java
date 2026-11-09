package com.example.cryptomitm.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.example.cryptomitm.config.Config;
import com.example.cryptomitm.crypto.CryptoUtil;
import com.example.cryptomitm.crypto.RsaScheme;
import com.example.cryptomitm.store.SessionStore;
import com.example.cryptomitm.util.HttpUtil;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * HTTP layer (fires for ALL tools, after the proxy layer).
 *  - request to-be-sent: RE-ENCRYPT so the server receives valid ciphertext.
 *  - response received:  DECRYPT (and recover the session key on key exchange).
 */
public class CryptoHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final Gson gson = new Gson();

    public CryptoHttpHandler(MontoyaApi api) { this.api = api; }

    private boolean isKex(String url) { return url.contains(Config.KEX_URL_MARKER); }

    // ------------------------------------------------------------ REQUEST

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        boolean fromProxyPlaintext = req.hasHeader(Config.HDR_DECRYPTED);  // proxy decrypted it
        boolean fromOperator = req.hasHeader(Config.HDR_TOOL);             // you typed plaintext in Repeater
        HttpRequest edited = req.withRemovedHeader(Config.HDR_DECRYPTED).withRemovedHeader(Config.HDR_TOOL);

        if (!fromProxyPlaintext && !fromOperator) {
            return RequestToBeSentAction.continueWith(edited);
        }

        try {
            String body = req.bodyToString();

            if (Config.SCHEME == Config.Scheme.DIRECT_RSA) {
                String plain = HttpUtil.formParam(body, Config.RSA_FIELD);
                if (plain != null) {
                    PublicKey serverPub = CryptoUtil.publicKeyFromBase64(Config.SERVER_PUBLIC_KEY);
                    String cipher = RsaScheme.encrypt(plain.getBytes(StandardCharsets.UTF_8), serverPub);
                    edited = edited.withBody(HttpUtil.replaceFormParam(body, Config.RSA_FIELD, cipher));
                }
                return RequestToBeSentAction.continueWith(edited);
            }

            // HYBRID
            edited = edited.withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

            if (isKex(req.url())) {
                // body is the plaintext exchange JSON (with our swapped key) -> re-encode as message=
                String json = gson.fromJson(body, JsonObject.class).toString();
                edited = edited.withBody(HttpUtil.formBody(Config.MSG_FIELD, json));
                return RequestToBeSentAction.continueWith(edited);
            }

            String session = HttpUtil.cookie(req, Config.SESSION_COOKIE);
            SessionStore.Entry entry = SessionStore.get(session);
            if (entry == null) {
                api.logging().logToOutput("[http/req] no session key for cookie=" + session + " (sending as-is)");
                return RequestToBeSentAction.continueWith(edited);
            }
            String sealed = CryptoUtil.aesGcmEncrypt(body, entry.symKey);
            edited = edited.withBody(HttpUtil.formBody(Config.MSG_FIELD, sealed));
            if (entry.authToken != null && !entry.authToken.isEmpty()) {
                edited = edited.withUpdatedHeader("Authorization", "Bearer " + entry.authToken);
            }
            return RequestToBeSentAction.continueWith(edited);

        } catch (Exception e) {
            api.logging().logToError(e);
            return RequestToBeSentAction.continueWith(edited);
        }
    }

    // ----------------------------------------------------------- RESPONSE

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        HttpResponse edited = resp;
        HttpRequest req = resp.initiatingRequest();
        String url = req.url();

        boolean shouldRun = req.isInScope()
                && url.contains(Config.TARGET_URL_SUBSTR)
                && resp.headerValue("Content-Type") != null
                && resp.headerValue("Content-Type").toLowerCase().contains("application/json");
        if (!shouldRun || Config.SCHEME == Config.Scheme.DIRECT_RSA) {
            return ResponseReceivedAction.continueWith(edited);
        }

        try {
            String session = sessionFromResponseOrRequest(resp, req);

            if (isKex(url)) {
                return handleKexResponse(resp, edited, session);
            }

            // Data response: AES-GCM decrypt for visibility; proxy layer re-seals for the browser.
            SessionStore.Entry entry = SessionStore.get(session);
            if (entry == null) {
                api.logging().logToOutput("[http/resp] no session key for cookie=" + session);
                return ResponseReceivedAction.continueWith(edited);
            }
            JsonObject root = gson.fromJson(resp.bodyToString(), JsonObject.class);
            if (root == null || !root.has(Config.RESP_MSG_FIELD) || root.get(Config.RESP_MSG_FIELD).isJsonNull()) {
                return ResponseReceivedAction.continueWith(edited);
            }
            String plaintext = CryptoUtil.aesGcmDecrypt(root.get(Config.RESP_MSG_FIELD).getAsString(), entry.symKey);
            api.logging().logToOutput("[resp] decrypted body:\n" + plaintext);
            edited = edited.withBody(plaintext).withAddedHeader(Config.HDR_DECRYPTED, "1");
            return ResponseReceivedAction.continueWith(edited);

        } catch (Exception e) {
            api.logging().logToError(e);
            return ResponseReceivedAction.continueWith(edited);
        }
    }

    private ResponseReceivedAction handleKexResponse(HttpResponseReceived resp, HttpResponse edited, String session)
            throws Exception {
        JsonObject root = gson.fromJson(resp.bodyToString(), JsonObject.class);
        JsonObject bodyObj = (root != null) ? root.getAsJsonObject("body") : null;
        if (bodyObj == null || !bodyObj.has(Config.KEX_WRAPPED_SYMKEY_FIELD)) {
            return ResponseReceivedAction.continueWith(edited);
        }

        PrivateKey attackerPriv = CryptoUtil.privateKeyFromBase64(Config.ATTACKER_PRIVATE_KEY);
        String wrapped = bodyObj.get(Config.KEX_WRAPPED_SYMKEY_FIELD).getAsString();
        String symKey = new String(RsaScheme.decrypt(wrapped, attackerPriv), StandardCharsets.UTF_8);

        String token = (!Config.KEX_AUTH_TOKEN_FIELD.isEmpty() && bodyObj.has(Config.KEX_AUTH_TOKEN_FIELD))
                ? bodyObj.get(Config.KEX_AUTH_TOKEN_FIELD).getAsString() : "";

        SessionStore.Entry entry = new SessionStore.Entry(symKey, token);
        entry.clientRealPubKey = SessionStore.takePendingClientPubKey();
        SessionStore.put(session, entry);
        api.logging().logToOutput("[kex] recovered session key for cookie=" + session + "\n  symKey=" + symKey);

        // Transparent mode: re-wrap the session key to the client's REAL key so the browser keeps working.
        if (Config.TRANSPARENT_REWRAP && entry.clientRealPubKey != null) {
            PublicKey realClientPub = CryptoUtil.publicKeyFromBase64(entry.clientRealPubKey);
            String rewrapped = RsaScheme.encrypt(symKey.getBytes(StandardCharsets.UTF_8), realClientPub);
            bodyObj.addProperty(Config.KEX_WRAPPED_SYMKEY_FIELD, rewrapped);
            root.add("body", bodyObj);
            edited = edited.withBody(root.toString());
            api.logging().logToOutput("[kex] re-wrapped session key to the real client key (transparent)");
        }
        return ResponseReceivedAction.continueWith(edited);
    }

    private String sessionFromResponseOrRequest(HttpResponseReceived resp, HttpRequest req) {
        if (resp.hasCookie(Config.SESSION_COOKIE)) {
            String fresh = resp.cookieValue(Config.SESSION_COOKIE);
            String old = HttpUtil.cookie(req, Config.SESSION_COOKIE);
            if (!old.isEmpty()) SessionStore.rekey(old, fresh);
            return fresh;
        }
        return HttpUtil.cookie(req, Config.SESSION_COOKIE);
    }
}
