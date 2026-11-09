package com.example.cryptomitm.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.example.cryptomitm.config.Config;
import com.example.cryptomitm.crypto.CryptoUtil;
import com.example.cryptomitm.crypto.RsaScheme;
import com.example.cryptomitm.store.SessionStore;
import com.example.cryptomitm.util.HttpUtil;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

/**
 * PROXY REQUEST layer — decrypts inbound (browser->server) requests so Burp's
 * HTTP history shows plaintext, and substitutes the client public key in the
 * key-exchange request. Re-encryption happens later, at the HTTP layer.
 */
public class CryptoProxyRequestHandler implements ProxyRequestHandler {
    private final MontoyaApi api;
    private final Gson gson = new Gson();

    public CryptoProxyRequestHandler(MontoyaApi api) { this.api = api; }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {
        HttpRequest edited = req;
        String url = req.url();

        boolean shouldRun = url.contains(Config.TARGET_URL_SUBSTR)
                && req.isInScope()
                && !req.hasHeader("Content-Type", "multipart/form-data");
        if (!shouldRun) {
            return ProxyRequestReceivedAction.continueWith(req);
        }

        try {
            if (Config.SCHEME == Config.Scheme.DIRECT_RSA) {
                return handleDirectRsa(req, edited);
            }
            return handleHybrid(req, edited, url);
        } catch (Exception e) {
            api.logging().logToError(e);
            return ProxyRequestReceivedAction.continueWith(req);
        }
    }

    private ProxyRequestReceivedAction handleDirectRsa(InterceptedRequest req, HttpRequest edited) throws Exception {
        String body = req.bodyToString();
        String cipher = HttpUtil.formParam(body, Config.RSA_FIELD);
        if (cipher == null) return ProxyRequestReceivedAction.continueWith(req);

        PrivateKey attackerPriv = CryptoUtil.privateKeyFromBase64(Config.ATTACKER_PRIVATE_KEY);
        String plaintext = new String(RsaScheme.decrypt(cipher, attackerPriv), StandardCharsets.UTF_8);
        api.logging().logToOutput("[req/direct] " + Config.RSA_FIELD + " = " + plaintext);

        String newBody = HttpUtil.replaceFormParam(body, Config.RSA_FIELD, plaintext);
        edited = edited.withBody(newBody).withAddedHeader(Config.HDR_DECRYPTED, "1");
        return ProxyRequestReceivedAction.continueWith(edited);
    }

    private ProxyRequestReceivedAction handleHybrid(InterceptedRequest req, HttpRequest edited, String url) throws Exception {
        String body = req.bodyToString();
        String message = HttpUtil.formParam(body, Config.MSG_FIELD);
        if (message == null) return ProxyRequestReceivedAction.continueWith(req);

        if (url.contains(Config.KEX_URL_MARKER)) {
            // Key-exchange request: swap the client's public key for ours, remember the real one.
            JsonObject root = gson.fromJson(message, JsonObject.class);
            JsonObject bodyObj = root.getAsJsonObject("body");
            String realClientPub = bodyObj.has(Config.KEX_CLIENT_PUBKEY_FIELD)
                    ? bodyObj.get(Config.KEX_CLIENT_PUBKEY_FIELD).getAsString() : null;
            if (realClientPub != null) SessionStore.setPendingClientPubKey(realClientPub);

            bodyObj.addProperty(Config.KEX_CLIENT_PUBKEY_FIELD, Config.ATTACKER_PUBLIC_KEY);
            root.add("body", bodyObj);

            api.logging().logToOutput("[req/kex] swapped client public key -> attacker key");
            // Leave as plaintext JSON; the HTTP layer re-encodes to message=...
            edited = edited.withBody(root.toString()).withAddedHeader(Config.HDR_DECRYPTED, "1");
            return ProxyRequestReceivedAction.continueWith(edited);
        }

        // Normal encrypted request: AES-GCM decrypt for visibility.
        String session = HttpUtil.cookie(req, Config.SESSION_COOKIE);
        SessionStore.Entry entry = SessionStore.get(session);
        if (entry == null) {
            api.logging().logToOutput("[req] no session key yet for cookie=" + session);
            return ProxyRequestReceivedAction.continueWith(req);
        }
        String plaintext = CryptoUtil.aesGcmDecrypt(message, entry.symKey);
        api.logging().logToOutput("[req] decrypted body:\n" + plaintext);
        edited = edited.withBody(plaintext).withAddedHeader(Config.HDR_DECRYPTED, "1");
        return ProxyRequestReceivedAction.continueWith(edited);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
        // Proxy HTTP history is recorded from this stage; we leave the (now-plaintext) body as-is.
        return ProxyRequestToBeSentAction.continueWith(req);
    }
}
