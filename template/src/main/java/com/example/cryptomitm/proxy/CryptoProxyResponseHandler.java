package com.example.cryptomitm.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.example.cryptomitm.config.Config;
import com.example.cryptomitm.crypto.CryptoUtil;
import com.example.cryptomitm.store.SessionStore;
import com.example.cryptomitm.util.HttpUtil;

/**
 * PROXY RESPONSE layer — re-encrypts a response the HTTP layer decrypted, so the
 * browser (which holds the session key in transparent mode) can still read it.
 * The HTTP layer marks such responses with {@link Config#HDR_DECRYPTED}.
 */
public class CryptoProxyResponseHandler implements ProxyResponseHandler {
    private final MontoyaApi api;

    public CryptoProxyResponseHandler(MontoyaApi api) { this.api = api; }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {
        boolean decrypted = resp.hasHeader(Config.HDR_DECRYPTED);
        HttpResponse edited = resp.withRemovedHeader(Config.HDR_DECRYPTED);
        if (!decrypted) {
            return ProxyResponseReceivedAction.continueWith(edited);
        }

        try {
            HttpRequest req = resp.initiatingRequest();
            String session = HttpUtil.cookie(req, Config.SESSION_COOKIE);
            SessionStore.Entry entry = SessionStore.get(session);
            if (entry == null) {
                // Passive mode / unknown session: leave the plaintext for the operator.
                return ProxyResponseReceivedAction.continueWith(edited);
            }
            String sealed = CryptoUtil.aesGcmEncrypt(resp.bodyToString(), entry.symKey);
            edited = edited.withBody("{\"" + Config.RESP_MSG_FIELD + "\":\"" + sealed + "\"}");
        } catch (Exception e) {
            api.logging().logToError(e);
        }
        return ProxyResponseReceivedAction.continueWith(edited);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }
}
