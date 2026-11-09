package com.example.cryptomitm;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.example.cryptomitm.config.Config;
import com.example.cryptomitm.http.CryptoHttpHandler;
import com.example.cryptomitm.proxy.CryptoProxyRequestHandler;
import com.example.cryptomitm.proxy.CryptoProxyResponseHandler;

import java.security.Security;

/**
 * Entry point. Registers the proxy + HTTP handlers that implement the
 * decrypt-at-proxy / re-encrypt-at-http pattern (see docs/04-burp-execution-flow.md).
 */
public class CryptoMitmExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        // Optional: a stronger provider. JDK SunJCE already covers OAEP(+MGF1) and AES-GCM,
        // so this is only needed for algorithms the JDK lacks. Safe to keep.
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Throwable ignored) {
            // Bouncy Castle not on the classpath -> fine, JDK providers are used.
        }

        api.extension().setName(Config.EXT_NAME);

        api.proxy().registerRequestHandler(new CryptoProxyRequestHandler(api));
        api.proxy().registerResponseHandler(new CryptoProxyResponseHandler(api));
        api.http().registerHttpHandler(new CryptoHttpHandler(api));

        api.logging().logToOutput(Config.EXT_NAME + " loaded. scheme=" + Config.SCHEME
                + " padding=" + Config.RSA_PADDING
                + " transparent=" + Config.TRANSPARENT_REWRAP);
        api.logging().logToOutput("Target filter: url contains '" + Config.TARGET_URL_SUBSTR + "' AND in scope.");
        if (Config.ATTACKER_PRIVATE_KEY.isEmpty()) {
            api.logging().logToError("ATTACKER_PRIVATE_KEY is empty — set your keypair in Config before use.");
        }
    }
}
