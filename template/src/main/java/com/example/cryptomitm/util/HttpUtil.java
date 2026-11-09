package com.example.cryptomitm.util;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/** Small HTTP helpers that avoid the common double-URL-decode and cookie-split bugs. */
public final class HttpUtil {
    private HttpUtil() {}

    /**
     * Read a single x-www-form-urlencoded parameter from a raw body, URL-decoding
     * EXACTLY ONCE. (Do not combine with Montoya's parameterValue(), which may already
     * decode — decoding twice turns a base64 '+' into a space and corrupts ciphertext.)
     */
    public static String formParam(String body, String name) {
        if (body == null) return null;
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String k = (eq < 0) ? pair : pair.substring(0, eq);
            if (k.equals(name)) {
                String v = (eq < 0) ? "" : pair.substring(eq + 1);
                return URLDecoder.decode(v, StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /** Build a single-parameter form body: name=urlencoded(value). */
    public static String formBody(String name, String value) {
        return name + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Replace one param's value in a multi-param form body, URL-encoding the new value. */
    public static String replaceFormParam(String body, String name, String rawValue) {
        String[] pairs = body.split("&");
        boolean found = false;
        for (int i = 0; i < pairs.length; i++) {
            int eq = pairs[i].indexOf('=');
            String k = (eq < 0) ? pairs[i] : pairs[i].substring(0, eq);
            if (k.equals(name)) {
                pairs[i] = name + "=" + URLEncoder.encode(rawValue, StandardCharsets.UTF_8);
                found = true;
            }
        }
        return found ? String.join("&", pairs) : body + "&" + formBody(name, rawValue);
    }

    /** Cookie read that handles '=' inside the value and avoids prefix collisions. */
    public static String cookie(HttpRequest req, String name) {
        if (req == null || !req.hasHeader("Cookie")) return "";
        for (String c : req.headerValue("Cookie").split(";")) {
            c = c.trim();
            if (c.startsWith(name + "=")) {
                return c.substring(name.length() + 1);
            }
        }
        return "";
    }
}
