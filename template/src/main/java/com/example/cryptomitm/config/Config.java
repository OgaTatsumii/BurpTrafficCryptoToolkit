package com.example.cryptomitm.config;

/**
 * Per-target configuration. Fill this from your "crypto profile"
 * (see docs/02-finding-the-crypto.md and docs/03-analyzing-keygen.md).
 *
 * Nothing here is target-specific in this template — every value is a placeholder.
 * Secrets (the attacker keypair) must NOT be committed; keep them in a local,
 * git-ignored copy of this file.
 */
public final class Config {
    private Config() {}

    public static final String EXT_NAME = "Crypto MITM Template";

    /** Only touch requests whose URL contains this. Combine with request.isInScope(). TODO */
    public static final String TARGET_URL_SUBSTR = "target.example.com/api";

    // --- cross-layer signalling headers (see docs/04) ---
    /** Proxy layer sets this after decrypting -> HTTP layer re-encrypts. Stripped before egress. */
    public static final String HDR_DECRYPTED = "X-TL-Crypto";
    /** You set this in Repeater to send PLAINTEXT and have the extension seal it. */
    public static final String HDR_TOOL = "X-TL-Tool";

    public enum Scheme { DIRECT_RSA, HYBRID_RSA_AES }
    /** TODO pick the scheme you identified. */
    public static final Scheme SCHEME = Scheme.HYBRID_RSA_AES;

    public enum RsaPadding { PKCS1, OAEP }
    /** RSA padding used by the app for the key step. TODO */
    public static final RsaPadding RSA_PADDING = RsaPadding.OAEP;
    /** OAEP hashes (JCA names). A common non-default combo is SHA-256 / SHA-1. TODO */
    public static final String OAEP_HASH = "SHA-256";
    public static final String OAEP_MGF1_HASH = "SHA-1";

    // ============================ DIRECT_RSA ============================
    /** Body field that carries the RSA ciphertext (e.g. the password field). TODO */
    public static final String RSA_FIELD = "password";
    /** The REAL server public key, to re-encrypt with before forwarding. SPKI base64. TODO */
    public static final String SERVER_PUBLIC_KEY = "";

    // ========================= HYBRID_RSA_AES =========================
    /** Request body field carrying the encrypted envelope. TODO */
    public static final String MSG_FIELD = "message";
    /** Response body field carrying the encrypted envelope. TODO */
    public static final String RESP_MSG_FIELD = "resMessage";
    /** URL marker that identifies the key-exchange transaction(s). TODO */
    public static final String KEX_URL_MARKER = "KEX";
    /** Field (inside the exchange request JSON "body") holding the client's public key. TODO */
    public static final String KEX_CLIENT_PUBKEY_FIELD = "clientPubKey";
    /** Field (inside the exchange response JSON "body") holding the wrapped symmetric key. TODO */
    public static final String KEX_WRAPPED_SYMKEY_FIELD = "wrappedSymKey";
    /** Optional field holding an auth token returned by the exchange; "" to ignore. */
    public static final String KEX_AUTH_TOKEN_FIELD = "authToken";
    /** Session cookie name used to key the recovered-session store. TODO */
    public static final String SESSION_COOKIE = "SESSION";

    /**
     * Transparent mode: re-wrap the recovered session key to the client's REAL
     * public key so the live browser keeps working (see docs/03).
     * When false, the tool is passive: great when YOU drive the session via
     * Burp/Repeater, but the live browser won't continue past the exchange.
     */
    public static final boolean TRANSPARENT_REWRAP = false;

    // ====================== attacker keypair (SECRET) ======================
    // DO NOT COMMIT. SPKI base64 (public) / PKCS#8 base64 (private).
    public static final String ATTACKER_PUBLIC_KEY  = "";   // TODO
    public static final String ATTACKER_PRIVATE_KEY = "";   // TODO
}
