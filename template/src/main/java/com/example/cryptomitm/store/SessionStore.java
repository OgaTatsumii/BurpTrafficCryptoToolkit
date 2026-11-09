package com.example.cryptomitm.store;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe store of recovered per-session material.
 * Burp invokes handlers on multiple threads, so this must be concurrent.
 */
public final class SessionStore {
    private SessionStore() {}

    public static final class Entry {
        public volatile String symKey;            // base64 AES session key
        public volatile String authToken;         // optional
        public volatile String clientRealPubKey;  // for transparent re-wrap (SPKI base64)

        public Entry(String symKey, String authToken) {
            this.symKey = symKey;
            this.authToken = authToken;
        }
    }

    private static final ConcurrentHashMap<String, Entry> SESSIONS = new ConcurrentHashMap<>();

    public static void put(String session, Entry e) { if (session != null) SESSIONS.put(session, e); }
    public static Entry get(String session)         { return session == null ? null : SESSIONS.get(session); }
    public static void remove(String session)       { if (session != null) SESSIONS.remove(session); }
    public static void clear()                      { SESSIONS.clear(); }

    /** Move an entry when the server rotates the session cookie. */
    public static void rekey(String oldCookie, String newCookie) {
        if (oldCookie == null || newCookie == null || oldCookie.equals(newCookie)) return;
        Entry e = SESSIONS.remove(oldCookie);
        if (e != null) SESSIONS.put(newCookie, e);
    }

    /**
     * Pending client public key captured during a key-exchange REQUEST, consumed in the
     * matching RESPONSE for transparent re-wrap.
     *
     * NOTE: the exchange request usually has no session cookie yet (the response sets it),
     * so robust request->response correlation is target-specific. This single-slot default
     * is adequate for ONE operator driving ONE session at a time. For concurrent sessions,
     * correlate on a stable value inside the message (e.g. a UUID) instead.
     */
    private static volatile String pendingClientPubKey;
    public static void setPendingClientPubKey(String pub) { pendingClientPubKey = pub; }
    public static String takePendingClientPubKey() {
        String v = pendingClientPubKey;
        pendingClientPubKey = null;
        return v;
    }
}
